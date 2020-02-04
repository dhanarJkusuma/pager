package auth

import (
	"context"
	"database/sql"
	"errors"
	"github.com/dhanarJkusuma/pager"
	"github.com/dhanarJkusuma/pager/schema"
	"github.com/go-redis/redis"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidPasswordLogin = errors.New("invalid password")
	ErrInvalidUserLogin     = errors.New("invalid user")
	ErrCreatingToken        = errors.New("error while create a new auth token")
	ErrCreatingCookie       = errors.New("error while set cookie")
	ErrInvalidCookie        = errors.New("invalid cookie")
	ErrInvalidAuthorization = errors.New("invalid authorization")
	ErrValidateCookie       = errors.New("error validate cookie")
	ErrUserNotFound         = errors.New("user not found")
	ErrUserNotActive        = errors.New("user is not active")
)

type LoginParams struct {
	Identifier string
	Password   string
}

type LoginMethod int

const (
	LoginEmail         LoginMethod = 0
	LoginUsername      LoginMethod = 1
	LoginEmailUsername LoginMethod = 2

	CookieBasedAuth int = 0
	TokenBasedAuth  int = 1

	authorization string = "Authorization"
	UserPrinciple string = "UserPrinciple"
)

type Auth struct {
	sessionName string

	cacheClient      *redis.Client
	loginMethod      LoginMethod
	expiredInSeconds int64

	tokenStrategy    pager.TokenGenerator
	passwordStrategy pager.PasswordGenerator

	dbSchema *schema.Schema
}

type Options struct {
	SessionName  string
	GuardSchema  *schema.Schema
	CacheClient  *redis.Client
	LoginMethod  LoginMethod
	ExpiredInSec int64

	TokenStrategy    pager.TokenGenerator
	PasswordStrategy pager.PasswordGenerator
}

func NewAuth(opts Options) *Auth {
	authModule := &Auth{
		sessionName:      opts.SessionName,
		dbSchema:         opts.GuardSchema,
		cacheClient:      opts.CacheClient,
		loginMethod:      opts.LoginMethod,
		expiredInSeconds: opts.ExpiredInSec,
		tokenStrategy:    opts.TokenStrategy,
		passwordStrategy: opts.PasswordStrategy,
	}

	return authModule
}

// Authenticate function will authenticate user by LoginParams and return user entity if user has successfully login
// Authenticate function will get the data from database
// if user exist, password request validated, and logged user has active status, then loggedUser entity will be returned, otherwise it'll return error
func (a *Auth) Authenticate(params LoginParams) (*schema.User, error) {
	var loggedUser *schema.User
	var err error

	switch a.loginMethod {
	case LoginEmail:
		loggedUser, err = a.dbSchema.User(nil).
			FindUser(map[string]interface{}{
				"email": params.Identifier,
			})
	case LoginUsername:
		loggedUser, err = a.dbSchema.User(nil).
			FindUser(map[string]interface{}{
				"username": params.Identifier,
			})
	case LoginEmailUsername:
		loggedUser, err = a.dbSchema.User(nil).
			FindUserByUsernameOrEmail(params.Identifier)
	}
	if loggedUser == nil {
		return nil, ErrInvalidUserLogin
	}
	if err != nil {
		return nil, err
	}

	if !a.passwordStrategy.ValidatePassword(loggedUser.Password, params.Password) {
		return nil, ErrInvalidPasswordLogin
	}

	if !loggedUser.Active {
		return nil, ErrUserNotActive
	}
	return loggedUser, nil
}

// SignInCookie will authenticate user login and set the cookie with validated user session
// It'll generate a cookie token with specific tokenStrategy and set the token in the redis with the specific key and expiredTime
func (a *Auth) SignInCookie(w http.ResponseWriter, params LoginParams) (*schema.User, error) {
	loggedUser, err := a.Authenticate(params)
	if err != nil {
		return nil, err
	}

	hashCookie := a.tokenStrategy.GenerateCookie()
	http.SetCookie(w, &http.Cookie{
		Name:    a.sessionName,
		Value:   hashCookie,
		Path:    "/",
		Expires: time.Now().Add(time.Duration(a.expiredInSeconds)),
	})

	err = a.cacheClient.Do(
		"SETEX",
		hashCookie,
		strconv.FormatInt(a.expiredInSeconds, 10),
		loggedUser.ID,
	).Err()
	if err != nil {
		return nil, ErrCreatingCookie
	}

	return loggedUser, nil
}

// ClearSession function will clear the login session with the provided cookie
// It'll delete cookie in the redis db and set the empty cookie as response to user
func (a *Auth) ClearSession(w http.ResponseWriter, r *http.Request) error {
	cookieData, err := r.Cookie(a.sessionName)
	if err != nil {
		return ErrInvalidCookie
	}
	cookie := cookieData.Value
	err = a.cacheClient.Do(
		"DEL",
		cookie,
	).Err()
	if err != nil {
		return err
	}

	// clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:   a.sessionName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	return nil
}

// SignInCookie will authenticate user login and return token string for authentication based token
// It'll generate a token with specific tokenStrategy and set the token in the redis with the specific key and expiredTime
func (a *Auth) SignIn(params LoginParams) (*schema.User, string, error) {
	loggedUser, err := a.Authenticate(params)
	if err != nil {
		return nil, "", err
	}

	token := a.tokenStrategy.GenerateToken()
	err = a.cacheClient.Do(
		"SETEX",
		token,
		strconv.FormatInt(a.expiredInSeconds, 10),
		loggedUser.ID,
	).Err()
	if err != nil {
		return nil, "", ErrCreatingToken
	}

	return loggedUser, token, nil
}

// Logout function will clear the login session with the provided header Authorization
// It'll delete token data in the redis db
func (a *Auth) Logout(request *http.Request) error {
	var err error
	var user *schema.User

	user = GetUserLogin(request)
	if user == nil {
		return ErrInvalidUserLogin
	}

	token := request.Header.Get(authorization)
	err = a.cacheClient.Do(
		"DEL",
		token,
	).Err()
	if err != nil {
		return err
	}
	return nil
}

// Register function will create a new user with hashed password that provided by auth module
// This function will return error that indicate user creation is success or not
func (a *Auth) Register(user *schema.User) error {
	userSchema := a.dbSchema.User(user)
	userSchema.Password = a.passwordStrategy.HashPassword(user.Password)
	return userSchema.CreateUser()
}

func (a *Auth) ProtectRoute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := a.getUserPrinciple(r, CookieBasedAuth)
		if err != nil {
			// clear session
			a.ClearSession(w, r)

			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), UserPrinciple, user)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (a *Auth) ProtectRouteUsingToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := a.getUserPrinciple(r, TokenBasedAuth)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), UserPrinciple, user)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (a *Auth) ProtectWithRBAC(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserLogin(r)
		if user == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !user.CanAccess(r.Method, r.URL.Path) {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *Auth) VerifyToken(token string) (int64, error) {
	result, err := a.cacheClient.Do(
		"GET",
		token,
	).Int64()
	if err != nil {
		return -1, err
	}
	return result, nil
}

func (a *Auth) GetUserByToken(token string) (*schema.User, error) {
	userId, err := a.VerifyToken(token)
	if err != nil {
		return nil, err
	}

	user, err := schema.FindUser(map[string]interface{}{
		"id": userId,
	}, nil)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (a *Auth) getUserPrinciple(r *http.Request, strategy int) (*schema.User, error) {
	var token string
	switch strategy {
	case CookieBasedAuth:
		cookieData, err := r.Cookie(a.SessionName)
		if err != nil {
			return nil, ErrInvalidCookie
		}
		token = cookieData.Value
	case TokenBasedAuth:
		rawToken := r.Header.Get(authorization)
		headers := strings.Split(rawToken, " ")
		if len(headers) != 2 {
			return nil, ErrInvalidAuthorization
		}
		token = headers[1]
	}

	userID, err := a.VerifyToken(token)
	if err != nil {
		return nil, ErrValidateCookie
	}

	user, err := schema.FindUser(map[string]interface{}{
		"id": userID,
	}, nil)
	if err != nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

func GetUserLogin(r *http.Request) *schema.User {
	ctx := r.Context()
	return ctx.Value(UserPrinciple).(*schema.User)
}
