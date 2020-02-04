package pager

import (
	"context"
	"errors"
	schema2 "github.com/dhanarJkusuma/pager/schema"
	"github.com/go-redis/redis"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidPasswordLogin = errors.New("invalid password")
	ErrInvalidUserLogin     = errors.New("invalid user")
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
	SessionName string

	cacheClient      *redis.Client
	loginMethod      LoginMethod
	origin           string
	expiredInSeconds int64

	tokenStrategy    TokenGenerator
	passwordStrategy PasswordGenerator
}

func (a *Auth) Authenticate(params LoginParams) (*schema2.User, error) {
	var loggedUser *schema2.User
	var err error

	switch a.loginMethod {
	case LoginEmail:
		loggedUser, err = schema2.FindUser(map[string]interface{}{
			"email": params.Identifier,
		}, nil)
	case LoginUsername:
		loggedUser, err = schema2.FindUser(map[string]interface{}{
			"username": params.Identifier,
		}, nil)
	case LoginEmailUsername:
		loggedUser, err = schema2.FindUserByUsernameOrEmail(params.Identifier, nil)
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

func (a *Auth) SignInWithCookie(w http.ResponseWriter, params LoginParams) (*schema2.User, error) {
	loggedUser, err := a.Authenticate(params)
	if err != nil {
		return nil, err
	}

	hashCookie := a.tokenStrategy.GenerateToken()
	http.SetCookie(w, &http.Cookie{
		Name:    a.SessionName,
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

func (a *Auth) ClearSession(w http.ResponseWriter, r *http.Request) error {
	cookieData, err := r.Cookie(a.SessionName)
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
		Name:   a.SessionName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	return nil
}

func (a *Auth) SignIn(params LoginParams) (*schema2.User, string, error) {
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
		return nil, "", ErrCreatingCookie
	}

	return loggedUser, token, nil
}

func (a *Auth) Logout(request *http.Request) error {
	var err error
	var user *schema2.User
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

func (a *Auth) Register(user *schema2.User) error {
	user.Password = a.passwordStrategy.HashPassword(user.Password)
	return user.CreateUser()
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

func (a *Auth) GetUserByToken(token string) (*schema2.User, error) {
	userId, err := a.VerifyToken(token)
	if err != nil {
		return nil, err
	}

	user, err := schema2.FindUser(map[string]interface{}{
		"id": userId,
	}, nil)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (a *Auth) getUserPrinciple(r *http.Request, strategy int) (*schema2.User, error) {
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

	user, err := schema2.FindUser(map[string]interface{}{
		"id": userID,
	}, nil)
	if err != nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

func GetUserLogin(r *http.Request) *schema2.User {
	ctx := r.Context()
	return ctx.Value(UserPrinciple).(*schema2.User)
}
