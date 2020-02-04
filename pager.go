package pager

import (
	"database/sql"
	"errors"
	"github.com/dhanarJkusuma/pager/migration"
	"github.com/dhanarJkusuma/pager/schema"
	"github.com/go-redis/redis"
	"log"
	"sync"
)

type AuthManager interface {
	GenerateToken()
}

// Constants for Error Messaging
const (
	ErrMigration = "error while migrating rbac-database, reason = %s"
)

var (
	ErrNoSchema      = errors.New("no schema provided")
	ErrInvalidParams = errors.New("invalid params")
)

type Pager struct {
	Dialect   string
	Migration *migration.Migration
	Auth      *Auth

	dbConnection *sql.DB
}

type SessionOptions struct {
	LoginMethod      LoginMethod
	SessionName      string
	Origin           string
	ExpiredInSeconds int64
}

type Options struct {
	DbConnection *sql.DB
	CacheClient  *redis.Client
	SchemaName   string
	Session      SessionOptions
}

type pagerBuilder struct {
	pagerOptions     *Options
	tokenStrategy    TokenGenerator
	passwordStrategy PasswordGenerator
}

func NewPager(opts *Options) *pagerBuilder {
	rbacBuilder := &pagerBuilder{
		pagerOptions: opts,
	}
	defaultTokenGen := &DefaultTokenGenerator{}
	defaultPasswordStrategy := &DefaultBcryptPassword{}
	rbacBuilder.tokenStrategy = defaultTokenGen
	rbacBuilder.passwordStrategy = defaultPasswordStrategy
	return rbacBuilder
}

func (p *pagerBuilder) SetTokenGenerator(generator TokenGenerator) *pagerBuilder {
	p.tokenStrategy = generator
	return p
}

func (p *pagerBuilder) SetPasswordGenerator(generator PasswordGenerator) *pagerBuilder {
	p.passwordStrategy = generator
	return p
}

func (p *pagerBuilder) BuildPager() *Pager {
	rbac := &Pager{}
	authModule := &Auth{
		SessionName:      p.pagerOptions.Session.SessionName,
		origin:           p.pagerOptions.Session.Origin,
		expiredInSeconds: p.pagerOptions.Session.ExpiredInSeconds,
		loginMethod:      p.pagerOptions.Session.LoginMethod,
		cacheClient:      p.pagerOptions.CacheClient,
		tokenStrategy:    p.tokenStrategy,
		passwordStrategy: p.passwordStrategy,
	}
	migrator, err := migration.NewMigration(migration.MigrationOptions{
		Schema:       p.pagerOptions.SchemaName,
		DBConnection: p.pagerOptions.DbConnection,
	})
	if err != nil {
		log.Fatal(err)
	}
	rbac.dbConnection = p.pagerOptions.DbConnection
	rbac.Migration = migrator
	rbac.Auth = authModule
	return rbac
}

var (
	once            sync.Once
	bluePrintSchema *schema.Schema
)

func (p *Pager) GetBluePrint() *schema.Schema {
	if p == nil || p.dbConnection == nil {
		return nil
	}
	once.Do(func() {
		bluePrintSchema = &schema.Schema{
			DbConnection: p.dbConnection,
		}
	})
	return bluePrintSchema
}
