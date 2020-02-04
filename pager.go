package pager

import (
	"database/sql"
	"errors"
	"github.com/dhanarJkusuma/pager/auth"
	"github.com/dhanarJkusuma/pager/migration"
	"github.com/dhanarJkusuma/pager/schema"
	"github.com/go-redis/redis"
	"log"
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
	Migration *migration.Migration
	Auth      *auth.Auth

	pagerSchema *schema.Schema
}

type SessionOptions struct {
	LoginMethod      auth.LoginMethod
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
	rbac := &Pager{
		pagerSchema: &schema.Schema{DbConnection: p.pagerOptions.DbConnection},
	}

	// initialize auth module
	authModule := auth.NewAuth(auth.Options{
		SessionName:  p.pagerOptions.Session.SessionName,
		GuardSchema:  rbac.pagerSchema,
		CacheClient:  p.pagerOptions.CacheClient,
		LoginMethod:  p.pagerOptions.Session.LoginMethod,
		ExpiredInSec: p.pagerOptions.Session.ExpiredInSeconds,

		TokenStrategy:    p.tokenStrategy,
		PasswordStrategy: p.passwordStrategy,
	})

	// initialize migration module
	migrator, err := migration.NewMigration(migration.MigrationOptions{
		Schema:       p.pagerOptions.SchemaName,
		DBConnection: p.pagerOptions.DbConnection,
	})
	if err != nil {
		log.Fatal(err)
	}

	// set migration and auth module
	rbac.Migration = migrator
	rbac.Auth = authModule
	return rbac
}

func (p *Pager) GetSchema() *schema.Schema {
	return p.pagerSchema
}
