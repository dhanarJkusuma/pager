package main

import (
	"database/sql"
	"fmt"
	"github.com/dhanarJkusuma/pager"
	"github.com/go-redis/redis"
	_ "github.com/go-sql-driver/mysql"
	"time"
)

func main() {
	dbConn := fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&multiStatements=true", "root", "", "127.0.0.1", "auth")
	db, err := sql.Open("mysql", dbConn)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	// init redis
	cacheClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
	})

	auth := generateAuth(&authOptions{
		db:          db,
		redisClient: cacheClient,
		schema:      "auth",
		origin:      "localhost",
	})
	err = auth.Migration.Initialize()
	if err != nil {
		panic(err.Error())
	}
}

type authOptions struct {
	redisClient *redis.Client
	db          *sql.DB
	schema      string
	origin      string
}

func generateAuth(options *authOptions) *pager.Pager {
	return pager.NewPager(&pager.Options{
		CacheClient:  options.redisClient,
		DbConnection: options.db,
		SchemaName:   options.schema,
		Session: pager.SessionOptions{
			Origin:           options.origin,
			LoginMethod:      pager.LoginEmail,
			ExpiredInSeconds: int64(24 * time.Hour),
			SessionName:      "_Quiz_App",
		},
	}).BuildPager()
}