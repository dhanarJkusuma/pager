package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/dhanarJkusuma/pager"
)

var (
	ErrInvalidUserID       = errors.New("invalid user id")
	ErrInvalidPermissionID = errors.New("invalid permission id")
	ErrInvalidRoleID       = errors.New("invalid role id")
	ErrTxWithNoBegin       = errors.New("error dbTx without begin()")
)

type DbContract interface {
	Prepare(query string) (*sql.Stmt, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	Exec(query string, args ...interface{}) (sql.Result, error)
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

type RBACSchema struct {
	dbConnection *sql.DB
}

// Migration Repository
func CheckMigration(ptx *pager.PagerTx, migrationType string) (bool, error) {
	var db DbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return false, ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}
	rawResult := struct {
		MigrationKey string `db:"migration_key"`
	}{}
	selectQuery := `SELECT migration_key FROM rbac_migration WHERE migration_key = ? LIMIT 1`
	result := db.QueryRow(selectQuery, migrationType)
	err := result.Scan(&rawResult.MigrationKey)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func InsertMigration(ptx *pager.PagerTx, migrationType string) error {
	var db DbContract
	if ptx == nil {
		db = dbConnection
	} else {
		if ptx.dbTx == nil {
			return ErrTxWithNoBegin
		}
		db = ptx.dbTx
	}
	insertQuery := `INSERT INTO rbac_migration(migration_key) VALUES (?)`
	_, err := db.Exec(
		insertQuery,
		migrationType,
	)
	return err
}
