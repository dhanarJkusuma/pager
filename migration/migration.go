package migration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/dhanarJkusuma/pager"
	"github.com/dhanarJkusuma/pager/repository"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
)

const (
	MYSQLDialect = "mysql"
)

var (
	ErrMigrationAlreadyExist = errors.New("error while running migration, migration already exist")
	ErrMigrationHistory      = errors.New("error while record migration history")
)

type RunMigration interface {
	Run(ptx *pager.PagerTx) error
}

const migrationUp = "mysql_migration.up.sql"
const migrationIndexUp = "mysql_migration_index.up.sql"
const migrationDown = "mysql_migration.down.sql"

type indexSchema struct {
	IndexName string `db:"index_name"`
}

var requiredIndexes = map[string]bool{
	"rbac_user_email_idx":                      false,
	"rbac_user_username_idx":                   false,
	"rbac_permission_route_method_idx":         false,
	"rbac_permission_name_idx":                 false,
	"rbac_role_name_idx":                       false,
	"rbac_user_role_role_user_idx":             false,
	"rbac_role_permission_role_permission_idx": false,
	"rbac_role_rbac_rule_idx":                  false,
}

type Migration struct {
	dbConnection *sql.DB
	schemaName   string
}

type MigrationOptions struct {
	DBConnection *sql.DB
	Schema       string
}

func NewMigration(opts MigrationOptions) (*Migration, error) {
	m := &Migration{
		schemaName:   opts.Schema,
		dbConnection: opts.DBConnection,
	}
	return m, nil
}

// Initialize function will create migration for RBAC auth
func (m *Migration) Initialize() error {
	var err error
	fmt.Println("Migration :: Migrating Schema")
	err = m.migrate(migrationUp)
	if err != nil {
		m.Down()
		return err
	}

	err = m.validateIndexes()
	if err != nil {
		fmt.Println("Migration :: Migrating indexes")
		err = m.migrate(migrationIndexUp)
		if err != nil {
			m.Down()
			return err
		}
		return nil
	}

	return err
}

func (m *Migration) migrate(filename string) error {
	migrationPath := fmt.Sprintf("%s/migration/sql/%s", getCurrentPath(), filename)
	query, err := openSource(migrationPath)
	if err != nil {
		return err
	}
	// run migration version
	ctx := context.Background()
	_, err = m.dbConnection.ExecContext(ctx, query)
	return err
}

func (m *Migration) Down() {
	fmt.Println("Migration :: Down")
	err := m.migrate(migrationDown)
	if err != nil {
		fmt.Println("Err occur while clean up the migration")
	}
}

const validateMigrationQuery = `
		SELECT 
			COUNT(1) AS count_table 
		FROM INFORMATION_SCHEMA.TABLES 
		WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?`

func (m *Migration) isMigrationTableExist() (bool, error) {
	ctx := context.Background()
	result := struct {
		dataCount int64 `db:"count_table"`
	}{}
	dbResult := m.dbConnection.QueryRowContext(ctx, validateMigrationQuery, m.schemaName, "rbac_migration")
	err := dbResult.Scan(&result)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	return result.dataCount > 0, nil
}

func (m *Migration) Run(migration RunMigration) error {
	var err error
	ptx := &pager.PagerTx{}

	err = ptx.BeginTx()
	if err != nil {
		return err
	}
	defer ptx.FinishTx(err)

	migrationType := reflect.TypeOf(migration)
	alreadyRun, err := repository.CheckMigration(ptx, migrationType.Elem().Name())
	if err != nil {
		return err
	}
	if alreadyRun {
		err = ErrMigrationAlreadyExist
		return ErrMigrationAlreadyExist
	}
	err = migration.Run(ptx)
	if err == nil {
		errRecordMigration := repository.InsertMigration(ptx, migrationType.Elem().Name())
		if errRecordMigration != nil {
			log.Printf("%s : %s", ErrMigrationHistory.Error(), errRecordMigration)
			return ErrMigrationHistory
		}
	}
	return err
}

// validateIndexes will check all required indexes in the database
// It will select all indexes from the database and compare it with requiredIndexes variable.
// If the value of requiredIndexes with index_name is false, then it'll return error invalid index Schema.
func (m *Migration) validateIndexes() error {
	querySchema := `SELECT DISTINCT 
		INDEX_NAME AS index_name 
	FROM INFORMATION_SCHEMA.STATISTICS 
	WHERE TABLE_SCHEMA = ? 
	AND INDEX_NAME <> ?`

	rows, err := m.dbConnection.Query(querySchema, m.schemaName, "PRIMARY")
	if err != nil {
		log.Println(err)
		return errors.New(fmt.Sprintf(pager.ErrMigration, "error while checking the tables"))
	}

	var index indexSchema
	for rows.Next() {
		err = rows.Scan(&index.IndexName)
		if err != nil {
			log.Println(err)
			return errors.New(fmt.Sprintf(pager.ErrMigration, "error while checking the indexes"))
		}

		if _, ok := requiredIndexes[index.IndexName]; ok {
			requiredIndexes[index.IndexName] = true
		}
	}

	for _, v := range requiredIndexes {
		if !v {
			return errors.New("invalid RBAC index Schema")
		}
	}
	return nil
}

func getCurrentPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}

	return path.Dir(filename)
}

func openSource(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	b, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (m *Migration) scanSource(rootPath string, callback func(currentPath string)) error {
	return filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		ext := filepath.Ext(path)
		if info.IsDir() || ext != ".sql" {
			return nil
		}
		callback(path)
		return nil
	})
}
