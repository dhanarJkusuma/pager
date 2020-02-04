package pager

import (
	"database/sql"
	"github.com/dhanarJkusuma/pager/migration"
	"github.com/dhanarJkusuma/pager/repository"
	schema2 "github.com/dhanarJkusuma/pager/schema"
	"log"
)

type PagerTx struct {
	dbTx *sql.Tx
}

func (ptx *PagerTx) BeginTx() error {
	tx, err := dbConnection.Begin()
	ptx.dbTx = tx
	return err
}

func (ptx *PagerTx) User(user *schema2.User) *schema2.User {
	user.db = ptx.dbTx
	return user
}

func (ptx *PagerTx) Role(role *schema2.Role) *schema2.Role {
	role.db = ptx.dbTx
	return role
}

func (ptx *PagerTx) Group(group *repository.Group) *repository.Group {
	group.db = ptx.dbTx
	return group
}

func (ptx *PagerTx) Permission(permission *schema2.Permission) *schema2.Permission {
	permission.db = ptx.dbTx
	return permission
}

func (ptx *PagerTx) FinishTx(err error) error {
	if err == nil {
		return ptx.dbTx.Commit()
	}
	if err == migration.ErrMigrationAlreadyExist {
		log.Println("migration already exist")
	} else {
		log.Fatal("failed to run migration, err = ", err)
	}

	return ptx.dbTx.Rollback()
}
