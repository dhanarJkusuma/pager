package schema

import (
	"database/sql"
	"errors"
	"github.com/dhanarJkusuma/pager/repository"
)

type Schema struct {
	DbConnection *sql.DB
}

type Entity struct {
	DBContract repository.DbContract
}

type existRecord struct {
	IsExist bool `db:"is_exist"`
}

var (
	ErrInvalidID = errors.New("invalid id")
)

// User function will inject schema in the userModel
// This function will inject the database connection to userModel
func (s *Schema) User(userModel *User) *User {
	if userModel == nil {
		return &User{
			Entity: Entity{DBContract: s.DbConnection},
		}
	}
	userModel.DBContract = s.DbConnection
	return userModel
}

// Permission function will inject schema in the permissionModel
// This function will inject the database connection to permissionModel
func (s *Schema) Permission(permissionModel *Permission) *Permission {
	if permissionModel == nil {
		return &Permission{
			Entity: Entity{DBContract: s.DbConnection},
		}
	}
	permissionModel.DBContract = s.DbConnection
	return permissionModel
}

// Role function will inject schema in the roleModel
// This function will inject the database connection to roleModel
func (s *Schema) Role(roleModel *Role) *Role {
	if roleModel == nil {
		return &Role{
			Entity: Entity{DBContract: s.DbConnection},
		}
	}
	roleModel.DBContract = s.DbConnection
	return roleModel
}

func (s *Schema) Rule(ruleModel *Rule) *Rule {
	if ruleModel == nil {
		return &Rule{
			Entity: Entity{DBContract: s.DbConnection},
		}
	}
	ruleModel.DBContract = s.DbConnection
	return ruleModel
}
