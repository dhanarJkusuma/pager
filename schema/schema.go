package schema

import (
	"context"
	"database/sql"
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

// Fetch represent how we get the user data from database
type Fetch interface {
	// user fetcher
	GetUser(email string) (*User, error)
	GetUserContext(ctx context.Context, email string) (*User, error)
	FindUserByUsernameOrEmail(params string) (*User, error)
	FindUserByUsernameOrEmailContext(ctx context.Context, params string) (*User, error)
	FindUser(params map[string]interface{}) (*User, error)
	FindUserContext(ctx context.Context, params map[string]interface{}) (*User, error)

	// permission fetcher
	GetPermission(name string) (*Permission, error)
	GetPermissionContext(ctx context.Context, name string) (*Permission, error)

	// role fetcher
	GetRole(name string) (*Role, error)
	GetRoleContext(ctx context.Context, name string) (*Role, error)
}

func (s *Schema) User(userModel *User) *User {
	if userModel == nil {
		return &User{
			Entity: Entity{DBContract: s.DbConnection},
		}
	}
	userModel.DBContract = s.DbConnection
	return userModel
}
func (s *Schema) Permission(permissionModel *Permission) *Permission {
	if permissionModel == nil {
		return &Permission{
			Entity: Entity{DBContract: s.DbConnection},
		}
	}
	permissionModel.DBContract = s.DbConnection
	return permissionModel
}

func (s *Schema) Role(roleModel *Role) *Role {
	if roleModel == nil {
		return &Role{
			Entity: Entity{DBContract: s.DbConnection},
		}
	}
	roleModel.DBContract = s.DbConnection
	return roleModel
}

func (s *Schema) Fetch() Fetch {
	f := &fetcher{DbContract: s.DbConnection}
	return f
}
