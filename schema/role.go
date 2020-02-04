package schema

import (
	"context"
	"database/sql"
	"github.com/dhanarJkusuma/pager"
	"time"
)

// Role Repository
type Role struct {
	Entity
	ID          int64  `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	Description string `db:"description" json:"description"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

const insertRoleQuery = `
	INSERT INTO rbac_role (
		name, 
		description
	) VALUES (?,?)
`

func (r *Role) CreateRole() error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}
	result, err := r.DBContract.Exec(
		insertRoleQuery,
		r.Name,
		r.Description,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

func (r *Role) CreateRoleContext(ctx context.Context) error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}
	result, err := r.DBContract.ExecContext(
		ctx,
		insertRoleQuery,
		r.Name,
		r.Description,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

const deleteRoleQuery = `DELETE FROM rbac_role WHERE id = ?`

func (r *Role) DeleteRole() error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}
	_, err := r.DBContract.Exec(
		deleteRoleQuery,
		r.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) DeleteRoleContext(ctx context.Context) error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}
	_, err := r.DBContract.ExecContext(
		ctx,
		deleteRoleQuery,
		r.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const assignRoleQuery = `
	INSERT INTO rbac_user_role (
		role_id, 
		user_id
	) VALUES (?,?)
`

func (r *Role) Assign(u *User) error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}

	_, err := r.DBContract.Exec(
		assignRoleQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) AssignContext(ctx context.Context, u *User) error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}

	_, err := r.DBContract.ExecContext(
		ctx,
		assignRoleQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const revokeRoleQuery = `DELETE FROM rbac_user_role WHERE role_id = ? AND user_id = ?`

func (r *Role) Revoke(u *User) error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}

	_, err := r.DBContract.Exec(
		revokeRoleQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}

	return nil
}

func (r *Role) RevokeContext(ctx context.Context, u *User) error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}
	_, err := r.DBContract.ExecContext(
		ctx,
		revokeRoleQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}

	return nil
}

const addPermissionQuery = `
	INSERT INTO rbac_role_permission (
		role_id, 
		permission_id
	) VALUES (?,?)
`

func (r *Role) AddPermission(p *Permission) error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}

	_, err := r.DBContract.Exec(
		addPermissionQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) AddPermissionContext(ctx context.Context, p *Permission) error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}
	_, err := r.DBContract.ExecContext(
		ctx,
		addPermissionQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const removePermissionQuery = `DELETE FROM rbac_role_permission WHERE role_id = ? AND permission_id = ?`

func (r *Role) RemovePermission(p *Permission) error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}

	_, err := r.DBContract.Exec(
		removePermissionQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *Role) RemovePermissionContext(ctx context.Context, p *Permission) error {
	if r.DBContract == nil {
		return pager.ErrNoSchema
	}
	_, err := r.DBContract.ExecContext(
		ctx,
		removePermissionQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const getPermissionQuery = `
	SELECT
		p.id,
		p.name,
		p.method,
		p.route,
		p.description
	FROM rbac_role_permission rp
	JOIN rbac_permission p WHERE rp.role_id = ?
`

func (r *Role) GetPermission() ([]Permission, error) {
	if r.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	permissions := make([]Permission, 0)
	result, err := r.DBContract.Query(getPermissionQuery, r.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return permissions, nil
		}
		return nil, err
	}

	var permission Permission
	permission.DBContract = r.DBContract

	for result.Next() {
		err = result.Scan(&permission.ID, &permission.Name, &permission.Method, &permission.Route, &permission.Description)
		if err == nil {
			permissions = append(permissions, permission)
		}
	}
	return permissions, nil
}

func (r *Role) GetPermissionContext(ctx context.Context) ([]Permission, error) {
	if r.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	permissions := make([]Permission, 0)
	result, err := r.DBContract.QueryContext(ctx, getPermissionQuery, r.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return permissions, nil
		}
		return nil, err
	}

	var permission Permission
	for result.Next() {
		err = result.Scan(&permission.ID, &permission.Name, &permission.Method, &permission.Route, &permission.Description)
		if err == nil {
			permissions = append(permissions, permission)
		}
	}
	return permissions, nil
}

const fetchRoleQuery = `
	SELECT
		id,
		name,
		description 
	FROM rbac_role WHERE name = ?
`

func (r *Role) GetRole(name string) (*Role, error) {
	if r.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	var role = new(Role)
	result := r.DBContract.QueryRow(fetchRoleQuery, name)
	err := result.Scan(&role.ID, &role.Name, &role.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return role, nil
}

func (r *Role) GetRoleContext(ctx context.Context, name string) (*Role, error) {
	if r.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	var role = new(Role)
	result := r.DBContract.QueryRowContext(ctx, fetchRoleQuery, name)
	err := result.Scan(&role.ID, &role.Name, &role.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return role, nil
}
