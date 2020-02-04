package schema

import (
	"context"
	"database/sql"
	"github.com/dhanarJkusuma/pager"
	"time"
)

// Permission Repository
type Permission struct {
	Entity

	ID          int64  `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	Method      string `db:"method" json:"method"`
	Route       string `db:"route" json:"route"`
	Description string `db:"description" json:"description"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

const insertPermissionQuery = `
	INSERT INTO rbac_permission (
		name, 
		method,
		route,
		description
	) VALUES (?,?,?,?)
`

func (p *Permission) CreatePermission() error {
	if p.DBContract == nil {
		return pager.ErrNoSchema
	}
	result, err := p.DBContract.Exec(
		insertPermissionQuery,
		p.Name,
		p.Method,
		p.Route,
		p.Description,
	)
	if err != nil {
		return err
	}
	p.ID, _ = result.LastInsertId()
	return nil
}

func (p *Permission) CreatePermissionContext(ctx context.Context) error {
	if p.DBContract == nil {
		return pager.ErrNoSchema
	}
	result, err := p.DBContract.ExecContext(
		ctx,
		insertPermissionQuery,
		p.Name,
		p.Method,
		p.Route,
		p.Description,
	)
	if err != nil {
		return err
	}

	p.ID, _ = result.LastInsertId()
	return nil
}

const deletePermissionQuery = `DELETE FROM rbac_permission WHERE id = ?`

func (p *Permission) DeletePermission() error {
	if p.DBContract == nil {
		return pager.ErrNoSchema
	}
	_, err := p.DBContract.Exec(
		deletePermissionQuery,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (p *Permission) DeletePermissionWithContext(ctx context.Context) error {
	if p.DBContract == nil {
		return pager.ErrNoSchema
	}
	_, err := p.DBContract.ExecContext(
		ctx,
		deletePermissionQuery,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const fetchPermissionQuery = `
	SELECT
		id,
		name,
		method,
		route,
		description
	FROM rbac_permission WHERE name = ?
`

func (p *Permission) GetPermission(name string) (*Permission, error) {
	if p.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	var permission = new(Permission)
	result := p.DBContract.QueryRow(fetchPermissionQuery, name)
	err := result.Scan(&permission.ID, &permission.Name, &permission.Method, &permission.Route, &permission.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	permission.DBContract = p.DBContract
	return permission, nil
}

func (p *Permission) GetPermissionContext(ctx context.Context, name string) (*Permission, error) {
	if p.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	var permission = new(Permission)
	result := p.DBContract.QueryRowContext(ctx, fetchPermissionQuery, name)
	err := result.Scan(&permission.ID, &permission.Name, &permission.Method, &permission.Route, &permission.Description)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	permission.DBContract = p.DBContract
	return permission, nil
}
