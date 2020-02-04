package schema

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/dhanarJkusuma/pager"
)

// User represents `rbac_user` table in the database
type User struct {
	Entity

	ID       int64  `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
	Email    string `db:"email" json:"email"`
	Password string `db:"password" json:"-"`
	Active   bool   `db:"active" json:"active"`
}

const insertUserQuery = `
	INSERT INTO rbac_user (
		email,
		username,
		password
	) VALUES (?,?,?)
`

// CreateUser function will create a new record of user entity
func (u *User) CreateUser() error {
	if u.DBContract == nil {
		return pager.ErrNoSchema
	}
	result, err := u.DBContract.Exec(
		insertUserQuery,
		u.Email,
		u.Username,
		u.Password,
	)
	if err != nil {
		return err
	}

	u.ID, err = result.LastInsertId()
	u.Active = true
	return nil
}

// CreateUserWithContext function will create a new record of user entity with context
func (u *User) CreateUserWithContext(ctx context.Context) error {
	if u.DBContract == nil {
		return pager.ErrNoSchema
	}

	result, err := u.DBContract.ExecContext(
		ctx,
		insertUserQuery,
		u.Email,
		u.Username,
		u.Password,
	)
	if err != nil {
		return err
	}

	u.ID, err = result.LastInsertId()
	u.Active = true
	return nil
}

const saveUserQuery = `
	INSERT INTO rbac_user (
		email,
		username,
		password,
		active
	) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE email = ?, username = ?, password = ?, active = ?
`

// Save function will save updated user entity
// if user record already exist in the database, it will be updated
// otherwise it will create a new one
func (u *User) Save() error {
	if u.DBContract == nil {
		return pager.ErrNoSchema
	}

	result, err := u.DBContract.Exec(
		saveUserQuery,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
	)
	if err != nil {
		return err
	}

	u.ID, _ = result.LastInsertId()
	return nil
}

// Save function will save updated user entity with context
// if user record already exist in the database, it will be updated
// otherwise it will create a new one
func (u *User) SaveWithContext(ctx context.Context) error {
	if u.DBContract == nil {
		return pager.ErrNoSchema
	}
	result, err := u.DBContract.ExecContext(
		ctx,
		saveUserQuery,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
	)
	if err != nil {
		return err
	}

	u.ID, _ = result.LastInsertId()
	return nil
}

const deleteUserQuery = `DELETE FROM rbac_user WHERE id = ?`

// Delete function will save delete user entity with specific ID
// if user has no ID, than error will be returned
func (u *User) Delete() error {
	if u.DBContract == nil {
		return pager.ErrNoSchema
	}

	_, err := u.DBContract.Exec(
		deleteUserQuery,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

// Delete function will save delete user entity with specific ID and context
// if user has no ID, than error will be returned
func (u *User) DeleteWithContext(ctx context.Context) error {
	if u.DBContract == nil {
		return pager.ErrNoSchema
	}
	_, err := u.DBContract.ExecContext(
		ctx,
		deleteUserQuery,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const getAccessQuery = `
 	SELECT EXISTS(
		SELECT 
			*
		FROM rbac_user_role ur 
		JOIN rbac_role_permission rp ON ur.role_id = rp.role_id
		JOIN rbac_permission p ON p.id = rp. permission_id 
		WHERE ur.user_id = ? AND p.method = ? AND p.route = ?
	) AS is_exist
`

// CanAccess function will return bool that represent this user is eligible to access the resource path or not
// This function will check the user permission database
func (u *User) CanAccess(method, path string) (bool, error) {
	if u.DBContract == nil {
		return false, pager.ErrNoSchema
	}

	var accessRecord existRecord
	result := u.DBContract.QueryRow(getAccessQuery, u.ID, method, path)
	err := result.Scan(&accessRecord.IsExist)
	if err != nil {
		return false, err
	}
	return accessRecord.IsExist, nil
}

// CanAccessContext function will return bool that represent this user is eligible to access the resource path or not
// This function will check the user permission database with specific context
func (u *User) CanAccessContext(ctx context.Context, method, path string) (bool, error) {
	if u.DBContract == nil {
		return false, pager.ErrNoSchema
	}

	var accessRecord existRecord
	result := u.DBContract.QueryRowContext(ctx, getAccessQuery, u.ID, method, path)
	err := result.Scan(&accessRecord.IsExist)
	if err != nil {
		return false, err
	}

	return accessRecord.IsExist, nil
}

const getUserPermissionQuery = `
	SELECT EXISTS(
		SELECT 
			COUNT(1) as count
		FROM rbac_user_role ur 
		JOIN rbac_role_permission rp ON ur.role_id = rp.role_id
		JOIN rbac_permission p ON p.id = rp. permission_id 
		WHERE ur.user_id = ? AND p.name = ?
	) AS is_exist
`

// CanAccess function will return bool that represent this user is eligible to access the resource path or not
// This function will check the user permission database
func (u *User) HasPermission(permissionName string) (bool, error) {
	if u.DBContract == nil {
		return false, pager.ErrNoSchema
	}

	var permissionRecord existRecord
	result := u.DBContract.QueryRow(getUserPermissionQuery, u.ID, permissionName)
	err := result.Scan(&permissionRecord.IsExist)
	if err != nil {
		return false, err
	}
	return permissionRecord.IsExist, nil
}

func (u *User) HasPermissionContext(ctx context.Context, permissionName string) (bool, error) {
	if u.DBContract == nil {
		return false, pager.ErrNoSchema
	}

	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := u.DBContract.QueryRowContext(ctx, getUserPermissionQuery, u.ID, permissionName)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false, err
	}
	return rowData.count > 0, nil
}

const getUserRoleQuery = `
	SELECT 
		COUNT(1) as count
	FROM rbac_user_role ur 
	JOIN rbac_role r ON ur.role_id = r.id 
	WHERE ur.user_id = ? AND r.name = ?
`

func (u *User) HasRole(roleName string) (bool, error) {
	if u.DBContract == nil {
		return false, pager.ErrNoSchema
	}

	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := u.DBContract.QueryRow(getUserRoleQuery, u.ID, roleName)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false, err
	}
	return rowData.count > 0, nil
}

func (u *User) HasRoleContext(ctx context.Context, roleName string) (bool, error) {
	if u.DBContract == nil {
		return false, pager.ErrNoSchema
	}
	rowData := struct {
		count int64 `db:"count"`
	}{}

	result := u.DBContract.QueryRowContext(ctx, getUserRoleQuery, u.ID, roleName)
	err := result.Scan(&rowData.count)
	if err != nil {
		return false, err
	}
	return rowData.count > 0, nil
}

const getUserRolesQuery = `
	SELECT
		r.id,
		r.name,
		r.description,
		r.created_at,
		r.updated_at
	FROM rbac_user_role ur
	JOIN rbac_role r WHERE ur.user_id = ?
`

func (u *User) GetRoles() ([]Role, error) {
	if u.DBContract == nil {
		return nil, pager.ErrNoSchema
	}
	var roles []Role

	roles = make([]Role, 0)
	result, err := u.DBContract.Query(getUserRolesQuery, u.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return roles, nil
		}
		return nil, err
	}

	var role Role
	role.DBContract = u.DBContract
	for result.Next() {
		err = result.Scan(&role.ID, &role.Name, &role.Description, &role.Description, &role.CreatedAt, &role.UpdatedAt)
		if err == nil {
			roles = append(roles, role)
		}
		return nil, err
	}
	return roles, nil
}

func (u *User) GetRolesContext(ctx context.Context) ([]Role, error) {
	if u.DBContract == nil {
		return nil, pager.ErrNoSchema
	}
	var roles []Role

	roles = make([]Role, 0)
	result, err := u.DBContract.QueryContext(ctx, getUserRolesQuery, u.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return roles, nil
		}
		return nil, err
	}

	var role Role
	for result.Next() {
		err = result.Scan(&role)
		if err == nil {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

const fetchUserByEmail = `
	SELECT 
		id, 
		email, 
		username, 
		password, 
		active 
	FROM rbac_user WHERE email = ?
`

func (u *User) GetUser(email string) (*User, error) {
	if u.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	var user = new(User)
	result := u.DBContract.QueryRow(fetchUserByEmail, email)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	user.DBContract = u.DBContract
	return user, nil
}

func (u *User) GetUserContext(ctx context.Context, email string) (*User, error) {
	if u.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	var user = new(User)
	result := u.DBContract.QueryRowContext(ctx, fetchUserByEmail, email)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	user.DBContract = u.DBContract
	return user, nil
}

const fetchUserByUsernameOrEmail = `
	SELECT 
		id, 
		email, 
		username, 
		password, 
		active 
	FROM rbac_user WHERE email = ? OR username = ?
`

func (u *User) FindUserByUsernameOrEmail(params string) (*User, error) {
	if u.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	var user = new(User)
	result := u.DBContract.QueryRow(fetchUserByUsernameOrEmail, params, params)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	user.DBContract = u.DBContract
	return user, nil
}

func (u *User) FindUserByUsernameOrEmailContext(ctx context.Context, params string) (*User, error) {
	if u.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	var user = new(User)
	result := u.DBContract.QueryRowContext(ctx, fetchUserByUsernameOrEmail, params, params)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	user.DBContract = u.DBContract
	return user, nil
}

const fetchDynamicUserParams = `
		SELECT 
			id, 
			email, 
			username, 
			password, 
			active FROM rbac_user WHERE 
`

func (u *User) FindUser(params map[string]interface{}) (*User, error) {
	if u.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	var user = new(User)
	var result *sql.Row
	paramsLength := len(params)
	if paramsLength == 0 {
		return nil, pager.ErrInvalidParams
	}

	query := fetchDynamicUserParams
	values := make([]interface{}, 0)
	index := 0
	for k := range params {
		query += fmt.Sprintf("%s = ?", k)
		if index < paramsLength-1 {
			query += ` AND `
		}
		values = append(values, params[k])
	}

	query += " LIMIT 1"
	result = u.DBContract.QueryRow(query, values...)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	user.DBContract = u.DBContract
	return user, nil

}

func (u *User) FindUserContext(ctx context.Context, params map[string]interface{}) (*User, error) {
	if u.DBContract == nil {
		return nil, pager.ErrNoSchema
	}

	var user = new(User)
	var result *sql.Row
	paramsLength := len(params)
	if paramsLength == 0 {
		return nil, pager.ErrInvalidParams
	}

	query := fetchDynamicUserParams
	values := make([]interface{}, 0)
	index := 0
	for k := range params {
		query += fmt.Sprintf("%s = ?", k)
		if index < paramsLength-1 {
			query += ` AND `
		}
		values = append(values, params[k])
	}

	query += " LIMIT 1"
	result = u.DBContract.QueryRowContext(ctx, query, values...)
	err := result.Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Active)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	user.DBContract = u.DBContract
	return user, nil

}
