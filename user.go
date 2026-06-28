package authkit

// User represents an authenticated user resolved from an OAuth session.
// It is injected into every request context after successful authentication.
type User struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatarUrl"`
	Provider  string `json:"provider"`
	Role      string `json:"role"`

	// TenantID binds the principal to one tenant (the hard security boundary).
	// Populated in every credential path: UserStore (password), the OAuth
	// callback mapping, and APIKeyValidator. Used to set the per-transaction
	// RLS GUC and to key tenant-scoped permission resolution.
	TenantID string `json:"tenantId"`

	// BranchID is an optional authorization scope within a tenant (not an RLS
	// boundary). Carried into queries as a row filter, never as a permission.
	BranchID string `json:"branchId,omitempty"`

	// permissions is resolved from the RBAC policy — at login time (cached in
	// the session) or per request when LivePermissionResolution is enabled.
	permissions []string
}

// Can reports whether the user holds the given permission.
// A user with the "*" (PermAll) permission passes every check.
func (u *User) Can(permission string) bool {
	if u == nil {
		return false
	}
	for _, p := range u.permissions {
		if p == PermAll || p == permission {
			return true
		}
	}
	return false
}
