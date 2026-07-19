package authkit

import "maps"

// User represents an authenticated principal. It is injected into every
// request context after successful authentication, regardless of the
// credential used (OAuth session, password session, bearer JWT, or API key).
type User struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatarUrl"`
	Provider  string `json:"provider"`
	Role      string `json:"role"`

	// TenantID binds the principal to one tenant — the hard security boundary
	// in a multi-tenant deployment. Populated in every credential path:
	// UserStore (password), the OAuth callback mapping, and APIKeyValidator.
	// Single-tenant applications simply leave it empty.
	TenantID string `json:"tenantId,omitempty"`

	// Attrs carries host-defined principal attributes (for example an
	// organizational sub-scope, locale, or plan tier). authkit round-trips it
	// through sessions and access-token claims but never interprets it: keys
	// and meaning belong to the host application. Keep values small — they
	// travel in the session record and the JWT.
	Attrs map[string]string `json:"attrs,omitempty"`

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

// Permissions returns a copy of the user's resolved permission list. Hosts use
// it to enumerate capabilities (e.g. for a /me endpoint) instead of probing
// Can() against a parallel catalog.
func (u *User) Permissions() []string {
	if u == nil || len(u.permissions) == 0 {
		return nil
	}
	out := make([]string, len(u.permissions))
	copy(out, u.permissions)
	return out
}

// SetPermissions replaces the user's resolved permission list. It exists for
// host-driven login flows that mint sessions through EstablishSession with a
// permission set the host resolved itself (e.g. an ephemeral or synthetic
// principal outside the PolicyProvider). Normal logins never need it.
func (u *User) SetPermissions(perms []string) {
	cp := make([]string, len(perms))
	copy(cp, perms)
	u.permissions = cp
}

// Attr returns the named host-defined attribute, or "" when absent.
func (u *User) Attr(key string) string {
	if u == nil {
		return ""
	}
	return u.Attrs[key]
}

// cloneAttrs copies an attribute map so stored state can never be mutated
// through a shared reference.
func cloneAttrs(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return maps.Clone(m)
}
