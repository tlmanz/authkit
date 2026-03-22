package authkit

// User represents an authenticated user resolved from an OAuth session.
// It is injected into every request context after successful authentication.
type User struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatarUrl"`
	Provider  string `json:"provider"`
	Role      string `json:"role"`

	// permissions is resolved from the RBAC policy at login time and cached
	// in the session so every subsequent request avoids a policy lookup.
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
