package authkit

import "context"

// contextKey is an unexported type for context keys in this package,
// preventing collisions with keys from other packages.
type contextKey string

const userContextKey contextKey = "authkit_user"

// UserFromCtx returns the authenticated User stored in ctx, or nil if the
// request has not passed through RequireAuth middleware.
func UserFromCtx(ctx context.Context) *User {
	u, _ := ctx.Value(userContextKey).(*User)
	return u
}

// withUser returns a new context carrying the given User.
func withUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}
