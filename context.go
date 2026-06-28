package authkit

import "context"

// contextKey is an unexported type for context keys in this package,
// preventing collisions with keys from other packages.
type contextKey string

const (
	userContextKey   contextKey = "authkit_user"
	tenantContextKey contextKey = "authkit_tenant"
)

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

// WithTenant returns a copy of ctx carrying the given tenant ID. authkit sets
// this from the authenticated principal before resolving permissions, so a
// tenant-aware PolicyProvider (and the host's per-transaction RLS GUC) can
// scope to the right tenant. It is the single owner of the tenant context key
// shared across the auth library and the host application.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantContextKey, tenantID)
}

// TenantIDFromCtx returns the tenant ID stored in ctx. ok is false when no
// tenant has been set (or it is empty), which callers MUST treat as fail-closed.
func TenantIDFromCtx(ctx context.Context) (id string, ok bool) {
	id, _ = ctx.Value(tenantContextKey).(string)
	return id, id != ""
}
