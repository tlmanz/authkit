package authkit

import (
	"context"
	"net/http"
	"strings"
)

// extractBearerToken reads an API key from the request.
// Checks Authorization: Bearer <token> first, then X-API-Key as a fallback.
func extractBearerToken(r *http.Request) string {
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		return strings.TrimPrefix(v, "Bearer ")
	}
	if k := r.Header.Get("X-API-Key"); k != "" {
		return k
	}
	return ""
}

// tryAPIKeyAuth checks the request for a bearer token and, if a valid API key
// is found, returns the associated User (with Tenant + Role populated by the
// validator). Permissions are resolved by inject, not here. Returns nil when no
// key is present, the key is invalid, or APIKeyValidator is not configured.
func (a *Auth) tryAPIKeyAuth(r *http.Request) *User {
	if a.keyValidator == nil {
		return nil
	}
	raw := extractBearerToken(r)
	if raw == "" {
		return nil
	}
	u, err := a.keyValidator.ValidateKey(r.Context(), raw)
	if err != nil || u == nil {
		return nil
	}
	return u
}

// permsForRole resolves the permissions for (tenant, role), consulting the TTL
// cache first. The tenant must already be set on ctx so a DB-backed, tenant-aware
// PolicyProvider scopes its lookup correctly.
func (a *Auth) permsForRole(ctx context.Context, tenantID, role string) []string {
	if role == "" {
		return nil
	}
	key := tenantID + "|" + role
	if a.permCache != nil {
		if p, ok := a.permCache.get(key); ok {
			return p
		}
	}
	p := a.rbacProvider.PermissionsForRole(ctx, role)
	if a.permCache != nil {
		a.permCache.put(key, p)
	}
	return p
}

// inject sets the tenant on the request context, (re)resolves the user's
// permissions when required, attaches the user, and returns the updated request.
//
// forceResolve is true for credentials with no cached permissions (API keys).
// For session users, permissions were cached at login and are trusted unless
// LivePermissionResolution is enabled, in which case they are re-resolved per
// request (so role/permission changes take effect within the cache TTL rather
// than only on next login).
func (a *Auth) inject(r *http.Request, u *User, forceResolve bool) *http.Request {
	ctx := WithTenant(r.Context(), u.TenantID)
	if forceResolve || a.cfg.LivePermissionResolution {
		u.permissions = a.permsForRole(ctx, u.TenantID, u.Role)
	}
	ctx = withUser(ctx, u)
	return r.WithContext(ctx)
}

// RequireAuth is middleware that enforces a valid credential — either an API
// key (via APIKeyValidator, if configured) or an OAuth session cookie.
// Responds 401 when neither is present or valid.
// On success it injects the User into the request context.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := a.tryAPIKeyAuth(r); u != nil {
			next.ServeHTTP(w, a.inject(r, u, true))
			return
		}
		u, err := a.loadSession(r.Context(), r)
		if err != nil || u == nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, a.inject(r, u, false))
	})
}

// Require is middleware that enforces both a valid credential (API key or
// OAuth session) AND that the authenticated user holds the given permission.
// Returns 401 when there is no credential, 403 when the user lacks the permission.
func (a *Auth) Require(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u := a.tryAPIKeyAuth(r); u != nil {
				r = a.inject(r, u, true)
				if !u.Can(permission) {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			u, err := a.loadSession(r.Context(), r)
			if err != nil || u == nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			r = a.inject(r, u, false)
			if !u.Can(permission) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireSessionAuth is like RequireAuth but rejects API key credentials.
// Use this for routes that must only be accessed via an OAuth session
// (e.g. /auth/me, UI-only management actions).
func (a *Auth) RequireSessionAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := a.loadSession(r.Context(), r)
		if err != nil || u == nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, a.inject(r, u, false))
	})
}

// RequireSession is like Require but rejects API key credentials.
// Use this for permission-gated management routes that must use OAuth sessions.
func (a *Auth) RequireSession(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, err := a.loadSession(r.Context(), r)
			if err != nil || u == nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			r = a.inject(r, u, false)
			if !u.Can(permission) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
