package authkit

import (
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
// is found, returns a fully populated User (with permissions resolved from the
// RBAC policy). Returns nil when no key is present, the key is invalid, or
// APIKeyValidator is not configured.
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
	// Resolve RBAC permissions for the role assigned to this API key.
	u.permissions = a.rbac.permissionsForRole(u.Role)
	return u
}

// RequireAuth is middleware that enforces a valid credential — either an API
// key (via APIKeyValidator, if configured) or an OAuth session cookie.
// Responds 401 when neither is present or valid.
// On success it injects the User into the request context.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := a.tryAPIKeyAuth(r); u != nil {
			next.ServeHTTP(w, r.WithContext(withUser(r.Context(), u)))
			return
		}
		u, err := userFromSession(a.store, r, a.log)
		if err != nil || u == nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), u)))
	})
}

// Require is middleware that enforces both a valid credential (API key or
// OAuth session) AND that the authenticated user holds the given permission.
// Returns 401 when there is no credential, 403 when the user lacks the permission.
func (a *Auth) Require(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u := a.tryAPIKeyAuth(r); u != nil {
				if !u.Can(permission) {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r.WithContext(withUser(r.Context(), u)))
				return
			}
			u, err := userFromSession(a.store, r, a.log)
			if err != nil || u == nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			if !u.Can(permission) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(withUser(r.Context(), u)))
		})
	}
}

// RequireSessionAuth is like RequireAuth but rejects API key credentials.
// Use this for routes that must only be accessed via an OAuth session
// (e.g. /auth/me, UI-only management actions).
func (a *Auth) RequireSessionAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := userFromSession(a.store, r, a.log)
		if err != nil || u == nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), u)))
	})
}

// RequireSession is like Require but rejects API key credentials.
// Use this for permission-gated management routes that must use OAuth sessions.
func (a *Auth) RequireSession(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, err := userFromSession(a.store, r, a.log)
			if err != nil || u == nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			if !u.Can(permission) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(withUser(r.Context(), u)))
		})
	}
}
