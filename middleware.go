package authkit

import (
	"net/http"
)

// RequireAuth is middleware that enforces a valid session. If the request has
// no valid session the handler responds with 401 and stops the chain.
// On success it injects the User into the request context so downstream
// handlers can call UserFromCtx(r.Context()).
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := userFromSession(a.store, r, a.log)
		if err != nil || u == nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), u)))
	})
}

// Require is middleware that enforces both a valid session AND that the
// authenticated user holds the given permission. Use it to gate individual
// routes or sub-trees:
//
//	mux.Handle("POST /api/projects", auth.Require("manage")(createProject))
//
// Returns 401 when there is no session, 403 when the user lacks the permission.
func (a *Auth) Require(permission string) func(http.Handler) http.Handler {
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
