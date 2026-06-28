package authkit

import (
	"encoding/json"
	"net/http"

	"github.com/markbates/goth/gothic"
)

// BeginAuth starts the OAuth flow for the provider named in the URL path.
// Mount this on: GET /auth/{provider}
//
// The provider name is extracted from the Go 1.22+ path value {provider}.
func (a *Auth) BeginAuth(w http.ResponseWriter, r *http.Request) {
	gothic.BeginAuthHandler(w, r)
}

// Callback completes the OAuth handshake, resolves the user's role from the
// RBAC policy, stores the user in the session, then redirects to AfterLoginURL.
// Mount this on: GET /auth/{provider}/callback
func (a *Auth) Callback(w http.ResponseWriter, r *http.Request) {
	gothUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		a.log.Error("authkit: OAuth callback error: %v", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	email := gothUser.Email
	role, permissions := a.rbacProvider.RoleFor(r.Context(), email)

	u := &User{
		Email:       email,
		Name:        gothUser.Name,
		AvatarURL:   gothUser.AvatarURL,
		Provider:    gothUser.Provider,
		Role:        role,
		permissions: permissions,
	}

	if err := a.saveSession(r.Context(), w, r, u); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, a.cfg.AfterLoginURL, http.StatusSeeOther)
}

// Logout clears the session and redirects to AfterLogoutURL.
// Mount this on: POST /auth/logout
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	_ = gothic.Logout(w, r)
	a.endSession(r.Context(), w, r)
	http.Redirect(w, r, a.cfg.AfterLogoutURL, http.StatusSeeOther)
}

// Me returns the currently authenticated user as JSON.
// Returns 401 if the request has no valid session.
// Mount this on: GET /auth/me
func (a *Auth) Me(w http.ResponseWriter, r *http.Request) {
	u := UserFromCtx(r.Context())
	if u == nil {
		// Me can also be called without RequireAuth in the chain — handle that.
		var err error
		u, err = a.loadSession(r.Context(), r)
		if err != nil || u == nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(u)
}
