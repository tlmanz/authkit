package authkit

import (
	"errors"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Register creates a new user account with email and password, then logs
// them in automatically. Mount this on: POST /auth/register
//
// Expects form values: email, password, and optionally name.
func (a *Auth) Register(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Mode == AuthModeOAuth {
		http.Error(w, "password registration is not enabled", http.StatusNotFound)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	name := strings.TrimSpace(r.FormValue("name"))
	password := r.FormValue("password")

	if !validEmail.MatchString(email) {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}

	if err := a.validatePassword(password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashed, err := HashPassword(password)
	if err != nil {
		a.log.Error("authkit: hash error during registration: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := a.cfg.UserStore.CreateUser(r.Context(), email, name, hashed); err != nil {
		if errors.Is(err, ErrUserExists) {
			http.Error(w, "user already exists", http.StatusConflict)
			return
		}
		a.log.Error("authkit: register error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Re-read the persisted user so the auto-login session carries the tenant
	// (and any store-assigned fields). CreateUser does not return the tenant.
	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email)
	if err != nil {
		a.log.Error("authkit: post-register lookup failed for %q: %v", email, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Auto-login: scope ctx to the user's tenant, resolve RBAC role, create session.
	ctx := WithTenant(r.Context(), storedUser.TenantID)
	role, permissions := a.rbacProvider.RoleFor(ctx, email)
	u := &User{
		Email:       email,
		Name:        name,
		Provider:    "password",
		Role:        role,
		TenantID:    storedUser.TenantID,
		BranchID:    storedUser.BranchID,
		permissions: permissions,
	}

	if err := saveUserToSession(a.store, w, r, u); err != nil {
		a.log.Error("authkit: session error during registration: %v", err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, a.cfg.AfterLoginURL, http.StatusSeeOther)
}

// Login authenticates a user with email and password.
// Mount this on: POST /auth/login
//
// Expects form values: email and password.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Mode == AuthModeOAuth {
		http.Error(w, "password login is not enabled", http.StatusNotFound)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email)
	if err != nil {
		// Constant-time: run a dummy bcrypt compare to prevent timing-based
		// user enumeration.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

	if !CheckPassword(storedUser.HashedPassword, password) {
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

	// Scope ctx to the user's tenant so a tenant-aware PolicyProvider resolves
	// role/permissions against the right tenant.
	ctx := WithTenant(r.Context(), storedUser.TenantID)
	role, permissions := a.rbacProvider.RoleFor(ctx, email)
	u := &User{
		Email:       email,
		Name:        storedUser.Name,
		Provider:    "password",
		Role:        role,
		TenantID:    storedUser.TenantID,
		BranchID:    storedUser.BranchID,
		permissions: permissions,
	}

	if err := saveUserToSession(a.store, w, r, u); err != nil {
		a.log.Error("authkit: session error during login: %v", err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, a.cfg.AfterLoginURL, http.StatusSeeOther)
}
