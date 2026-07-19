package authkit

import (
	"context"
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

	if err := a.saveSession(ctx, w, r, u); err != nil {
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

	// Throttle per account+IP to blunt brute force / credential stuffing.
	tkey := throttleKey(email, clientIP(r))
	if !a.throttleAllow(w, r, tkey) {
		return
	}

	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email)
	if err != nil {
		// Constant-time: run a dummy bcrypt compare to prevent timing-based
		// user enumeration.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		a.throttleFailure(r.Context(), tkey)
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

	if !CheckPassword(storedUser.HashedPassword, password) {
		a.throttleFailure(r.Context(), tkey)
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

	// Success — clear the failure counter.
	a.throttleReset(r.Context(), tkey)

	// Scope ctx to the user's tenant so a tenant-aware PolicyProvider resolves
	// role/permissions against the right tenant.
	ctx := WithTenant(r.Context(), storedUser.TenantID)
	role, permissions := a.rbacProvider.RoleFor(ctx, email)

	// First-login gate: a user flagged must-change-password sets their own
	// password before anything else — even 2FA (the onboarding order is
	// Set password → Enroll 2FA → Recovery). Reuse the short-lived pending token
	// (it proves the password was just verified) so the SPA can post a new one to
	// /auth/password/first-change with no full session yet.
	if storedUser.MustChangePassword {
		a.setPendingCookie(w, a.issuePendingToken(email))
		writeJSON(w, http.StatusOK, map[string]string{"status": "password_change_required"})
		return
	}

	// Two-step auth: when the role requires 2FA, stop here and start the TOTP
	// challenge instead of minting a session — UNLESS this device was previously
	// trusted ("remember this device"), in which case skip straight to a session.
	// The password was still required; the trusted token is revocable + expiring.
	if a.cfg.TOTPStore != nil && a.requires2FA(role) {
		if a.trustedDeviceValid(r, storedUser.TenantID, email) {
			if err := a.establishLoginSession(ctx, w, r, email, storedUser); err != nil {
				a.log.Error("authkit: session error during trusted-device login: %v", err)
				http.Error(w, "session error", http.StatusInternalServerError)
				return
			}
			a.emitAudit(ctx, AuditEvent{Type: AuditLogin, TenantID: storedUser.TenantID, Actor: email, Subject: email, IP: clientIP(r), At: nowFn(), Meta: map[string]any{"trusted_device": true}})
			http.Redirect(w, r, a.cfg.AfterLoginURL, http.StatusSeeOther)
			return
		}
		a.beginTwoFactor(ctx, w, email)
		return
	}

	u := &User{
		Email:       email,
		Name:        storedUser.Name,
		Provider:    "password",
		Role:        role,
		TenantID:    storedUser.TenantID,
		BranchID:    storedUser.BranchID,
		permissions: permissions,
	}

	if err := a.saveSession(ctx, w, r, u); err != nil {
		a.log.Error("authkit: session error during login: %v", err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	a.emitAudit(ctx, AuditEvent{Type: AuditLogin, TenantID: u.TenantID, Actor: email, Subject: email, IP: clientIP(r), At: nowFn()})
	http.Redirect(w, r, a.cfg.AfterLoginURL, http.StatusSeeOther)
}

// establishLoginSession resolves the user's role/permissions and creates the
// session. Shared by the post-2FA verify path.
func (a *Auth) establishLoginSession(ctx context.Context, w http.ResponseWriter, r *http.Request, email string, storedUser *PasswordUser) error {
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
	return a.saveSession(ctx, w, r, u)
}

// ChangeFirstPassword replaces the password for a user in the first-login
// "must change password" pending state — the pending cookie set by Login proves
// the old (temporary) password was just verified. On success it clears the
// must-change flag (via UpdatePassword) and CONTINUES the login: it starts the
// TOTP step when the role needs 2FA, otherwise it mints the session directly. So
// the order is always Set password → 2FA, matching onboarding.
// Mount on: POST /auth/password/first-change. Expects form: password.
func (a *Auth) ChangeFirstPassword(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Mode == AuthModeOAuth {
		http.Error(w, "password login is not enabled", http.StatusNotFound)
		return
	}
	email, ok := a.readPendingToken(r)
	if !ok {
		http.Error(w, "no pending challenge", http.StatusUnauthorized)
		return
	}
	newPassword := r.FormValue("password")
	if err := a.validatePassword(newPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "invalid challenge", http.StatusUnauthorized)
		return
	}
	ctx := WithTenant(r.Context(), storedUser.TenantID)
	hashed, err := HashPassword(newPassword)
	if err != nil {
		a.log.Error("authkit: hash password: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// UpdatePassword also clears the must-change flag (the store owns that).
	if err := a.cfg.UserStore.UpdatePassword(ctx, email, hashed); err != nil {
		a.log.Error("authkit: first-password update: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	storedUser.HashedPassword = hashed
	storedUser.MustChangePassword = false
	a.emitAudit(ctx, AuditEvent{Type: AuditPasswordChange, TenantID: storedUser.TenantID, Actor: email, Subject: email, IP: clientIP(r), At: nowFn(), Meta: map[string]any{"first_login": true}})

	// Continue the login. beginTwoFactor rotates the pending cookie for the TOTP
	// step; the non-2FA path clears it and establishes the session.
	role, _ := a.rbacProvider.RoleFor(ctx, email)
	if a.cfg.TOTPStore != nil && a.requires2FA(role) {
		a.beginTwoFactor(ctx, w, email)
		return
	}
	a.clearPendingCookie(w)
	if err := a.establishLoginSession(ctx, w, r, email, storedUser); err != nil {
		a.log.Error("authkit: session error after first-password change: %v", err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	a.emitAudit(ctx, AuditEvent{Type: AuditLogin, TenantID: storedUser.TenantID, Actor: email, Subject: email, IP: clientIP(r), At: nowFn()})
	http.Redirect(w, r, a.cfg.AfterLoginURL, http.StatusSeeOther)
}
