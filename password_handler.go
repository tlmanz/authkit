package authkit

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Register creates a new user account with email and password, then logs
// them in automatically. Mount this on: POST /auth/register
//
// Expects fields (form or JSON): email, password, and optionally name.
func (a *Auth) Register(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Mode == AuthModeOAuth {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "password registration is not enabled")
		return
	}
	parseBody(r)

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	name := strings.TrimSpace(r.FormValue("name"))
	password := r.FormValue("password")

	if !validEmail.MatchString(email) {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid email")
		return
	}

	if err := a.validatePassword(password); err != nil {
		a.writeError(w, r, http.StatusBadRequest, ErrCodePasswordPolicy, err.Error())
		return
	}

	hashed, err := a.hashPassword(password)
	if err != nil {
		a.log.Error("hash error during registration", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}

	if err := a.cfg.UserStore.CreateUser(r.Context(), email, name, hashed); err != nil {
		if errors.Is(err, ErrUserExists) {
			a.writeError(w, r, http.StatusConflict, ErrCodeConflict, "user already exists")
			return
		}
		a.log.Error("register failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}

	// Re-read the persisted user so the auto-login session carries the tenant
	// (and any store-assigned fields). CreateUser does not return the tenant.
	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email)
	if err != nil {
		a.log.Error("post-register lookup failed", "email", email, "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
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
		Attrs:       cloneAttrs(storedUser.Attrs),
		permissions: permissions,
	}

	if err := a.saveSession(ctx, w, r, u); err != nil {
		a.log.Error("session error during registration", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "session error")
		return
	}

	http.Redirect(w, r, a.cfg.AfterLoginURL, http.StatusSeeOther)
}

// Login authenticates a user with email and password.
// Mount this on: POST /auth/login
//
// Expects fields (form or JSON): email and password.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Mode == AuthModeOAuth {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "password login is not enabled")
		return
	}
	parseBody(r)

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	// Throttle per account+IP to blunt brute force / credential stuffing.
	tkey := throttleKey(email, a.clientIP(r))
	if !a.throttleAllow(w, r, tkey) {
		return
	}

	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email)
	if err != nil {
		// Constant-time: run a dummy verification to prevent timing-based
		// user enumeration.
		a.dummyVerify(password)
		a.throttleFailure(r.Context(), tkey)
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidCredential, "invalid email or password")
		return
	}

	if !a.checkPassword(storedUser.HashedPassword, password) {
		a.throttleFailure(r.Context(), tkey)
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidCredential, "invalid email or password")
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
	// (it proves the password was just verified) so the client can post a new
	// one to /auth/password/first-change with no full session yet.
	if storedUser.MustChangePassword {
		a.setPendingCookie(w, a.issuePendingToken(email))
		writeJSON(w, http.StatusOK, map[string]string{"status": "password_change_required"})
		return
	}

	// Two-step auth: when the role requires 2FA, stop here and start the TOTP
	// challenge instead of minting a session — UNLESS this device was previously
	// trusted ("remember this device"), in which case skip straight to a session.
	// The password was still required; the trusted token is revocable + expiring.
	if a.cfg.TwoFactor.Store != nil && a.requires2FA(role) {
		if a.trustedDeviceValid(r, storedUser.TenantID, email) {
			if err := a.establishLoginSession(ctx, w, r, email, storedUser); err != nil {
				a.log.Error("session error during trusted-device login", "err", err)
				a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "session error")
				return
			}
			a.emitAudit(ctx, AuditEvent{Type: AuditLogin, TenantID: storedUser.TenantID, Actor: email, Subject: email, IP: a.clientIP(r), At: nowFn(), Meta: map[string]any{"trusted_device": true}})
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
		Attrs:       cloneAttrs(storedUser.Attrs),
		permissions: permissions,
	}

	if err := a.saveSession(ctx, w, r, u); err != nil {
		a.log.Error("session error during login", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "session error")
		return
	}

	a.emitAudit(ctx, AuditEvent{Type: AuditLogin, TenantID: u.TenantID, Actor: email, Subject: email, IP: a.clientIP(r), At: nowFn()})
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
		Attrs:       cloneAttrs(storedUser.Attrs),
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
// Mount on: POST /auth/password/first-change. Fields: password.
func (a *Auth) ChangeFirstPassword(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Mode == AuthModeOAuth {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "password login is not enabled")
		return
	}
	parseBody(r)
	email, ok := a.readPendingToken(r)
	if !ok {
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidChallenge, "no pending challenge")
		return
	}
	newPassword := r.FormValue("password")
	if err := a.validatePassword(newPassword); err != nil {
		a.writeError(w, r, http.StatusBadRequest, ErrCodePasswordPolicy, err.Error())
		return
	}

	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email)
	if err != nil {
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidChallenge, "invalid challenge")
		return
	}
	ctx := WithTenant(r.Context(), storedUser.TenantID)
	hashed, err := a.hashPassword(newPassword)
	if err != nil {
		a.log.Error("hash password failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	// UpdatePassword also clears the must-change flag (the store owns that).
	if err := a.cfg.UserStore.UpdatePassword(ctx, email, hashed); err != nil {
		a.log.Error("first-password update failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	storedUser.HashedPassword = hashed
	storedUser.MustChangePassword = false
	a.emitAudit(ctx, AuditEvent{Type: AuditPasswordChange, TenantID: storedUser.TenantID, Actor: email, Subject: email, IP: a.clientIP(r), At: nowFn(), Meta: map[string]any{"first_login": true}})

	// Continue the login. beginTwoFactor rotates the pending cookie for the TOTP
	// step; the non-2FA path clears it and establishes the session.
	role, _ := a.rbacProvider.RoleFor(ctx, email)
	if a.cfg.TwoFactor.Store != nil && a.requires2FA(role) {
		a.beginTwoFactor(ctx, w, email)
		return
	}
	a.clearPendingCookie(w)
	if err := a.establishLoginSession(ctx, w, r, email, storedUser); err != nil {
		a.log.Error("session error after first-password change", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "session error")
		return
	}
	a.emitAudit(ctx, AuditEvent{Type: AuditLogin, TenantID: storedUser.TenantID, Actor: email, Subject: email, IP: a.clientIP(r), At: nowFn()})
	http.Redirect(w, r, a.cfg.AfterLoginURL, http.StatusSeeOther)
}
