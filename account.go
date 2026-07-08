package authkit

import "net/http"

// Self-service account & security endpoints for an authenticated tenant user
// (§6.5). These complement the login-time flows: a logged-in user can rotate
// their own password, sign out everywhere, and manage their 2FA. Each requires
// a live session — mount them behind RequireSessionAuth. The current user and a
// tenant-scoped context are taken from RequireSessionAuth's injection.

// sessionUser returns the authenticated user and a tenant-scoped context, or
// writes 401 and returns ok=false. Mount these handlers behind
// RequireSessionAuth so the user is already injected.
func (a *Auth) sessionUser(w http.ResponseWriter, r *http.Request) (*User, bool) {
	u := UserFromCtx(r.Context())
	if u == nil {
		var err error
		if u, err = a.loadSession(r.Context(), r); err != nil || u == nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return nil, false
		}
	}
	return u, true
}

// ChangePassword lets a signed-in user rotate their own password. It verifies
// the current password, sets the new one, then revokes every session and mints
// a fresh one for THIS device — so other devices are logged out (a credential
// change must not leave old sessions live) while the user stays signed in here.
// Mount on: POST /auth/password/change. Form: current_password, new_password.
func (a *Auth) ChangePassword(w http.ResponseWriter, r *http.Request) {
	u, ok := a.sessionUser(w, r)
	if !ok {
		return
	}
	ctx := WithTenant(r.Context(), u.TenantID)

	current := r.FormValue("current_password")
	next := r.FormValue("new_password")
	if err := a.validatePassword(next); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	stored, err := a.cfg.UserStore.GetUserByEmail(ctx, u.Email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !CheckPassword(stored.HashedPassword, current) {
		http.Error(w, "current password is incorrect", http.StatusBadRequest)
		return
	}

	hashed, err := HashPassword(next)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := a.cfg.UserStore.UpdatePassword(ctx, u.Email, hashed); err != nil {
		a.log.Error("authkit: change password: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Invalidate every session, then re-establish one for the current device so
	// the user is not logged out of the browser they just changed it from.
	if a.cfg.SessionStore != nil {
		_ = a.cfg.SessionStore.RevokeAllForUser(ctx, u.TenantID, u.Email)
		// A password change also forgets trusted devices: a 2FA role re-verifies
		// on next login everywhere.
		a.revokeTrustedDevices(ctx, u.TenantID, u.Email)
		// ...and revokes every mobile refresh token, so the bearer axis is cut off
		// too and does not keep minting access tokens for up to the refresh TTL.
		if a.cfg.RefreshTokenStore != nil {
			_ = a.cfg.RefreshTokenStore.RevokeAllForUser(ctx, u.TenantID, u.Email)
		}
		if err := a.establishServerSession(ctx, w, r, u); err != nil {
			a.log.Error("authkit: re-establish session after password change: %v", err)
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
	}
	a.emitAudit(ctx, AuditEvent{Type: AuditPasswordChange, TenantID: u.TenantID, Actor: u.Email, Subject: u.Email, IP: clientIP(r), At: nowFn()})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// LogoutEverywhere revokes every session for the current user, including this
// one, and clears the cookie ("log out all devices"). The client should treat
// the response as a logout and route to login. Mount on: POST /auth/logout/all.
func (a *Auth) LogoutEverywhere(w http.ResponseWriter, r *http.Request) {
	u, ok := a.sessionUser(w, r)
	if !ok {
		return
	}
	ctx := WithTenant(r.Context(), u.TenantID)
	if a.cfg.SessionStore != nil {
		if err := a.cfg.SessionStore.RevokeAllForUser(ctx, u.TenantID, u.Email); err != nil {
			a.log.Error("authkit: revoke all sessions: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	// "Log out everywhere" also forgets every trusted device, so a 2FA role is
	// challenged again on each device next login.
	a.revokeTrustedDevices(ctx, u.TenantID, u.Email)
	// ...and revokes every mobile refresh token, so "log out all devices" truly
	// includes the bearer axis (a fired-staff revoke cuts off the phone too).
	if a.cfg.RefreshTokenStore != nil {
		_ = a.cfg.RefreshTokenStore.RevokeAllForUser(ctx, u.TenantID, u.Email)
	}
	a.clearSIDCookie(w)
	a.clearTrustedDeviceCookie(w)
	a.emitAudit(ctx, AuditEvent{Type: AuditRevoke, TenantID: u.TenantID, Actor: u.Email, Subject: u.Email, IP: clientIP(r), At: nowFn(), Meta: map[string]any{"scope": "all"}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// TwoFactorStatus reports whether the current user has confirmed 2FA and
// whether their role mandates it (§6.5#4). The SPA uses this to show
// enroll-vs-manage and to mark 2FA as required. Mount on: GET /auth/2fa/status.
func (a *Auth) TwoFactorStatus(w http.ResponseWriter, r *http.Request) {
	u, ok := a.sessionUser(w, r)
	if !ok {
		return
	}
	resp := map[string]bool{
		"available": a.cfg.TOTPStore != nil,
		"enabled":   false,
		"required":  a.requires2FA(u.Role),
	}
	if a.cfg.TOTPStore != nil {
		ctx := WithTenant(r.Context(), u.TenantID)
		if secret, confirmed, err := a.cfg.TOTPStore.Secret(ctx, u.TenantID, u.Email); err == nil {
			resp["enabled"] = secret != "" && confirmed
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// ConfirmTwoFactor activates a pending TOTP secret for a user enrolling
// voluntarily from their account page (as opposed to the login-time flow, which
// uses Verify2FA + the pending cookie). It validates a code against the freshly
// provisioned secret and confirms it. Mount on: POST /auth/2fa/confirm.
// Form: code (6-digit TOTP) or recovery_code.
func (a *Auth) ConfirmTwoFactor(w http.ResponseWriter, r *http.Request) {
	if a.cfg.TOTPStore == nil {
		http.Error(w, "2fa not enabled", http.StatusNotFound)
		return
	}
	u, ok := a.sessionUser(w, r)
	if !ok {
		return
	}
	ctx := WithTenant(r.Context(), u.TenantID)
	if !a.validate2FA(ctx, u.TenantID, u.Email, r) {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	if err := a.cfg.TOTPStore.Confirm(ctx, u.TenantID, u.Email); err != nil {
		a.log.Error("authkit: confirm 2fa: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.emitAudit(ctx, AuditEvent{Type: Audit2FAEnroll, TenantID: u.TenantID, Actor: u.Email, Subject: u.Email, IP: clientIP(r), At: nowFn()})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// DisableTwoFactor turns off the current user's 2FA. Refused when the user's
// role mandates 2FA (they would be forced to re-enroll at next login anyway).
// Mount on: POST /auth/2fa/disable.
func (a *Auth) DisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	mgr, ok := a.totpManager(w)
	if !ok {
		return
	}
	u, ok := a.sessionUser(w, r)
	if !ok {
		return
	}
	if a.requires2FA(u.Role) {
		http.Error(w, "two-factor authentication is required for your role", http.StatusForbidden)
		return
	}
	ctx := WithTenant(r.Context(), u.TenantID)
	if err := mgr.Disable(ctx, u.TenantID, u.Email); err != nil {
		a.log.Error("authkit: disable 2fa: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// With 2FA off, any trusted devices are moot; drop them.
	a.revokeTrustedDevices(ctx, u.TenantID, u.Email)
	a.emitAudit(ctx, AuditEvent{Type: Audit2FADisable, TenantID: u.TenantID, Actor: u.Email, Subject: u.Email, IP: clientIP(r), At: nowFn()})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// RegenerateRecoveryCodes issues a fresh set of recovery codes for a user whose
// 2FA is already confirmed, invalidating the old set, and returns the new codes
// to show once. Mount on: POST /auth/2fa/recovery/regenerate.
func (a *Auth) RegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	mgr, ok := a.totpManager(w)
	if !ok {
		return
	}
	u, ok := a.sessionUser(w, r)
	if !ok {
		return
	}
	ctx := WithTenant(r.Context(), u.TenantID)
	secret, confirmed, err := a.cfg.TOTPStore.Secret(ctx, u.TenantID, u.Email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if secret == "" || !confirmed {
		http.Error(w, "two-factor authentication is not enabled", http.StatusBadRequest)
		return
	}
	plain, hashes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := mgr.ReplaceRecoveryCodes(ctx, u.TenantID, u.Email, hashes); err != nil {
		a.log.Error("authkit: regenerate recovery codes: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.emitAudit(ctx, AuditEvent{Type: Audit2FARecoveryRegen, TenantID: u.TenantID, Actor: u.Email, Subject: u.Email, IP: clientIP(r), At: nowFn()})
	writeJSON(w, http.StatusOK, map[string][]string{"recoveryCodes": plain})
}

// totpManager resolves the optional TOTPManager extension on the configured
// store, writing 501/404 when 2FA management is unavailable.
func (a *Auth) totpManager(w http.ResponseWriter) (TOTPManager, bool) {
	if a.cfg.TOTPStore == nil {
		http.Error(w, "2fa not enabled", http.StatusNotFound)
		return nil, false
	}
	mgr, ok := a.cfg.TOTPStore.(TOTPManager)
	if !ok {
		http.Error(w, "2fa management not supported", http.StatusNotImplemented)
		return nil, false
	}
	return mgr, true
}
