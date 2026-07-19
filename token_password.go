package authkit

import (
	"net/http"
	"strings"
)

// Native password login: a password (+ optional TOTP) exchange that RETURNS the
// access + refresh token pair, instead of the cookie session the web
// /auth/login establishes. This is the first-party native path: the app
// collects credentials in a native screen (no browser / PKCE round-trip) and
// the same token layer — rotation, reuse detection, JWKS — backs it. The
// browser Authorize/IssueToken (PKCE) flow remains for third-party SSO.

// IssuePasswordToken exchanges email+password for a token pair. When the user's
// role requires 2FA, it instead returns a signed pending token that the client
// completes via IssuePasswordToken2FA. Cookie-free: everything travels in the
// request/response bodies so a native client needs no cookie jar.
//
// Mount on: POST /oauth/token/password. Fields: email, password.
func (a *Auth) IssuePasswordToken(w http.ResponseWriter, r *http.Request) {
	if !a.tokensEnabled() {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "tokens not enabled")
		return
	}
	if a.cfg.Mode == AuthModeOAuth {
		a.writeError(w, r, http.StatusNotFound, ErrCodeUnsupportedGrant, "password login is not enabled")
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
		// Constant-time: run a dummy verification to prevent timing-based enumeration.
		a.dummyVerify(password)
		a.throttleFailure(r.Context(), tkey)
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidGrant, "invalid email or password")
		return
	}
	if !a.checkPassword(storedUser.HashedPassword, password) {
		a.throttleFailure(r.Context(), tkey)
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidGrant, "invalid email or password")
		return
	}
	a.throttleReset(r.Context(), tkey)

	ctx := WithTenant(r.Context(), storedUser.TenantID)
	role, _ := a.rbacProvider.RoleFor(ctx, email)

	// A remembered device skips the TOTP step (password is still required).
	// The native client presents the opaque trusted-device token in the body.
	needs2FA := a.cfg.TwoFactor.Store != nil && a.requires2FA(role)
	if needs2FA && a.trustedDeviceTokenValid(
		ctx, storedUser.TenantID, email, r.FormValue("trusted_device_token")) {
		needs2FA = false
	}

	// Second factor required: mint a signed pending token and tell the client
	// whether to enroll (no confirmed secret yet) or verify.
	if needs2FA {
		_, confirmed, err := a.cfg.TwoFactor.Store.Secret(ctx, storedUser.TenantID, email)
		if err != nil {
			a.log.Error("totp secret lookup failed", "err", err)
			a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
			return
		}
		action := "verify"
		if !confirmed {
			action = "enroll"
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status":        "2fa_required",
			"action":        action,
			"pending_token": a.issuePendingToken(email),
		})
		return
	}

	u := &User{
		Email:    email,
		Name:     storedUser.Name,
		Provider: "password",
		Role:     role,
		TenantID: storedUser.TenantID,
		Attrs:    cloneAttrs(storedUser.Attrs),
	}
	access, refresh, err := a.issueTokenPair(ctx, u)
	if err != nil {
		a.log.Error("token issue failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	a.emitAudit(ctx, AuditEvent{Type: AuditLogin, TenantID: u.TenantID, Actor: email, Subject: email, IP: a.clientIP(r), At: nowFn(), Meta: map[string]any{"client": "native"}})
	writeTokenResponse(w, access, refresh, a.accessTTL())
}

// IssuePasswordToken2FA completes a pending native login by validating a TOTP
// (or recovery) code and returns the token pair. The pending token is the one
// returned by IssuePasswordToken; it is carried in the request body, not a
// cookie.
//
// Mount on: POST /oauth/token/2fa. Fields: pending_token, code (or recovery_code).
func (a *Auth) IssuePasswordToken2FA(w http.ResponseWriter, r *http.Request) {
	if !a.tokensEnabled() {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "tokens not enabled")
		return
	}
	if a.cfg.TwoFactor.Store == nil {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "2fa not enabled")
		return
	}
	parseBody(r)

	email, ok := a.parsePendingToken(r.FormValue("pending_token"))
	if !ok {
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidGrant, "invalid or expired 2fa challenge")
		return
	}

	tkey := throttleKey(email, a.clientIP(r))
	if !a.throttleAllow(w, r, tkey) {
		return
	}

	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email)
	if err != nil {
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidGrant, "invalid challenge")
		return
	}
	ctx := WithTenant(r.Context(), storedUser.TenantID)

	if !a.validate2FA(ctx, storedUser.TenantID, email, r) {
		a.throttleFailure(ctx, tkey)
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidGrant, "invalid code")
		return
	}
	// First successful verification confirms a pending enrollment (idempotent
	// for an already-confirmed secret), so future logins go straight to verify.
	if err := a.cfg.TwoFactor.Store.Confirm(ctx, storedUser.TenantID, email); err != nil {
		a.log.Error("totp confirm failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	a.throttleReset(ctx, tkey)

	role, _ := a.rbacProvider.RoleFor(ctx, email)
	u := &User{
		Email:    email,
		Name:     storedUser.Name,
		Provider: "password",
		Role:     role,
		TenantID: storedUser.TenantID,
		Attrs:    cloneAttrs(storedUser.Attrs),
	}
	access, refresh, err := a.issueTokenPair(ctx, u)
	if err != nil {
		a.log.Error("token issue failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}

	// "Remember this device": mint an opaque trusted-device token the client
	// stores and presents on the next login to skip the TOTP step.
	var trusted string
	if formTrue(r.FormValue("remember")) {
		trusted = a.mintTrustedDeviceToken(ctx, storedUser.TenantID, email)
	}

	a.emitAudit(ctx, AuditEvent{Type: AuditLogin, TenantID: u.TenantID, Actor: email, Subject: email, IP: a.clientIP(r), At: nowFn(), Meta: map[string]any{"client": "native", "twofa": true, "remembered": trusted != ""}})

	resp := map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    int(a.accessTTL().Seconds()),
	}
	if trusted != "" {
		resp["trusted_device_token"] = trusted
	}
	writeJSON(w, http.StatusOK, resp)
}
