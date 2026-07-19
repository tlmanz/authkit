package authkit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

// Password reset ("forgot password"). The flow is the same for both principal
// axes — regular users and platform admins — and shares one store:
//
//  1. forgot: the client posts an email. We ALWAYS answer 200 with the same body
//     (no user enumeration). When the email matches a principal, a single-use,
//     hashed token is minted and delivered out-of-band via ResetDelivery.
//  2. reset:  the client posts the raw token + a new password. We consume the
//     token (atomic, single-use), set the new password, and revoke every session
//     for that principal — a credential change must not leave old sessions live.
//
// Only the token's hash is stored, so a store compromise yields no usable links.
// The Kind field namespaces a token to one axis, so a user token can never be
// consumed on the platform path (or vice versa). Platform reset never touches
// 2FA — the admin still passes TOTP at next login.

// Reset kinds namespace a token to one principal axis.
const (
	ResetKindUser     = "user"
	ResetKindPlatform = "platform"
)

const defaultPasswordResetTTL = 30 * time.Minute

// ResetToken is a single-use, hashed password-reset token record. UsedAt is nil
// until the token is consumed.
type ResetToken struct {
	TokenHash string
	Email     string
	Kind      string
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// PasswordResetStore persists single-use password-reset tokens. The raw token is
// delivered out-of-band (email, SMS, ...); only its hash is stored.
// Consume MUST be atomic and single-use.
type PasswordResetStore interface {
	// CreateResetToken stores a hashed token bound to (email, kind) with expiry.
	CreateResetToken(ctx context.Context, tokenHash, email, kind string, expiresAt time.Time) error
	// ConsumeResetToken atomically marks the token used (only if unused and
	// unexpired) and returns the email it binds. ok is false when the token is
	// unknown, already used, expired, or of the wrong kind.
	ConsumeResetToken(ctx context.Context, tokenHash, kind string) (email string, ok bool, err error)
}

// ResetRequest is handed to ResetDelivery to deliver a reset token. authkit
// stores only the hash; Token here is the raw secret that goes in the link/code.
// Kind selects the template/channel and which reset page the link points to.
type ResetRequest struct {
	Email string
	Name  string
	Kind  string
	Token string
	TTL   time.Duration
}

// ResetDelivery delivers a password-reset token to the principal. The host owns
// the channel (email, SMS, ...) — authkit is channel-agnostic. Sending is
// best-effort from the request's perspective: the "forgot" endpoint logs a
// delivery error but still returns 200, so it leaks neither which emails exist
// nor which channel succeeded.
type ResetDelivery interface {
	SendPasswordReset(ctx context.Context, req ResetRequest) error
}

func (a *Auth) passwordResetTTL() time.Duration {
	if a.cfg.Reset.TTL > 0 {
		return a.cfg.Reset.TTL
	}
	return defaultPasswordResetTTL
}

func (a *Auth) resetEnabled() bool {
	return a.cfg.Reset.Store != nil && a.cfg.Reset.Delivery != nil
}

// newResetToken returns a 256-bit URL-safe raw token and its SHA-256 hash.
func newResetToken() (raw, hash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b[:])
	return raw, hashResetToken(raw), nil
}

func hashResetToken(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

// IssueResetToken mints, stores, and delivers a reset token for (email, kind).
// It is the shared core of the self-service forgot-password handlers and any
// admin-initiated reset (an operator resetting a staff member). It returns the
// raw token so an authenticated caller can surface the reset link directly; the
// public handlers discard it. A delivery error is returned (the caller decides);
// a store error is returned without attempting delivery.
func (a *Auth) IssueResetToken(ctx context.Context, email, name, kind string) (string, error) {
	raw, hash, err := newResetToken()
	if err != nil {
		return "", err
	}
	ttl := a.passwordResetTTL()
	if err := a.cfg.Reset.Store.CreateResetToken(ctx, hash, email, kind, nowFn().Add(ttl)); err != nil {
		return "", err
	}
	derr := a.cfg.Reset.Delivery.SendPasswordReset(ctx, ResetRequest{Email: email, Name: name, Kind: kind, Token: raw, TTL: ttl})
	return raw, derr
}

// ForgotPassword starts self-service recovery for a user. It ALWAYS responds
// 200 with the same body whether or not the email exists, leaking nothing
// about which emails are registered. Mount on: POST /auth/password/forgot.
// Fields: email.
func (a *Auth) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if !a.resetEnabled() {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "password reset not enabled")
		return
	}
	parseBody(r)
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	// Rate-limit before doing any email-existence-dependent work: this blunts
	// reset email-bombing of a victim and the timing side channel that would
	// otherwise distinguish a registered email (which does a store write +
	// delivery) from an unknown one. Namespaced so it never shares the login
	// lockout counter. The 429 reveals nothing about whether the email exists.
	tkey := "pwreset|" + throttleKey(email, a.clientIP(r))
	if !a.throttleAllow(w, r, tkey) {
		return
	}
	a.throttleFailure(r.Context(), tkey)
	if validEmail.MatchString(email) {
		if u, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email); err == nil {
			ctx := WithTenant(r.Context(), u.TenantID)
			if _, derr := a.IssueResetToken(ctx, email, u.Name, ResetKindUser); derr != nil {
				a.log.Error("deliver reset token failed", "err", derr)
			}
			a.emitAudit(ctx, AuditEvent{Type: AuditPasswordResetRequest, TenantID: u.TenantID, Actor: email, Subject: email, IP: a.clientIP(r), At: nowFn()})
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ResetPassword completes self-service recovery: consume a valid reset token,
// set the new password, and revoke all of the user's sessions. Mount on:
// POST /auth/password/reset. Fields: token, password.
func (a *Auth) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Reset.Store == nil {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "password reset not enabled")
		return
	}
	parseBody(r)
	token := strings.TrimSpace(r.FormValue("token"))
	password := r.FormValue("password")
	if err := a.validatePassword(password); err != nil {
		a.writeError(w, r, http.StatusBadRequest, ErrCodePasswordPolicy, err.Error())
		return
	}
	email, ok, err := a.cfg.Reset.Store.ConsumeResetToken(r.Context(), hashResetToken(token), ResetKindUser)
	if err != nil {
		a.log.Error("consume reset token failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	if !ok {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid or expired reset link")
		return
	}
	u, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email)
	if err != nil {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid or expired reset link")
		return
	}
	hashed, err := a.hashPassword(password)
	if err != nil {
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	ctx := WithTenant(r.Context(), u.TenantID)
	if err := a.cfg.UserStore.UpdatePassword(ctx, email, hashed); err != nil {
		a.log.Error("update password failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	// A credential change invalidates every existing session + trusted device +
	// refresh token, so a password reset cuts off the bearer axis too and an
	// attacker who triggered the reset cannot keep a live refresh chain.
	if a.cfg.Sessions.Store != nil {
		_ = a.cfg.Sessions.Store.RevokeAllForUser(ctx, u.TenantID, email)
	}
	a.revokeTrustedDevices(ctx, u.TenantID, email)
	if a.cfg.Tokens.RefreshStore != nil {
		_ = a.cfg.Tokens.RefreshStore.RevokeAllForUser(ctx, u.TenantID, email)
	}
	a.emitAudit(ctx, AuditEvent{Type: AuditPasswordReset, TenantID: u.TenantID, Actor: email, Subject: email, IP: a.clientIP(r), At: nowFn()})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// PlatformForgotPassword starts self-service recovery for a platform admin.
// Same no-enumeration contract as ForgotPassword. Mount on:
// POST /platform/password/forgot. Fields: email.
func (a *Auth) PlatformForgotPassword(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Platform.Store == nil || !a.resetEnabled() {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "not enabled")
		return
	}
	parseBody(r)
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	// Same rate-limit + no-enumeration reasoning as ForgotPassword.
	tkey := "pwreset|platform|" + throttleKey(email, a.clientIP(r))
	if !a.throttleAllow(w, r, tkey) {
		return
	}
	a.throttleFailure(r.Context(), tkey)
	if validEmail.MatchString(email) {
		if rec, err := a.cfg.Platform.Store.GetPlatformAdmin(r.Context(), email); err == nil {
			if _, derr := a.IssueResetToken(r.Context(), email, rec.Name, ResetKindPlatform); derr != nil {
				a.log.Error("deliver platform reset token failed", "err", derr)
			}
			a.emitAudit(r.Context(), AuditEvent{Type: AuditPasswordResetRequest, Actor: email, Subject: email, IP: a.clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true}})
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// PlatformResetPassword completes a platform admin's recovery: consume the
// token, set the new password, revoke platform sessions. 2FA enrollment is
// untouched — the admin still passes TOTP at next login. Mount on:
// POST /platform/password/reset. Fields: token, password.
func (a *Auth) PlatformResetPassword(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Platform.Store == nil || a.cfg.Reset.Store == nil {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "not enabled")
		return
	}
	parseBody(r)
	token := strings.TrimSpace(r.FormValue("token"))
	password := r.FormValue("password")
	if err := a.validatePassword(password); err != nil {
		a.writeError(w, r, http.StatusBadRequest, ErrCodePasswordPolicy, err.Error())
		return
	}
	email, ok, err := a.cfg.Reset.Store.ConsumeResetToken(r.Context(), hashResetToken(token), ResetKindPlatform)
	if err != nil {
		a.log.Error("consume platform reset token failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	if !ok {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid or expired reset link")
		return
	}
	hashed, err := a.hashPassword(password)
	if err != nil {
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	if err := a.cfg.Platform.Store.UpdatePassword(r.Context(), email, hashed); err != nil {
		a.log.Error("update platform password failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	// Platform sessions carry no tenant; revoke under the empty-tenant index.
	if a.cfg.Sessions.Store != nil {
		_ = a.cfg.Sessions.Store.RevokeAllForUser(r.Context(), "", email)
	}
	a.emitAudit(r.Context(), AuditEvent{Type: AuditPasswordReset, Actor: email, Subject: email, IP: a.clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
