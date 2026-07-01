package authkit

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// trustedDeviceCookieNm is the cookie holding the opaque trusted-device token.
const trustedDeviceCookieNm = "authkit_trusted"

// defaultTrustedDeviceTTL is how long a remembered device skips 2FA when
// Config.TrustedDeviceTTL is unset.
const defaultTrustedDeviceTTL = 30 * 24 * time.Hour

// TrustedDeviceStore persists "remember this device" tokens so a user whose role
// requires 2FA can skip the TOTP step on a device they previously trusted. The
// token is opaque and server-side, so it is revocable: "log out everywhere", a
// password change/reset, and disabling 2FA all drop a user's trusted devices.
// Password is still required on every login; only the second factor is skipped.
// NOT used for platform admins (their 2FA is mandatory). All calls carry the
// user's tenant on the context.
type TrustedDeviceStore interface {
	// Trust records a trusted device for (tenant, email) and returns the opaque
	// cookie token. ttl bounds its lifetime.
	Trust(ctx context.Context, tenantID, email string, ttl time.Duration) (token string, err error)
	// IsTrusted reports whether token is a live trusted device for (tenant, email).
	IsTrusted(ctx context.Context, tenantID, email, token string) (bool, error)
	// RevokeAllForUser drops every trusted device for a user.
	RevokeAllForUser(ctx context.Context, tenantID, email string) error
}

func (a *Auth) trustedDeviceTTL() time.Duration {
	if a.cfg.TrustedDeviceTTL > 0 {
		return a.cfg.TrustedDeviceTTL
	}
	return defaultTrustedDeviceTTL
}

func (a *Auth) trustedDeviceCookieName() string {
	if a.cfg.SecureCookie {
		return "__Host-" + trustedDeviceCookieNm
	}
	return trustedDeviceCookieNm
}

// trustedDeviceValid reports whether the request carries a live trusted-device
// cookie for (tenantID, email), so the login can skip the TOTP step.
func (a *Auth) trustedDeviceValid(r *http.Request, tenantID, email string) bool {
	if a.cfg.TrustedDeviceStore == nil {
		return false
	}
	c, err := r.Cookie(a.trustedDeviceCookieName())
	if err != nil || c.Value == "" {
		return false
	}
	ok, err := a.cfg.TrustedDeviceStore.IsTrusted(WithTenant(r.Context(), tenantID), tenantID, email, c.Value)
	return err == nil && ok
}

// rememberDevice mints + sets a trusted-device cookie when the client asked to
// (the "trust this device" checkbox: a truthy `remember` form value) and a store
// is configured. Best-effort: a failure to remember never blocks the login.
func (a *Auth) rememberDevice(ctx context.Context, w http.ResponseWriter, r *http.Request, tenantID, email string) {
	if a.cfg.TrustedDeviceStore == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(r.FormValue("remember"))) {
	case "true", "on", "1", "yes":
	default:
		return
	}
	token, err := a.cfg.TrustedDeviceStore.Trust(ctx, tenantID, email, a.trustedDeviceTTL())
	if err != nil {
		a.log.Error("authkit: trust device: %v", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.trustedDeviceCookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(a.trustedDeviceTTL() / time.Second),
	})
}

// revokeTrustedDevices drops a user's trusted devices (nil-safe). Called wherever
// sessions are revoked: logout-everywhere, password change/reset, disable 2FA.
func (a *Auth) revokeTrustedDevices(ctx context.Context, tenantID, email string) {
	if a.cfg.TrustedDeviceStore == nil {
		return
	}
	if err := a.cfg.TrustedDeviceStore.RevokeAllForUser(ctx, tenantID, email); err != nil {
		a.log.Error("authkit: revoke trusted devices: %v", err)
	}
}

// clearTrustedDeviceCookie expires the trusted-device cookie on this browser.
func (a *Auth) clearTrustedDeviceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: a.trustedDeviceCookieName(), Value: "", Path: "/",
		HttpOnly: true, Secure: a.cfg.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}
