package authkit

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// defaultTrustedDeviceTTL is how long a remembered device skips 2FA when
// TwoFactor.TrustedDeviceTTL is unset.
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
	if a.cfg.TwoFactor.TrustedDeviceTTL > 0 {
		return a.cfg.TwoFactor.TrustedDeviceTTL
	}
	return defaultTrustedDeviceTTL
}

func (a *Auth) trustedDeviceCookieName() string { return a.cookieName("trusted") }

// trustedDeviceValid reports whether the request carries a live trusted-device
// cookie for (tenantID, email), so the login can skip the TOTP step.
func (a *Auth) trustedDeviceValid(r *http.Request, tenantID, email string) bool {
	if a.cfg.TwoFactor.TrustedDevices == nil {
		return false
	}
	c, err := r.Cookie(a.trustedDeviceCookieName())
	if err != nil || c.Value == "" {
		return false
	}
	ok, err := a.cfg.TwoFactor.TrustedDevices.IsTrusted(WithTenant(r.Context(), tenantID), tenantID, email, c.Value)
	return err == nil && ok
}

// trustedDeviceTokenValid is the cookie-free variant used by the native token
// flow: the client presents the opaque trusted-device token in the request body
// instead of a cookie. Reports whether it is a live trust for (tenantID, email).
func (a *Auth) trustedDeviceTokenValid(ctx context.Context, tenantID, email, token string) bool {
	if a.cfg.TwoFactor.TrustedDevices == nil || token == "" {
		return false
	}
	ok, err := a.cfg.TwoFactor.TrustedDevices.IsTrusted(WithTenant(ctx, tenantID), tenantID, email, token)
	return err == nil && ok
}

// mintTrustedDeviceToken records a trusted device and returns the opaque token
// for the native client to store (secure storage) and present on next login.
// Best-effort: an error yields an empty token and never blocks the login.
func (a *Auth) mintTrustedDeviceToken(ctx context.Context, tenantID, email string) string {
	if a.cfg.TwoFactor.TrustedDevices == nil {
		return ""
	}
	token, err := a.cfg.TwoFactor.TrustedDevices.Trust(ctx, tenantID, email, a.trustedDeviceTTL())
	if err != nil {
		a.log.Error("trust device (native) failed", "err", err)
		return ""
	}
	return token
}

// formTrue reports whether a request value is a truthy flag.
func formTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "on", "1", "yes":
		return true
	default:
		return false
	}
}

// rememberDevice mints + sets a trusted-device cookie when the client asked to
// (the "trust this device" checkbox: a truthy `remember` value) and a store
// is configured. Best-effort: a failure to remember never blocks the login.
func (a *Auth) rememberDevice(ctx context.Context, w http.ResponseWriter, r *http.Request, tenantID, email string) {
	if a.cfg.TwoFactor.TrustedDevices == nil {
		return
	}
	if !formTrue(r.FormValue("remember")) {
		return
	}
	token, err := a.cfg.TwoFactor.TrustedDevices.Trust(ctx, tenantID, email, a.trustedDeviceTTL())
	if err != nil {
		a.log.Error("trust device failed", "err", err)
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
	if a.cfg.TwoFactor.TrustedDevices == nil {
		return
	}
	if err := a.cfg.TwoFactor.TrustedDevices.RevokeAllForUser(ctx, tenantID, email); err != nil {
		a.log.Error("revoke trusted devices failed", "err", err)
	}
}

// clearTrustedDeviceCookie expires the trusted-device cookie on this browser.
func (a *Auth) clearTrustedDeviceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: a.trustedDeviceCookieName(), Value: "", Path: "/",
		HttpOnly: true, Secure: a.cfg.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}
