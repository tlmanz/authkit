package authkit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

// The trusted-device cookie holds one entry per remembered account, because a
// shared counter PC is normal: several people who must pass 2FA each tick
// "remember", and one of them doing so must not make the browser forget the
// others (a single-token cookie did exactly that). There is no cap on how many
// accounts a browser remembers.
//
// maxTrustedCookieValue is not such a cap; it is the browser's. A cookie over
// ~4096 bytes (name, value and attributes together) is silently dropped, which
// would forget EVERY remembered account at once. Only when the value would not
// fit are entries dropped, oldest first. At ~80 bytes per encoded entry that is
// around fifty accounts on one browser. A cookie longer than this was never
// issued here, and is ignored rather than spent on store lookups.
const maxTrustedCookieValue = 3800

// trustedEntry is one remembered account in the trusted-device cookie: the
// store's opaque token, labelled with trustedAccountKey for the account it
// belongs to. The label is what lets a login look up its own token only, and
// lets "log out everywhere" drop its own without asking the store. An empty
// account marks the single raw token a v2.0.0 cookie held, whose owner is
// unknown.
type trustedEntry struct{ account, token string }

// trustedAccountKey labels (tenantID, email) in the cookie. It is an HMAC under
// the session secret, so the cookie names nobody and a label cannot be made for
// someone else's account. Twelve characters (72 bits) keeps a browser's
// accounts apart. base64url never contains '.', the entry separator.
func (a *Auth) trustedAccountKey(tenantID, email string) string {
	// Length-prefixed: '|' is legal in an email, so a bare join would let two
	// different (tenant, email) pairs share a label.
	return a.sign(fmt.Sprintf("trusted|%d|%s|%s", len(tenantID), tenantID, email))[:12]
}

// trustedEntries returns the entries this browser's cookie holds, newest first.
// The cookie carries base64url(JSON array of "account.token"). A v2.0.0 cookie
// carries one raw token, read as a single unlabelled entry so browsers
// remembered before the upgrade keep working.
func (a *Auth) trustedEntries(r *http.Request) []trustedEntry {
	c, err := r.Cookie(a.trustedDeviceCookieName())
	if err != nil || c.Value == "" || len(c.Value) > maxTrustedCookieValue {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	var list []string
	if err != nil || json.Unmarshal(raw, &list) != nil {
		return []trustedEntry{{token: c.Value}}
	}
	entries := make([]trustedEntry, 0, len(list))
	for _, s := range list {
		if account, token, ok := strings.Cut(s, "."); ok && token != "" {
			entries = append(entries, trustedEntry{account: account, token: token})
		}
	}
	return entries
}

// encodeTrustedEntries encodes entries (newest first) as the cookie value,
// keeping as many of the newest as fit in maxTrustedCookieValue. The JSON
// wrapping keeps any token a store issues safe, whatever characters it uses.
func encodeTrustedEntries(entries []trustedEntry) string {
	list := make([]string, 0, len(entries))
	jsonLen := 1 // the opening '['; each item then adds its own length + ',' or ']'
	for _, e := range entries {
		item := e.account + "." + e.token
		quoted, _ := json.Marshal(item)
		if base64.RawURLEncoding.EncodedLen(jsonLen+len(quoted)+1) > maxTrustedCookieValue {
			break
		}
		list = append(list, item)
		jsonLen += len(quoted) + 1
	}
	if len(list) == 0 {
		return ""
	}
	raw, _ := json.Marshal(list)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// setTrustedEntries writes entries as this browser's trusted-device cookie, or
// expires the cookie when none are left.
func (a *Auth) setTrustedEntries(w http.ResponseWriter, entries []trustedEntry) {
	value := encodeTrustedEntries(entries)
	if value == "" {
		a.clearTrustedDeviceCookie(w)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.trustedDeviceCookieName(),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(a.trustedDeviceTTL() / time.Second),
	})
}

// tokenTrustedFor reports whether token is a live trust for (tenantID, email).
func (a *Auth) tokenTrustedFor(ctx context.Context, tenantID, email, token string) bool {
	ok, err := a.cfg.TwoFactor.TrustedDevices.IsTrusted(WithTenant(ctx, tenantID), tenantID, email, token)
	return err == nil && ok
}

// trustedDeviceValid reports whether the request carries a live trusted-device
// token for (tenantID, email), so the login can skip the TOTP step. It asks the
// store about at most two tokens, the account's own entry and an unlabelled
// v2.0.0 one, however many other accounts the cookie holds.
func (a *Auth) trustedDeviceValid(r *http.Request, tenantID, email string) bool {
	if a.cfg.TwoFactor.TrustedDevices == nil {
		return false
	}
	key := a.trustedAccountKey(tenantID, email)
	var own, legacy string
	for _, e := range a.trustedEntries(r) {
		switch {
		case e.account == key && own == "":
			own = e.token
		case e.account == "" && legacy == "":
			legacy = e.token
		}
	}
	for _, token := range []string{own, legacy} {
		if token != "" && a.tokenTrustedFor(r.Context(), tenantID, email, token) {
			return true
		}
	}
	return false
}

// trustedEntriesExcept returns this browser's entries that do NOT belong to
// (tenantID, email). The account's own entries are dropped by label, live or
// not, so a stale token of its own never lingers. An unlabelled v2.0.0 entry
// can only be told apart by asking the store, so call this before revoking the
// account's trust; it is kept only when the store says it is someone else's, and
// an error drops it, since it may be this account's.
func (a *Auth) trustedEntriesExcept(ctx context.Context, r *http.Request, tenantID, email string) []trustedEntry {
	if a.cfg.TwoFactor.TrustedDevices == nil {
		return nil
	}
	key := a.trustedAccountKey(tenantID, email)
	var keep []trustedEntry
	seenLegacy := false
	for _, e := range a.trustedEntries(r) {
		switch {
		case e.account == key:
		case e.account == "":
			if seenLegacy {
				continue // a v2.0.0 cookie held one; more were never issued
			}
			seenLegacy = true
			ok, err := a.cfg.TwoFactor.TrustedDevices.IsTrusted(WithTenant(ctx, tenantID), tenantID, email, e.token)
			if err == nil && !ok {
				keep = append(keep, e)
			}
		default:
			keep = append(keep, e)
		}
	}
	return keep
}

// trustedDeviceTokenValid is the cookie-free variant used by the native token
// flow: the client presents the opaque trusted-device token in the request body
// instead of a cookie. Reports whether it is a live trust for (tenantID, email).
func (a *Auth) trustedDeviceTokenValid(ctx context.Context, tenantID, email, token string) bool {
	return a.cfg.TwoFactor.TrustedDevices != nil && token != "" && a.tokenTrustedFor(ctx, tenantID, email, token)
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

// rememberDevice mints a trusted-device token when the client asked to (the
// "trust this device" checkbox: a truthy `remember` value) and a store is
// configured, and adds it to this browser's cookie. Any earlier entry of the
// same account leaves the cookie (its token stays valid in the store until it
// expires, but only this browser ever held it); other accounts' entries are
// kept. Best-effort: a failure to remember never blocks the login.
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
	own := trustedEntry{account: a.trustedAccountKey(tenantID, email), token: token}
	a.setTrustedEntries(w, append([]trustedEntry{own}, a.trustedEntriesExcept(ctx, r, tenantID, email)...))
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
