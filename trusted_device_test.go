package authkit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The browser half of "remember this device": one cookie that must remember
// every account that ticked the box on it, not just the last one.

// rememberOn runs the remember step for email on a browser currently holding
// cookie (nil for none) and returns the cookie the browser holds afterwards.
func rememberOn(t *testing.T, a *Auth, cookie *http.Cookie, email string) *http.Cookie {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", strings.NewReader("remember=true"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.rememberDevice(r.Context(), w, r, "t1", email)
	for _, c := range w.Result().Cookies() {
		if c.Name == a.trustedDeviceCookieName() {
			return c
		}
	}
	t.Fatalf("remembering %s set no trusted-device cookie", email)
	return nil
}

// loginRequest is a login carrying cookie, as the next sign-in would.
func loginRequest(cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

// countingTrusted counts the store lookups a login makes.
type countingTrusted struct {
	*memTrusted
	lookups int
}

func (c *countingTrusted) IsTrusted(ctx context.Context, tenantID, email, token string) (bool, error) {
	c.lookups++
	return c.memTrusted.IsTrusted(ctx, tenantID, email, token)
}

// failingTrusted cannot answer whether a token is trusted.
type failingTrusted struct{ *memTrusted }

func (failingTrusted) IsTrusted(context.Context, string, string, string) (bool, error) {
	return false, errors.New("store unavailable")
}

func TestTrustedDevice_EveryAccountOnABrowserStaysTrusted(t *testing.T) {
	a := passwordTokenAuth(t, nil, false, newMemTrusted())

	var c *http.Cookie
	for _, email := range []string{"owner@shop.lk", "manager@shop.lk", "admin@klutch.lk"} {
		c = rememberOn(t, a, c, email)
	}
	for _, email := range []string{"owner@shop.lk", "manager@shop.lk", "admin@klutch.lk"} {
		if !a.trustedDeviceValid(loginRequest(c), "t1", email) {
			t.Errorf("%s lost their trust when another account remembered the browser", email)
		}
	}
	if a.trustedDeviceValid(loginRequest(c), "t1", "stranger@shop.lk") {
		t.Error("an account that never ticked remember is trusted")
	}
}

func TestTrustedDevice_RememberingAgainReplacesThatAccountsToken(t *testing.T) {
	a := passwordTokenAuth(t, nil, false, newMemTrusted())

	c := rememberOn(t, a, nil, "owner@shop.lk")
	c = rememberOn(t, a, c, "manager@shop.lk")
	c = rememberOn(t, a, c, "owner@shop.lk")

	if got := a.trustedEntries(loginRequest(c)); len(got) != 2 {
		t.Fatalf("cookie holds %d entries, want 2 (one per account): %v", len(got), got)
	}
}

// A browser remembered before the cookie held a list carries one raw token.
func TestTrustedDevice_SingleTokenCookieStillWorks(t *testing.T) {
	store := newMemTrusted()
	a := passwordTokenAuth(t, nil, false, store)
	token, _ := store.Trust(t.Context(), "t1", "owner@shop.lk", 0)

	old := &http.Cookie{Name: a.trustedDeviceCookieName(), Value: token}
	if !a.trustedDeviceValid(loginRequest(old), "t1", "owner@shop.lk") {
		t.Fatal("a browser remembered under the single-token cookie is no longer trusted")
	}
	c := rememberOn(t, a, old, "manager@shop.lk")
	for _, email := range []string{"owner@shop.lk", "manager@shop.lk"} {
		if !a.trustedDeviceValid(loginRequest(c), "t1", email) {
			t.Errorf("%s not trusted after upgrading a single-token cookie", email)
		}
	}
}

// There is no cap on accounts, but a cookie the browser would drop forgets all of
// them, so the oldest give way only once the cookie would not fit.
func TestTrustedDevice_CookieStaysWithinWhatBrowsersKeep(t *testing.T) {
	a := passwordTokenAuth(t, nil, false, newMemTrusted())

	var c *http.Cookie
	for i := range 200 {
		c = rememberOn(t, a, c, "staff"+strconv.Itoa(i)+"@shop.lk")
	}
	if len(c.Value) > maxTrustedCookieValue {
		t.Fatalf("cookie value is %d bytes, over the %d a browser keeps", len(c.Value), maxTrustedCookieValue)
	}
	if !a.trustedDeviceValid(loginRequest(c), "t1", "staff199@shop.lk") {
		t.Error("the newest account was dropped to make room")
	}
	if a.trustedDeviceValid(loginRequest(c), "t1", "staff0@shop.lk") {
		t.Error("the oldest account should give way once the cookie is full")
	}
	if n := len(a.trustedEntries(loginRequest(c))); n < 20 {
		t.Errorf("only %d accounts fit; the limit should be the cookie size, not a small count", n)
	}
}

// A sign-in asks the store about its own entry, however many accounts the
// browser remembers: the cookie comes from the client, so its length must not
// set the number of store round-trips.
func TestTrustedDevice_LoginLooksUpOnlyItsOwnEntry(t *testing.T) {
	store := &countingTrusted{memTrusted: newMemTrusted()}
	a := passwordTokenAuth(t, nil, false, store)

	var c *http.Cookie
	for i := range 30 {
		c = rememberOn(t, a, c, "staff"+strconv.Itoa(i)+"@shop.lk")
	}

	store.lookups = 0
	if !a.trustedDeviceValid(loginRequest(c), "t1", "staff7@shop.lk") {
		t.Fatal("a remembered account is not trusted")
	}
	if store.lookups != 1 {
		t.Errorf("trusting one account took %d store lookups, want 1", store.lookups)
	}

	store.lookups = 0
	if a.trustedDeviceValid(loginRequest(c), "t1", "stranger@shop.lk") {
		t.Fatal("an account that never ticked remember is trusted")
	}
	if store.lookups != 0 {
		t.Errorf("an account with no entry took %d store lookups, want 0", store.lookups)
	}
}

// A cookie larger than any this package writes was not issued here.
func TestTrustedDevice_OversizedCookieIsIgnored(t *testing.T) {
	store := &countingTrusted{memTrusted: newMemTrusted()}
	a := passwordTokenAuth(t, nil, false, store)

	huge := &http.Cookie{Name: a.trustedDeviceCookieName(), Value: strings.Repeat("A", maxTrustedCookieValue+1)}
	if a.trustedDeviceValid(loginRequest(huge), "t1", "owner@shop.lk") || store.lookups != 0 {
		t.Fatalf("an oversized cookie was read (%d store lookups)", store.lookups)
	}
}

// "Log out everywhere" forgets this user's trust and nobody else's, and a store
// that cannot answer must not keep the user's own token on the browser.
func TestTrustedDevice_EntriesExceptDropsItsOwnEvenWhenTheStoreFails(t *testing.T) {
	a := passwordTokenAuth(t, nil, false, newMemTrusted())
	c := rememberOn(t, a, nil, "owner@shop.lk")
	c = rememberOn(t, a, c, "manager@shop.lk")

	broken := passwordTokenAuth(t, nil, false, failingTrusted{newMemTrusted()})
	r := loginRequest(c)
	keep := broken.trustedEntriesExcept(r.Context(), r, "t1", "owner@shop.lk")
	if len(keep) != 1 || keep[0].token != "trusted-manager@shop.lk" {
		t.Fatalf("kept %v, want only the manager's entry", keep)
	}

	// An unlabelled v2.0.0 token may be the owner's; unable to ask, drop it.
	old := &http.Cookie{Name: a.trustedDeviceCookieName(), Value: "trusted-owner@shop.lk"}
	r = loginRequest(old)
	if keep := broken.trustedEntriesExcept(r.Context(), r, "t1", "owner@shop.lk"); len(keep) != 0 {
		t.Fatalf("kept %v; an unlabelled token the store could not vouch for must go", keep)
	}
}

// The label is keyed on the session secret, so it means nothing to another
// deployment and cannot be minted for someone else's account.
func TestTrustedDevice_AccountKeyDependsOnTheSecret(t *testing.T) {
	a := passwordTokenAuth(t, nil, false, newMemTrusted())
	if a.trustedAccountKey("t1", "owner@shop.lk") == a.trustedAccountKey("t1", "manager@shop.lk") {
		t.Fatal("two accounts share a label")
	}
	b, err := New(Config{
		Mode: AuthModePassword, SessionSecret: "fedcba9876543210fedcba9876543210",
		UserStore: twoFAUserStore{}, Sessions: SessionConfig{Store: newMemStore()},
		AppName: "Example", RBAC: RBACConfig{Provider: fixedRolePolicy{}},
		TwoFactor: TwoFactorConfig{TrustedDeviceTTL: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.trustedAccountKey("t1", "owner@shop.lk") == b.trustedAccountKey("t1", "owner@shop.lk") {
		t.Fatal("the label does not depend on the session secret")
	}
}
