package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// 2FA a user turned on themselves, from an account page, for a role that does
// not mandate it. Turning it on has to mean being asked for a code at sign-in;
// before this, only RequireForRoles was consulted and the setting protected
// nothing.

// voluntaryAuth is an Auth where the owner role (fixedRolePolicy) does NOT
// require 2FA unless requireRoles says so, so by default any challenge comes
// from the user's own enrollment.
func voluntaryAuth(t *testing.T, store TOTPStore, trusted TrustedDeviceStore, requireRoles ...string) *Auth {
	t.Helper()
	a, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "0123456789abcdef0123456789abcdef",
		UserStore:     twoFAUserStore{},
		Sessions:      SessionConfig{Store: newMemStore()},
		TwoFactor:     TwoFactorConfig{Store: store, TrustedDevices: trusted, RequireForRoles: requireRoles},
		AppName:       "Example",
		RBAC:          RBACConfig{Provider: fixedRolePolicy{}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// enrolled is a TOTP store holding the owner's secret, confirmed or still pending.
func enrolled(t *testing.T, confirmed bool) *memTOTPStore {
	t.Helper()
	store := newMemTOTP()
	if err := store.Enroll(t.Context(), "t1", "owner@shop.lk", "JBSWY3DPEHPK3PXP", nil); err != nil {
		t.Fatal(err)
	}
	if confirmed {
		if err := store.Confirm(t.Context(), "t1", "owner@shop.lk"); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

// brokenTOTP fails every secret lookup.
type brokenTOTP struct{ *memTOTPStore }

func (brokenTOTP) Secret(context.Context, string, string) (string, bool, error) {
	return "", false, errors.New("store unavailable")
}

// jsonHas reports whether body is a JSON object whose key holds want.
func jsonHas(body []byte, key, want string) bool {
	var m map[string]any
	return json.Unmarshal(body, &m) == nil && m[key] == want
}

// doLoginWithCookie is doLogin from a browser carrying cookie.
func doLoginWithCookie(t *testing.T, a *Auth, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(url.Values{
		"email": {"owner@shop.lk"}, "password": {"correct-horse"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.1:1111"
	req.AddCookie(cookie)
	a.Login(rec, req)
	return rec
}

func TestLogin_Voluntary2FAIsChallenged(t *testing.T) {
	a := voluntaryAuth(t, enrolled(t, true), nil)

	rec := doLogin(t, a)
	if rec.Code != http.StatusOK || !jsonHas(rec.Body.Bytes(), "status", "2fa_required") ||
		!jsonHas(rec.Body.Bytes(), "action", "verify") {
		t.Fatalf("login = %d %s, want a 2fa_required/verify challenge", rec.Code, rec.Body)
	}
	if findCookie(rec, a.sidCookieName()) != nil {
		t.Fatal("a session was minted without the code the user turned on")
	}
}

// Provisioning a secret and never confirming it leaves nothing that can produce
// a code, so it must not lock the user out.
func TestLogin_AbandonedVoluntaryEnrollmentIsNotChallenged(t *testing.T) {
	a := voluntaryAuth(t, enrolled(t, false), nil)

	if rec := doLogin(t, a); rec.Code != http.StatusSeeOther {
		t.Fatalf("login = %d %s, want a session (303)", rec.Code, rec.Body)
	}
}

func TestLogin_NoVoluntary2FAIsNotChallenged(t *testing.T) {
	a := voluntaryAuth(t, newMemTOTP(), nil)

	if rec := doLogin(t, a); rec.Code != http.StatusSeeOther {
		t.Fatalf("login = %d %s, want a session (303)", rec.Code, rec.Body)
	}
}

// If the store cannot say whether 2FA is on, the login must not guess "off".
func TestLogin_Voluntary2FALookupFailureFailsClosed(t *testing.T) {
	a := voluntaryAuth(t, brokenTOTP{newMemTOTP()}, nil)

	rec := doLogin(t, a)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("login = %d %s, want 500", rec.Code, rec.Body)
	}
	if findCookie(rec, a.sidCookieName()) != nil {
		t.Fatal("a session was minted while the 2FA state was unknown")
	}
}

func TestLogin_Voluntary2FAHonoursARememberedDevice(t *testing.T) {
	a := voluntaryAuth(t, enrolled(t, true), newMemTrusted())
	trusted := rememberOn(t, a, nil, "owner@shop.lk")

	rec := doLoginWithCookie(t, a, trusted)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login from a remembered device = %d %s, want a session (303)", rec.Code, rec.Body)
	}
}

// The role requires 2FA and this browser remembers the user, but their
// authenticator was reset (by an admin, say): they must set up a new one, not
// walk straight in on the strength of the old trust.
func TestLogin_RememberedDeviceDoesNotSkipReEnrollment(t *testing.T) {
	a := voluntaryAuth(t, newMemTOTP(), newMemTrusted(), "owner")
	trusted := rememberOn(t, a, nil, "owner@shop.lk")

	rec := doLoginWithCookie(t, a, trusted)
	if rec.Code != http.StatusOK || !jsonHas(rec.Body.Bytes(), "action", "enroll") {
		t.Fatalf("login after a 2FA reset = %d %s, want a 2fa_required/enroll challenge", rec.Code, rec.Body)
	}
}

func TestIssuePasswordToken_RememberedDeviceDoesNotSkipReEnrollment(t *testing.T) {
	trusted := newMemTrusted()
	a := passwordTokenAuth(t, newMemTOTP(), true, trusted)
	token, _ := trusted.Trust(t.Context(), "t1", "owner@shop.lk", time.Hour)

	rec, body := postTokenForm(t, a.IssuePasswordToken, "/oauth/token/password", url.Values{
		"email": {"owner@shop.lk"}, "password": {"correct-horse"}, "trusted_device_token": {token},
	})
	if rec.Code != http.StatusOK || body["action"] != "enroll" {
		t.Fatalf("native login after a 2FA reset = %d %v, want a 2fa_required/enroll challenge", rec.Code, body)
	}
}

// managedTOTP adds the account-page operations to memTOTPStore.
type managedTOTP struct{ *memTOTPStore }

func (m managedTOTP) Disable(_ context.Context, _, email string) error {
	delete(m.secrets, email)
	delete(m.confirmed, email)
	delete(m.recovery, email)
	return nil
}
func (managedTOTP) ReplaceRecoveryCodes(context.Context, string, string, []string) error { return nil }

// signedIn returns a session cookie for the owner, as an account page has.
func signedIn(t *testing.T, a *Auth) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	u := &User{Email: "owner@shop.lk", Name: "Owner", Provider: "password", Role: "owner", TenantID: "t1"}
	if err := a.EstablishSession(WithTenant(req.Context(), "t1"), rec, req, u); err != nil {
		t.Fatal(err)
	}
	c := findCookie(rec, a.sidCookieName())
	if c == nil {
		t.Fatal("no session cookie")
	}
	return c
}

func disable2FA(a *Auth, session *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/2fa/disable", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	a.DisableTwoFactor(rec, req)
	return rec
}

// Now that sign-in enforces 2FA a user turned on, a session alone (an unlocked
// till, a stolen cookie) must not be able to turn it off.
func TestDisableTwoFactor_TakesTheSecondFactor(t *testing.T) {
	store := managedTOTP{newMemTOTP()}
	if err := store.Enroll(t.Context(), "t1", "owner@shop.lk", "JBSWY3DPEHPK3PXP",
		[]string{hashRecoveryCode("RECOVERY-1")}); err != nil {
		t.Fatal(err)
	}
	_ = store.Confirm(t.Context(), "t1", "owner@shop.lk")
	a := voluntaryAuth(t, store, nil)
	session := signedIn(t, a)

	for _, form := range []url.Values{{}, {"code": {"123"}}, {"recovery_code": {"WRONG"}}} {
		if rec := disable2FA(a, session, form); rec.Code != http.StatusBadRequest {
			t.Fatalf("disable with %v = %d %s, want 400", form, rec.Code, rec.Body)
		}
	}
	if _, confirmed, _ := store.Secret(t.Context(), "t1", "owner@shop.lk"); !confirmed {
		t.Fatal("2FA was turned off without the second factor")
	}

	if rec := disable2FA(a, session, url.Values{"recovery_code": {"RECOVERY-1"}}); rec.Code != http.StatusOK {
		t.Fatalf("disable with a recovery code = %d %s, want 200", rec.Code, rec.Body)
	}
	if _, confirmed, _ := store.Secret(t.Context(), "t1", "owner@shop.lk"); confirmed {
		t.Fatal("2FA is still on after a valid disable")
	}
}

// managedOwner is a managedTOTP holding the owner's confirmed secret and one
// recovery code, RECOVERY-1.
func managedOwner(t *testing.T) managedTOTP {
	t.Helper()
	store := managedTOTP{newMemTOTP()}
	if err := store.Enroll(t.Context(), "t1", "owner@shop.lk", "JBSWY3DPEHPK3PXP",
		[]string{hashRecoveryCode("RECOVERY-1")}); err != nil {
		t.Fatal(err)
	}
	_ = store.Confirm(t.Context(), "t1", "owner@shop.lk")
	return store
}

// Fresh recovery codes pass sign-in and turn 2FA off, so handing them to a
// session alone would undo both protections.
func TestRegenerateRecoveryCodes_TakesTheSecondFactor(t *testing.T) {
	a := voluntaryAuth(t, managedOwner(t), nil)
	session := signedIn(t, a)

	regen := func(form url.Values) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/auth/2fa/recovery/regenerate", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(session)
		a.RegenerateRecoveryCodes(rec, req)
		return rec
	}
	if rec := regen(url.Values{}); rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "recoveryCodes") {
		t.Fatalf("regenerate without a code = %d %s, want 400 and no codes", rec.Code, rec.Body)
	}
	if rec := regen(url.Values{"recovery_code": {"RECOVERY-1"}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "recoveryCodes") {
		t.Fatalf("regenerate with a recovery code = %d %s, want 200 with codes", rec.Code, rec.Body)
	}
}

// Six digits are a million guesses; a stolen session must not get to make them.
func TestDisableTwoFactor_WrongCodesAreThrottled(t *testing.T) {
	store := managedOwner(t)
	a, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "0123456789abcdef0123456789abcdef",
		UserStore:     twoFAUserStore{},
		Sessions:      SessionConfig{Store: newMemStore()},
		TwoFactor:     TwoFactorConfig{Store: store},
		Throttler:     newMemThrottler(3, time.Hour),
		AppName:       "Example",
		RBAC:          RBACConfig{Provider: fixedRolePolicy{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	session := signedIn(t, a)

	for range 3 {
		disable2FA(a, session, url.Values{"code": {"123"}})
	}
	rec := disable2FA(a, session, url.Values{"recovery_code": {"RECOVERY-1"}})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("disable after repeated wrong codes = %d %s, want 429", rec.Code, rec.Body)
	}
	if _, confirmed, _ := store.Secret(t.Context(), "t1", "owner@shop.lk"); !confirmed {
		t.Fatal("2FA was turned off while locked out")
	}
}

func TestIssuePasswordToken_Voluntary2FAIsChallenged(t *testing.T) {
	a := passwordTokenAuth(t, enrolled(t, true), false, nil)

	rec, body := postTokenForm(t, a.IssuePasswordToken, "/oauth/token/password", url.Values{
		"email": {"owner@shop.lk"}, "password": {"correct-horse"},
	})
	if rec.Code != http.StatusOK || body["status"] != "2fa_required" || body["action"] != "verify" {
		t.Fatalf("native login = %d %v, want a 2fa_required/verify challenge", rec.Code, body)
	}
	if _, ok := body["access_token"]; ok {
		t.Fatal("tokens were issued without the code the user turned on")
	}
}
