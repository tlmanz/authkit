package authkit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// memTOTPStore is an in-memory TOTPStore. A secret is pending until Confirm.
type memTOTPStore struct {
	secrets   map[string]string          // email -> secret
	confirmed map[string]bool            // email -> confirmed (activated)
	recovery  map[string]map[string]bool // email -> hash -> used
}

func newMemTOTP() *memTOTPStore {
	return &memTOTPStore{secrets: map[string]string{}, confirmed: map[string]bool{}, recovery: map[string]map[string]bool{}}
}

func (m *memTOTPStore) Enroll(_ context.Context, _, email, secret string, hashes []string) error {
	m.secrets[email] = secret
	m.confirmed[email] = false // pending until first verify confirms it
	m.recovery[email] = map[string]bool{}
	for _, h := range hashes {
		m.recovery[email][h] = false
	}
	return nil
}
func (m *memTOTPStore) Confirm(_ context.Context, _, email string) error {
	if _, ok := m.secrets[email]; ok {
		m.confirmed[email] = true
	}
	return nil
}
func (m *memTOTPStore) Secret(_ context.Context, _, email string) (string, bool, error) {
	return m.secrets[email], m.confirmed[email], nil
}
func (m *memTOTPStore) ConsumeRecovery(_ context.Context, _, email, hash string) (bool, error) {
	codes, ok := m.recovery[email]
	if !ok {
		return false, nil
	}
	used, exists := codes[hash]
	if !exists || used {
		return false, nil
	}
	codes[hash] = true
	return true, nil
}

// twoFAUserStore returns a fixed user (owner role, tenant t1).
type twoFAUserStore struct{}

func (twoFAUserStore) CreateUser(context.Context, string, string, string) error { return nil }
func (twoFAUserStore) UpdatePassword(context.Context, string, string) error     { return nil }
func (twoFAUserStore) GetUserByEmail(_ context.Context, email string) (*PasswordUser, error) {
	if email != "owner@shop.lk" {
		return nil, ErrUserNotFound
	}
	hash, _ := HashPassword("correct-horse")
	return &PasswordUser{Email: email, Name: "Owner", HashedPassword: hash, TenantID: "t1"}, nil
}

// fixedRolePolicy assigns everyone the "owner" role.
type fixedRolePolicy struct{}

func (fixedRolePolicy) RoleFor(context.Context, string) (string, []string) {
	return "owner", []string{"*"}
}
func (fixedRolePolicy) PermissionsForRole(context.Context, string) []string { return []string{"*"} }

func twoFAAuth(t *testing.T, store TOTPStore) *Auth {
	t.Helper()
	a, err := New(Config{
		Mode:               AuthModePassword,
		SessionSecret:      "0123456789abcdef0123456789abcdef",
		UserStore:          twoFAUserStore{},
		SessionStore:       newMemStore(),
		TOTPStore:          store,
		Require2FAForRoles: []string{"owner", "manager"},
		AppName:            "Klutch",
		RBAC:               RBACConfig{Provider: fixedRolePolicy{}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func doLogin(t *testing.T, a *Auth) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(url.Values{
		"email": {"owner@shop.lk"}, "password": {"correct-horse"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.1:1111"
	a.Login(rec, req)
	return rec
}

func TestLogin_RequiresEnrollThen2FA(t *testing.T) {
	store := newMemTOTP()
	a := twoFAAuth(t, store)

	// 1) Password login for an owner not yet enrolled → action "enroll", no session.
	rec := doLogin(t, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200", rec.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "2fa_required" || resp["action"] != "enroll" {
		t.Fatalf("login resp = %v, want 2fa_required/enroll", resp)
	}
	pendingCookie := findCookie(rec, a.twofaCookieName())
	if pendingCookie == nil {
		t.Fatal("no pending cookie issued")
	}
	// No session cookie yet.
	if findCookie(rec, a.sidCookieName()) != nil {
		t.Fatal("session minted before 2FA completed")
	}

	// 2) Enroll using the pending cookie.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/2fa/enroll", nil)
	req.AddCookie(pendingCookie)
	a.Enroll2FA(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll status = %d, want 200", rec.Code)
	}
	var enroll struct {
		Secret        string   `json:"secret"`
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &enroll)
	if enroll.Secret == "" || len(enroll.RecoveryCodes) != recoveryCodeCount {
		t.Fatalf("enroll resp missing secret/recovery: %+v", enroll)
	}

	// 3) Verify with a valid TOTP code → session minted.
	code, _ := totp.GenerateCode(enroll.Secret, time.Now())
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/auth/2fa/verify", strings.NewReader(url.Values{"code": {code}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(pendingCookie)
	req.RemoteAddr = "10.0.0.1:1111"
	a.Verify2FA(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("verify status = %d, want 303", rec.Code)
	}
	if findCookie(rec, a.sidCookieName()) == nil {
		t.Fatal("no session minted after successful 2FA")
	}
}

// TestLogin_PendingEnrollmentStaysEnroll pins the bug fix: starting enrollment
// (provisioning a secret) but never verifying must NOT flip the next login to the
// verify step — the user has no working authenticator and would be locked out.
// Re-login must keep returning "enroll" until a code confirms the secret.
func TestLogin_PendingEnrollmentStaysEnroll(t *testing.T) {
	store := newMemTOTP()
	a := twoFAAuth(t, store)

	action := func() string {
		rec := doLogin(t, a)
		var resp map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp["action"]
	}

	// First login: not enrolled → enroll.
	if got := action(); got != "enroll" {
		t.Fatalf("first login action = %q, want enroll", got)
	}

	// Provision a secret (open the QR) but DO NOT verify it.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/2fa/enroll", nil)
	req.AddCookie(findCookie(doLogin(t, a), a.twofaCookieName()))
	a.Enroll2FA(rec, req)
	var enroll struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &enroll)
	if enroll.Secret == "" {
		t.Fatal("enroll did not return a secret")
	}

	// Re-login after abandoning enrollment: must STILL be enroll (the bug returned
	// verify here, locking the user out).
	if got := action(); got != "enroll" {
		t.Fatalf("re-login after unconfirmed enroll = %q, want enroll", got)
	}

	// Verify with a real code → confirms the secret.
	code, _ := totp.GenerateCode(enroll.Secret, time.Now())
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/auth/2fa/verify", strings.NewReader(url.Values{"code": {code}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(findCookie(doLogin(t, a), a.twofaCookieName()))
	req.RemoteAddr = "10.0.0.1:1111"
	a.Verify2FA(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("verify status = %d, want 303", rec.Code)
	}

	// Now that 2FA is confirmed, login goes to verify.
	if got := action(); got != "verify" {
		t.Fatalf("login after confirmation = %q, want verify", got)
	}
}

func TestVerify2FA_WrongCodeRejected(t *testing.T) {
	store := newMemTOTP()
	a := twoFAAuth(t, store)
	// Pre-enroll the user.
	_ = store.Enroll(context.Background(), "t1", "owner@shop.lk", "JBSWY3DPEHPK3PXP", nil)

	rec := doLogin(t, a)
	pending := findCookie(rec, a.twofaCookieName())

	rec = httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/2fa/verify", strings.NewReader(url.Values{"code": {"000000"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(pending)
	req.RemoteAddr = "10.0.0.1:1111"
	a.Verify2FA(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code status = %d, want 401", rec.Code)
	}
}

func TestVerify2FA_RecoveryCodeSingleUse(t *testing.T) {
	store := newMemTOTP()
	a := twoFAAuth(t, store)
	plain, hashes, _ := generateRecoveryCodes(3)
	_ = store.Enroll(context.Background(), "t1", "owner@shop.lk", "JBSWY3DPEHPK3PXP", hashes)

	use := func() int {
		rec := doLogin(t, a)
		pending := findCookie(rec, a.twofaCookieName())
		rec = httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/auth/2fa/verify", strings.NewReader(url.Values{"recovery_code": {plain[0]}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(pending)
		req.RemoteAddr = "10.0.0.1:1111"
		a.Verify2FA(rec, req)
		return rec.Code
	}

	if c := use(); c != http.StatusSeeOther {
		t.Fatalf("first recovery use = %d, want 303", c)
	}
	if c := use(); c != http.StatusUnauthorized {
		t.Fatalf("second recovery use = %d, want 401 (single-use)", c)
	}
}

func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
