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

// memTrusted is an in-memory TrustedDeviceStore (token -> email).
type memTrusted struct{ tokens map[string]string }

func newMemTrusted() *memTrusted { return &memTrusted{tokens: map[string]string{}} }

func (m *memTrusted) Trust(_ context.Context, _, email string, _ time.Duration) (string, error) {
	tok := "trusted-" + email
	m.tokens[tok] = email
	return tok, nil
}
func (m *memTrusted) IsTrusted(_ context.Context, _, email, token string) (bool, error) {
	return token != "" && m.tokens[token] == email, nil
}
func (m *memTrusted) RevokeAllForUser(_ context.Context, _, email string) error {
	for k, v := range m.tokens {
		if v == email {
			delete(m.tokens, k)
		}
	}
	return nil
}

// passwordTokenAuth builds an Auth with the token layer and (optionally) TOTP +
// a trusted-device store, so the mobile password/2FA endpoints can be exercised.
func passwordTokenAuth(t *testing.T, totpStore TOTPStore, require2FA bool, trusted TrustedDeviceStore) *Auth {
	t.Helper()
	cfg := Config{
		Mode:          AuthModePassword,
		SessionSecret: "0123456789abcdef0123456789abcdef",
		UserStore:     twoFAUserStore{}, // owner@shop.lk / correct-horse, tenant t1
		RBAC:          RBACConfig{Provider: fixedRolePolicy{}},
		Sessions:      SessionConfig{Store: newMemStore()},
		Tokens: TokenConfig{
			Enable:       true,
			SigningKeys:  testSigningKeys(t, "k1"),
			RefreshStore: newMemRefresh(),
			AccessTTL:    15 * time.Minute,
			RefreshTTL:   24 * time.Hour,
			Issuer:       "https://app.example.com",
			ClientID:     "example-mobile",
			RedirectURIs: []string{"com.example.app://oauth/callback"},
		},
		AppName: "Example",
	}
	if totpStore != nil {
		cfg.TwoFactor.Store = totpStore
	}
	if require2FA {
		cfg.TwoFactor.RequireForRoles = []string{"owner", "manager"}
	}
	if trusted != nil {
		cfg.TwoFactor.TrustedDevices = trusted
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func postTokenForm(t *testing.T, h http.HandlerFunc, path string, form url.Values) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.1:1111"
	rec := httptest.NewRecorder()
	h(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func TestIssuePasswordToken_Success(t *testing.T) {
	a := passwordTokenAuth(t, nil, false, nil)
	rec, body := postTokenForm(t, a.IssuePasswordToken, "/oauth/token/password",
		url.Values{"email": {"owner@shop.lk"}, "password": {"correct-horse"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Fatalf("missing access_token: %v", body)
	}
	if body["refresh_token"] == nil {
		t.Fatalf("missing refresh_token: %v", body)
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v, want Bearer", body["token_type"])
	}
}

func TestIssuePasswordToken_BadPassword(t *testing.T) {
	a := passwordTokenAuth(t, nil, false, nil)
	rec, body := postTokenForm(t, a.IssuePasswordToken, "/oauth/token/password",
		url.Values{"email": {"owner@shop.lk"}, "password": {"wrong"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if body["error"] != "invalid_grant" {
		t.Fatalf("error = %v, want invalid_grant", body["error"])
	}
}

func TestIssuePasswordToken_2FAFlow(t *testing.T) {
	store := newMemTOTP()
	a := passwordTokenAuth(t, store, true, nil)

	const secret = "JBSWY3DPEHPK3PXP"
	_ = store.Enroll(context.Background(), "t1", "owner@shop.lk", secret, nil)
	_ = store.Confirm(context.Background(), "t1", "owner@shop.lk") // already set up → verify

	// Step 1: password → 2fa_required + pending_token (no tokens yet).
	rec, body := postTokenForm(t, a.IssuePasswordToken, "/oauth/token/password",
		url.Values{"email": {"owner@shop.lk"}, "password": {"correct-horse"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("step1 status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if body["status"] != "2fa_required" || body["action"] != "verify" {
		t.Fatalf("step1 body = %v, want 2fa_required/verify", body)
	}
	pending, _ := body["pending_token"].(string)
	if pending == "" {
		t.Fatalf("missing pending_token: %v", body)
	}
	if body["access_token"] != nil {
		t.Fatalf("step1 must not issue tokens before 2fa: %v", body)
	}

	// Step 2: valid TOTP code + pending token → tokens.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	rec, body = postTokenForm(t, a.IssuePasswordToken2FA, "/oauth/token/2fa",
		url.Values{"pending_token": {pending}, "code": {code}})
	if rec.Code != http.StatusOK {
		t.Fatalf("step2 status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if body["access_token"] == nil || body["refresh_token"] == nil {
		t.Fatalf("step2 missing tokens: %v", body)
	}
}

func TestIssuePasswordToken2FA_BadCode(t *testing.T) {
	store := newMemTOTP()
	a := passwordTokenAuth(t, store, true, nil)
	_ = store.Enroll(context.Background(), "t1", "owner@shop.lk", "JBSWY3DPEHPK3PXP", nil)
	_ = store.Confirm(context.Background(), "t1", "owner@shop.lk")

	_, body := postTokenForm(t, a.IssuePasswordToken, "/oauth/token/password",
		url.Values{"email": {"owner@shop.lk"}, "password": {"correct-horse"}})
	pending, _ := body["pending_token"].(string)

	rec, body := postTokenForm(t, a.IssuePasswordToken2FA, "/oauth/token/2fa",
		url.Values{"pending_token": {pending}, "code": {"000000"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad code status = %d, want 401", rec.Code)
	}
	if body["error"] != "invalid_grant" {
		t.Fatalf("error = %v, want invalid_grant", body["error"])
	}
}

func TestIssuePasswordToken_RememberDeviceSkips2FA(t *testing.T) {
	store := newMemTOTP()
	trusted := newMemTrusted()
	a := passwordTokenAuth(t, store, true, trusted)
	const secret = "JBSWY3DPEHPK3PXP"
	_ = store.Enroll(context.Background(), "t1", "owner@shop.lk", secret, nil)
	_ = store.Confirm(context.Background(), "t1", "owner@shop.lk")

	// First login: password → 2fa, then verify WITH remember=true → tokens +
	// a trusted-device token.
	_, body := postTokenForm(t, a.IssuePasswordToken, "/oauth/token/password",
		url.Values{"email": {"owner@shop.lk"}, "password": {"correct-horse"}})
	pending, _ := body["pending_token"].(string)
	code, _ := totp.GenerateCode(secret, time.Now())
	_, body = postTokenForm(t, a.IssuePasswordToken2FA, "/oauth/token/2fa",
		url.Values{"pending_token": {pending}, "code": {code}, "remember": {"true"}})
	td, _ := body["trusted_device_token"].(string)
	if td == "" {
		t.Fatalf("expected trusted_device_token when remember=true: %v", body)
	}

	// Second login: password + the trusted-device token → tokens directly, no
	// 2FA prompt.
	rec, body := postTokenForm(t, a.IssuePasswordToken, "/oauth/token/password",
		url.Values{
			"email":                {"owner@shop.lk"},
			"password":             {"correct-horse"},
			"trusted_device_token": {td},
		})
	if rec.Code != http.StatusOK {
		t.Fatalf("trusted login status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if body["status"] == "2fa_required" {
		t.Fatalf("trusted device should skip 2fa, got: %v", body)
	}
	if body["access_token"] == nil || body["refresh_token"] == nil {
		t.Fatalf("trusted login missing tokens: %v", body)
	}

	// A bogus trusted token must NOT skip 2FA.
	_, body = postTokenForm(t, a.IssuePasswordToken, "/oauth/token/password",
		url.Values{
			"email":                {"owner@shop.lk"},
			"password":             {"correct-horse"},
			"trusted_device_token": {"bogus"},
		})
	if body["status"] != "2fa_required" {
		t.Fatalf("bogus trusted token must still require 2fa: %v", body)
	}
}
