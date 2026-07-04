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

// passwordTokenAuth builds an Auth with BOTH the token layer and (optionally)
// TOTP, so the mobile password/2FA token endpoints can be exercised end to end.
func passwordTokenAuth(t *testing.T, totpStore TOTPStore, require2FA bool) *Auth {
	t.Helper()
	cfg := Config{
		Mode:              AuthModePassword,
		SessionSecret:     "0123456789abcdef0123456789abcdef",
		UserStore:         twoFAUserStore{}, // owner@shop.lk / correct-horse, tenant t1
		RBAC:              RBACConfig{Provider: fixedRolePolicy{}},
		SessionStore:      newMemStore(),
		EnableTokens:      true,
		SigningKeys:       testSigningKeys(t, "k1"),
		RefreshTokenStore: newMemRefresh(),
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   24 * time.Hour,
		TokenIssuer:       "https://app.klutch.lk",
		TokenClientID:     "klutch-mobile",
		TokenRedirectURIs: []string{"lk.klutch.app://oauth/callback"},
		AppName:           "Klutch",
	}
	if totpStore != nil {
		cfg.TOTPStore = totpStore
	}
	if require2FA {
		cfg.Require2FAForRoles = []string{"owner", "manager"}
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
	a := passwordTokenAuth(t, nil, false)
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
	a := passwordTokenAuth(t, nil, false)
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
	a := passwordTokenAuth(t, store, true)

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
	a := passwordTokenAuth(t, store, true)
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
