package authkit

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestToken_ProviderRoundTripsThroughAccessToken(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())

	u := &User{Email: "owner@shop.lk", TenantID: "t1", Role: "owner", Provider: "demo"}
	tok, err := a.issueAccessToken(u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := a.verifyAccessToken(tok)
	if err != nil || got == nil {
		t.Fatalf("verify = (%v, %v)", got, err)
	}
	if got.Provider != "demo" {
		t.Fatalf("Provider = %q, want %q", got.Provider, "demo")
	}
}

func TestToken_OlderTokenWithoutProviderVerifiesAsEmpty(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())

	// No Provider set — mirrors a token minted before this field existed, or a
	// real (non-demo) password login today.
	u := &User{Email: "owner@shop.lk", TenantID: "t1", Role: "owner"}
	tok, err := a.issueAccessToken(u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := a.verifyAccessToken(tok)
	if err != nil || got == nil {
		t.Fatalf("verify = (%v, %v)", got, err)
	}
	if got.Provider != "" {
		t.Fatalf("Provider = %q, want empty", got.Provider)
	}
}

func TestIssueAccessTokenOnly_NoRefreshTokenAndCustomTTL(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nowFn = func() time.Time { return base }
	defer func() { nowFn = time.Now }()

	u := &User{Email: "demo-abc123@klutch.lk", TenantID: "demo-t1", Role: "owner", Provider: "demo"}
	rec := httptest.NewRecorder()
	ttl := 45 * time.Minute
	if err := a.IssueAccessTokenOnly(rec, u, ttl); err != nil {
		t.Fatalf("IssueAccessTokenOnly: %v", err)
	}
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := body["refresh_token"]; present {
		t.Fatalf("response carries a refresh_token, want none: %+v", body)
	}
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatal("missing access_token")
	}
	if got := int(body["expires_in"].(float64)); got != int(ttl.Seconds()) {
		t.Fatalf("expires_in = %d, want %d", got, int(ttl.Seconds()))
	}

	// The minted token actually carries the custom ttl, not AccessTokenTTL
	// (15m in tokenAuth's config) — verify it's still valid at +44m and
	// expired at +46m.
	nowFn = func() time.Time { return base.Add(44 * time.Minute) }
	if got, err := a.verifyAccessToken(access); err != nil || got.Provider != "demo" {
		t.Fatalf("token should still be valid within custom ttl: got=%v err=%v", got, err)
	}
	nowFn = func() time.Time { return base.Add(46 * time.Minute) }
	if _, err := a.verifyAccessToken(access); err == nil {
		t.Fatal("token should be expired past custom ttl")
	}
}

func TestIssueAccessTokenOnly_ZeroTTLFallsBackToConfigured(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())
	u := &User{Email: "owner@shop.lk", TenantID: "t1", Role: "owner"}
	rec := httptest.NewRecorder()
	if err := a.IssueAccessTokenOnly(rec, u, 0); err != nil {
		t.Fatalf("IssueAccessTokenOnly: %v", err)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if got := int(body["expires_in"].(float64)); got != int(a.accessTTL().Seconds()) {
		t.Fatalf("expires_in = %d, want configured AccessTokenTTL %d", got, int(a.accessTTL().Seconds()))
	}
}

func TestIssueAccessTokenOnly_TokensDisabled(t *testing.T) {
	a, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "0123456789abcdef0123456789abcdef",
		UserStore:     twoFAUserStore{},
		RBAC:          RBACConfig{Provider: fixedRolePolicy{}},
		SessionStore:  newMemStore(),
		// EnableTokens left false.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	u := &User{Email: "owner@shop.lk", TenantID: "t1", Role: "owner"}
	if err := a.IssueAccessTokenOnly(rec, u, time.Hour); err == nil {
		t.Fatal("expected error when tokens are disabled")
	}
	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
