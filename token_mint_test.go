package authkit

import (
	"testing"
	"time"
)

func TestToken_ProviderRoundTripsThroughAccessToken(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())

	u := &User{Email: "owner@shop.example.com", TenantID: "t1", Role: "owner", Provider: "trial"}
	tok, err := a.issueAccessToken(u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := a.verifyAccessToken(tok)
	if err != nil || got == nil {
		t.Fatalf("verify = (%v, %v)", got, err)
	}
	if got.Provider != "trial" {
		t.Fatalf("Provider = %q, want %q", got.Provider, "trial")
	}
}

func TestToken_AttrsRoundTripThroughAccessToken(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())

	u := &User{Email: "owner@shop.example.com", TenantID: "t1", Role: "owner",
		Attrs: map[string]string{"branch_id": "b7", "plan": "pro"}}
	tok, err := a.issueAccessToken(u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := a.verifyAccessToken(tok)
	if err != nil || got == nil {
		t.Fatalf("verify = (%v, %v)", got, err)
	}
	if got.Attr("branch_id") != "b7" || got.Attr("plan") != "pro" {
		t.Fatalf("Attrs did not round-trip: %+v", got.Attrs)
	}
}

func TestToken_TokenWithoutProviderVerifiesAsEmpty(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())

	u := &User{Email: "owner@shop.example.com", TenantID: "t1", Role: "owner"}
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

func TestMintAccessToken_CustomTTL(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nowFn = func() time.Time { return base }
	defer func() { nowFn = time.Now }()

	u := &User{Email: "trial-abc123@example.com", TenantID: "trial-t1", Role: "owner", Provider: "trial"}
	ttl := 45 * time.Minute
	access, err := a.MintAccessToken(u, ttl)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}

	// The minted token actually carries the custom ttl, not Tokens.AccessTTL
	// (15m in tokenAuth's config) — verify it's still valid at +44m and
	// expired at +46m.
	nowFn = func() time.Time { return base.Add(44 * time.Minute) }
	if got, err := a.verifyAccessToken(access); err != nil || got.Provider != "trial" {
		t.Fatalf("token should still be valid within custom ttl: got=%v err=%v", got, err)
	}
	nowFn = func() time.Time { return base.Add(46 * time.Minute) }
	if _, err := a.verifyAccessToken(access); err == nil {
		t.Fatal("token should be expired past custom ttl")
	}
}

func TestMintAccessToken_NonPositiveTTLIsRejected(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())
	u := &User{Email: "owner@shop.example.com", TenantID: "t1", Role: "owner"}
	for _, ttl := range []time.Duration{0, -time.Second} {
		if _, err := a.MintAccessToken(u, ttl); err == nil {
			t.Fatalf("ttl=%v: expected an error, got none", ttl)
		}
	}
}

func TestMintAccessToken_TokensDisabled(t *testing.T) {
	a, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "0123456789abcdef0123456789abcdef",
		UserStore:     twoFAUserStore{},
		RBAC:          RBACConfig{Provider: fixedRolePolicy{}},
		Sessions:      SessionConfig{Store: newMemStore()},
		// Tokens.Enable left false.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u := &User{Email: "owner@shop.example.com", TenantID: "t1", Role: "owner"}
	if _, err := a.MintAccessToken(u, time.Hour); err == nil {
		t.Fatal("expected error when tokens are disabled")
	}
}
