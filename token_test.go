package authkit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// memRefreshStore is an in-memory RefreshTokenStore (hashes raw tokens like a
// real store would, to mirror the boundary contract).
type memRefreshStore struct {
	mu sync.Mutex
	m  map[string]*RefreshToken // hash -> token
}

func newMemRefresh() *memRefreshStore { return &memRefreshStore{m: map[string]*RefreshToken{}} }

func rhash(raw string) string {
	s := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func (s *memRefreshStore) Create(_ context.Context, t *RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.m[rhash(t.ID)] = &cp
	return nil
}
func (s *memRefreshStore) Get(_ context.Context, raw string) (*RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.m[rhash(raw)]
	if !ok {
		return nil, nil
	}
	cp := *t
	return &cp, nil
}
func (s *memRefreshStore) Rotate(_ context.Context, rawOld string, next *RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.m[rhash(rawOld)]
	if !ok || old.UsedAt != nil || old.RevokedAt != nil {
		return ErrUserNotFound // any error: rotation rejected
	}
	now := time.Now()
	old.UsedAt = &now
	cp := *next
	s.m[rhash(next.ID)] = &cp
	return nil
}
func (s *memRefreshStore) RevokeChain(_ context.Context, chainID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, t := range s.m {
		if t.ChainID == chainID {
			t.RevokedAt = &now
		}
	}
	return nil
}
func (s *memRefreshStore) RevokeAllForUser(_ context.Context, tenantID, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, t := range s.m {
		if t.TenantID == tenantID && t.UserEmail == email && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}

// testSigningKeys derives a stable Ed25519 seed from each kid, so the same kid
// yields the same key regardless of position (needed to test rotation).
func testSigningKeys(t *testing.T, kids ...string) []SigningKey {
	t.Helper()
	var keys []SigningKey
	for _, kid := range kids {
		seed := sha256.Sum256([]byte("seed:" + kid))
		k, err := NewSigningKey(kid, seed[:])
		if err != nil {
			t.Fatalf("NewSigningKey: %v", err)
		}
		keys = append(keys, k)
	}
	return keys
}

func tokenAuth(t *testing.T, keys []SigningKey, store RefreshTokenStore) *Auth {
	t.Helper()
	a, err := New(Config{
		Mode:              AuthModePassword,
		SessionSecret:     "0123456789abcdef0123456789abcdef",
		UserStore:         twoFAUserStore{}, // owner@shop.lk, tenant t1
		RBAC:              RBACConfig{Provider: fixedRolePolicy{}},
		SessionStore:      newMemStore(),
		EnableTokens:      true,
		SigningKeys:       keys,
		RefreshTokenStore: store,
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   24 * time.Hour,
		TokenIssuer:       "https://api.klutch.lk",
		TokenClientID:     "klutch-mobile",
		TokenRedirectURIs: []string{"klutch://cb"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestToken_AccessRoundTripAndKeyRotation(t *testing.T) {
	keys := testSigningKeys(t, "k1")
	a := tokenAuth(t, keys, newMemRefresh())

	u := &User{Email: "owner@shop.lk", TenantID: "t1", Role: "owner"}
	tok, err := a.issueAccessToken(u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := a.verifyAccessToken(tok)
	if err != nil || got == nil {
		t.Fatalf("verify = (%v, %v)", got, err)
	}
	if got.Email != "owner@shop.lk" || got.TenantID != "t1" || got.Role != "owner" {
		t.Fatalf("claims mismatch: %+v", got)
	}

	// Rotate: a new deployment makes k2 the current signer but keeps k1 in the
	// ring — a token signed by the now-previous k1 must still verify.
	rotated := tokenAuth(t, testSigningKeys(t, "k2", "k1"), newMemRefresh())
	if _, err := rotated.verifyAccessToken(tok); err != nil {
		t.Fatalf("token signed by previous key must still verify after rotation: %v", err)
	}
	// New tokens are signed by the current key (k2).
	newTok, _ := rotated.issueAccessToken(u)
	parts := strings.Split(newTok, ".")
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if !strings.Contains(string(hdr), `"kid":"k2"`) {
		t.Fatalf("new token not signed by current key: header=%s", hdr)
	}
}

func TestToken_ExpiredAccessDoesNotAffectRefresh(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nowFn = func() time.Time { return base }
	defer func() { nowFn = time.Now }()

	u := &User{Email: "owner@shop.lk", TenantID: "t1", Role: "owner"}
	access, refresh, err := a.issueTokenPair(WithTenant(context.Background(), "t1"), u)
	if err != nil {
		t.Fatalf("issueTokenPair: %v", err)
	}

	// Advance past the access TTL: the access token is invalid…
	nowFn = func() time.Time { return base.Add(20 * time.Minute) }
	if _, err := a.verifyAccessToken(access); err == nil {
		t.Fatal("expected expired access token to fail verification")
	}

	// …but the refresh still works (no hard logout — §6.4 offline behavior).
	rec := postRefresh(t, a, refresh)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh after access expiry = %d, want 200", rec.Code)
	}
}

func TestToken_RefreshRotatesAndDetectsReuse(t *testing.T) {
	store := newMemRefresh()
	a := tokenAuth(t, testSigningKeys(t, "k1"), store)

	u := &User{Email: "owner@shop.lk", TenantID: "t1", Role: "owner"}
	_, refresh, err := a.issueTokenPair(WithTenant(context.Background(), "t1"), u)
	if err != nil {
		t.Fatalf("issueTokenPair: %v", err)
	}

	// First refresh succeeds and returns a NEW refresh token.
	rec := postRefresh(t, a, refresh)
	if rec.Code != http.StatusOK {
		t.Fatalf("first refresh = %d, want 200", rec.Code)
	}
	var pair struct {
		Refresh string `json:"refresh_token"`
		Access  string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &pair)
	if pair.Refresh == "" || pair.Refresh == refresh {
		t.Fatal("refresh did not rotate the token")
	}

	// Replaying the OLD (now-used) refresh ⇒ reuse detected ⇒ chain revoked.
	rec = postRefresh(t, a, refresh)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("reuse of old refresh = %d, want 401", rec.Code)
	}

	// The chain is revoked, so the rotated (child) token is now dead too.
	rec = postRefresh(t, a, pair.Refresh)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("child refresh after chain revoke = %d, want 401", rec.Code)
	}
}

func TestToken_VerifierResolvesPermsServerSide(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())
	u := &User{Email: "owner@shop.lk", TenantID: "t1", Role: "owner"}
	access, err := a.issueAccessToken(u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// A protected route gated on a permission the fixedRolePolicy grants ("*").
	var seen *User
	h := a.Require("invoice:issue")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = UserFromCtx(r.Context())
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/invoices", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("bearer-JWT request = %d, want 200", rec.Code)
	}
	if seen == nil || !seen.Can("invoice:issue") {
		t.Fatal("permissions not resolved server-side for token auth")
	}
}

// memAuthCodeStore is an in-memory AuthCodeStore: a jti may be claimed once.
type memAuthCodeStore struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newMemAuthCodes() *memAuthCodeStore { return &memAuthCodeStore{seen: map[string]bool{}} }

func (s *memAuthCodeStore) ClaimAuthCode(_ context.Context, jti string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[jti] {
		return false, nil
	}
	s.seen[jti] = true
	return true, nil
}

// TestPKCE_CodeIsSingleUse pins the fix: with an AuthCodeStore configured, an
// authorization code redeemed once cannot be exchanged a second time inside its
// TTL, even with the correct verifier — a copied code is rejected.
func TestPKCE_CodeIsSingleUse(t *testing.T) {
	a, err := New(Config{
		Mode: AuthModePassword, SessionSecret: "0123456789abcdef0123456789abcdef",
		UserStore: twoFAUserStore{}, RBAC: RBACConfig{Provider: fixedRolePolicy{}},
		SessionStore: newMemStore(), EnableTokens: true,
		SigningKeys: testSigningKeys(t, "k1"), RefreshTokenStore: newMemRefresh(),
		AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: 24 * time.Hour,
		TokenIssuer: "https://api.klutch.lk", TokenClientID: "klutch-mobile",
		TokenRedirectURIs: []string{"klutch://cb"},
		AuthCodeStore:     newMemAuthCodes(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	verifier := "verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	rec := httptest.NewRecorder()
	estReq := httptest.NewRequest("POST", "/login", nil)
	_ = a.establishServerSession(WithTenant(estReq.Context(), "t1"), rec, estReq, &User{Email: "owner@shop.lk", TenantID: "t1", Role: "owner"})
	sessionCookie := rec.Result().Cookies()[0]

	rec = httptest.NewRecorder()
	au := url.Values{
		"response_type": {"code"}, "client_id": {"klutch-mobile"},
		"redirect_uri": {"klutch://cb"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/authorize?"+au.Encode(), nil)
	req.AddCookie(sessionCookie)
	a.Authorize(rec, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	code := loc.Query().Get("code")

	exchange := func() int {
		rec := httptest.NewRecorder()
		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"code_verifier": {verifier}, "redirect_uri": {"klutch://cb"},
		}
		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		a.IssueToken(rec, req)
		return rec.Code
	}
	if c := exchange(); c != http.StatusOK {
		t.Fatalf("first exchange = %d, want 200", c)
	}
	if c := exchange(); c == http.StatusOK {
		t.Fatal("second exchange of the same code succeeded (must be single-use)")
	}
}

func TestPKCE_AuthorizeAndExchange(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1"), newMemRefresh())

	verifier := "verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// Establish a web session (the system browser carries this into /authorize).
	rec := httptest.NewRecorder()
	estReq := httptest.NewRequest("POST", "/login", nil)
	_ = a.establishServerSession(WithTenant(estReq.Context(), "t1"), rec, estReq, &User{Email: "owner@shop.lk", TenantID: "t1", Role: "owner"})
	sessionCookie := rec.Result().Cookies()[0]

	// GET /authorize → 303 redirect with a code.
	rec = httptest.NewRecorder()
	au := url.Values{
		"response_type": {"code"}, "client_id": {"klutch-mobile"},
		"redirect_uri": {"klutch://cb"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "state": {"xyz"},
	}
	req := httptest.NewRequest("GET", "/authorize?"+au.Encode(), nil)
	req.AddCookie(sessionCookie)
	a.Authorize(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("authorize = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != "xyz" {
		t.Fatalf("authorize redirect missing code/state: %s", rec.Header().Get("Location"))
	}

	exchange := func(verifier string) int {
		rec := httptest.NewRecorder()
		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"code_verifier": {verifier}, "redirect_uri": {"klutch://cb"},
		}
		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		a.IssueToken(rec, req)
		return rec.Code
	}

	if c := exchange(verifier); c != http.StatusOK {
		t.Fatalf("token exchange = %d, want 200", c)
	}
	if c := exchange("wrong-verifier"); c == http.StatusOK {
		t.Fatal("token exchange accepted a wrong PKCE verifier")
	}
}

func TestJWKS_PublishesKeys(t *testing.T) {
	a := tokenAuth(t, testSigningKeys(t, "k1", "k2"), newMemRefresh())
	rec := httptest.NewRecorder()
	a.JWKS(rec, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks = %d", rec.Code)
	}
	var out struct {
		Keys []map[string]string `json:"keys"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Keys) != 2 {
		t.Fatalf("jwks published %d keys, want 2", len(out.Keys))
	}
	if out.Keys[0]["kty"] != "OKP" || out.Keys[0]["crv"] != "Ed25519" || out.Keys[0]["kid"] == "" {
		t.Fatalf("unexpected jwk: %+v", out.Keys[0])
	}
}

func postRefresh(t *testing.T, a *Auth, refresh string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	form := url.Values{"refresh_token": {refresh}}
	req := httptest.NewRequest("POST", "/token/refresh", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	a.RefreshAccessToken(rec, req)
	return rec
}
