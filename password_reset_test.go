package authkit

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// ── in-memory reset store + delivery ────────────────────────────────────────

type memResetStore struct {
	mu sync.Mutex
	m  map[string]*ResetToken
}

func newMemResetStore() *memResetStore { return &memResetStore{m: map[string]*ResetToken{}} }

func (s *memResetStore) CreateResetToken(_ context.Context, hash, email, kind string, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[hash] = &ResetToken{TokenHash: hash, Email: email, Kind: kind, ExpiresAt: exp}
	return nil
}

func (s *memResetStore) ConsumeResetToken(_ context.Context, hash, kind string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.m[hash]
	if !ok || t.Kind != kind || t.UsedAt != nil || nowFn().After(t.ExpiresAt) {
		return "", false, nil
	}
	now := nowFn()
	t.UsedAt = &now
	return t.Email, true, nil
}

type captureDelivery struct{ last *ResetRequest }

func (d *captureDelivery) SendPasswordReset(_ context.Context, req ResetRequest) error {
	r := req
	d.last = &r
	return nil
}

func buildResetAuth() (*Auth, *mockUserStore, *captureDelivery, *memSessionStore) {
	us := newMockUserStore()
	cd := &captureDelivery{}
	ss := newMemStore()
	a := &Auth{
		cfg: Config{
			Mode:          AuthModePassword,
			SessionSecret: testSecret,
			UserStore:     us,
			Sessions:      SessionConfig{Store: ss},
			Reset:         ResetConfig{Store: newMemResetStore(), Delivery: cd},
		},
		store:        newCookieStore(testSecret, false),
		rbacProvider: newRBAC(Policy{}),
		log:          slog.Default(),
		audit:        NopAuditSink{},
	}
	return a, us, cd, ss
}

func TestForgotPassword_NoEnumeration(t *testing.T) {
	a, us, cd, _ := buildResetAuth()
	hash, _ := HashPassword("old-password")
	us.users["owner@shop.lk"] = &PasswordUser{Email: "owner@shop.lk", Name: "Owner", HashedPassword: hash, TenantID: "t1"}

	// Known email → 200 and a token is delivered.
	w := httptest.NewRecorder()
	a.ForgotPassword(w, postForm("/auth/forgot-password", url.Values{"email": {"owner@shop.lk"}}))
	if w.Code != http.StatusOK {
		t.Fatalf("known email = %d, want 200", w.Code)
	}
	if cd.last == nil || cd.last.Token == "" {
		t.Fatal("expected a reset token to be delivered for a known email")
	}

	// Unknown email → identical 200, but NOTHING delivered (no enumeration).
	cd.last = nil
	w = httptest.NewRecorder()
	a.ForgotPassword(w, postForm("/auth/forgot-password", url.Values{"email": {"ghost@shop.lk"}}))
	if w.Code != http.StatusOK {
		t.Fatalf("unknown email = %d, want 200", w.Code)
	}
	if cd.last != nil {
		t.Fatal("delivery happened for an unknown email — that leaks which accounts exist")
	}
}

func TestResetPassword_ChangesPasswordRevokesSessionsSingleUse(t *testing.T) {
	a, us, cd, ss := buildResetAuth()
	hash, _ := HashPassword("old-password")
	us.users["owner@shop.lk"] = &PasswordUser{Email: "owner@shop.lk", Name: "Owner", HashedPassword: hash, TenantID: "t1"}

	// A live session that must not survive the reset.
	_ = ss.Create(context.Background(), &Session{ID: "live", TenantID: "t1", Email: "owner@shop.lk"})

	// Request a token.
	a.ForgotPassword(httptest.NewRecorder(), postForm("/auth/forgot-password", url.Values{"email": {"owner@shop.lk"}}))
	token := cd.last.Token

	// Reset with the token.
	w := httptest.NewRecorder()
	a.ResetPassword(w, postForm("/auth/reset-password", url.Values{"token": {token}, "password": {"brand-new-password"}}))
	if w.Code != http.StatusOK {
		t.Fatalf("reset = %d, want 200", w.Code)
	}
	if !CheckPassword(us.users["owner@shop.lk"].HashedPassword, "brand-new-password") {
		t.Fatal("password was not updated to the new value")
	}
	if ss.len() != 0 {
		t.Fatal("existing sessions were not revoked after a password reset")
	}

	// Token is single-use: replaying it fails.
	w = httptest.NewRecorder()
	a.ResetPassword(w, postForm("/auth/reset-password", url.Values{"token": {token}, "password": {"another-new-password"}}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("token replay = %d, want 400", w.Code)
	}
}

func TestResetPassword_RejectsUnknownToken(t *testing.T) {
	a, _, _, _ := buildResetAuth()
	w := httptest.NewRecorder()
	a.ResetPassword(w, postForm("/auth/reset-password", url.Values{"token": {"not-a-real-token"}, "password": {"brand-new-password"}}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bogus token = %d, want 400", w.Code)
	}
}
