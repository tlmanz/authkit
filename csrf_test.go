package authkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func csrfAuth(t *testing.T, enable bool) *Auth {
	t.Helper()
	a, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "0123456789abcdef0123456789abcdef",
		UserStore:     stubUserStore{},
		CSRF:          CSRFConfig{Enable: enable},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestCSRF_SafeMethodIssuesCookie(t *testing.T) {
	a := csrfAuth(t, true)
	rec := httptest.NewRecorder()
	a.CSRF(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rec.Code)
	}
	cs := rec.Result().Cookies()
	if len(cs) == 0 || cs[0].Name != a.csrfCookieName() {
		t.Fatal("GET did not issue a CSRF cookie")
	}
	if !a.verifyCSRFToken(cs[0].Value) {
		t.Fatal("issued token does not verify")
	}
}

func TestCSRF_UnsafeRequiresMatchingToken(t *testing.T) {
	a := csrfAuth(t, true)
	tok, _ := a.issueCSRFToken()
	cookie := &http.Cookie{Name: a.csrfCookieName(), Value: tok}

	// No header → 403.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/x", nil)
	req.AddCookie(cookie)
	a.CSRF(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without header = %d, want 403", rec.Code)
	}

	// Matching header → pass.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/x", nil)
	req.AddCookie(cookie)
	req.Header.Set(csrfHeader, tok)
	a.CSRF(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST with matching token = %d, want 200", rec.Code)
	}

	// Tampered token (valid format but wrong MAC) → 403.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/x", nil)
	forged := "AAAA.BBBB"
	req.AddCookie(&http.Cookie{Name: a.csrfCookieName(), Value: forged})
	req.Header.Set(csrfHeader, forged)
	a.CSRF(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST with forged token = %d, want 403", rec.Code)
	}
}

func TestCSRF_SkippedForBearerAndWhenDisabled(t *testing.T) {
	// Bearer-authenticated request is exempt even without a CSRF token.
	a := csrfAuth(t, true)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/x", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	a.CSRF(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer POST = %d, want 200 (CSRF exempt)", rec.Code)
	}

	// Disabled → pass-through.
	a = csrfAuth(t, false)
	rec = httptest.NewRecorder()
	a.CSRF(okHandler()).ServeHTTP(rec, httptest.NewRequest("POST", "/api/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled POST = %d, want 200", rec.Code)
	}
}

// memThrottler is an in-memory LoginThrottler: lock after `limit` failures.
type memThrottler struct {
	limit    int
	fails    map[string]int
	locked   map[string]time.Time
	lockFor  time.Duration
	nowValue time.Time
}

func newMemThrottler(limit int, lockFor time.Duration) *memThrottler {
	return &memThrottler{limit: limit, fails: map[string]int{}, locked: map[string]time.Time{}, lockFor: lockFor, nowValue: time.Unix(0, 0)}
}

func (m *memThrottler) Allow(_ context.Context, key string) (time.Duration, bool) {
	if until, ok := m.locked[key]; ok && m.nowValue.Before(until) {
		return until.Sub(m.nowValue), false
	}
	return 0, true
}
func (m *memThrottler) RecordFailure(_ context.Context, key string) error {
	m.fails[key]++
	if m.fails[key] >= m.limit {
		m.locked[key] = m.nowValue.Add(m.lockFor)
	}
	return nil
}
func (m *memThrottler) Reset(_ context.Context, key string) error {
	delete(m.fails, key)
	delete(m.locked, key)
	return nil
}

func TestLogin_ThrottleLocksOutAndResets(t *testing.T) {
	th := newMemThrottler(3, time.Minute)
	a, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "0123456789abcdef0123456789abcdef",
		UserStore:     stubUserStore{}, // GetUserByEmail returns ErrUserNotFound
		Throttler:     th,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	post := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/auth/login", nil)
		req.Form = map[string][]string{"email": {"a@a.lk"}, "password": {"wrong"}}
		req.RemoteAddr = "10.0.0.1:1234"
		a.Login(rec, req)
		return rec.Code
	}

	// 3 failures → then locked out (429).
	if c := post(); c != http.StatusUnauthorized {
		t.Fatalf("attempt 1 = %d, want 401", c)
	}
	if c := post(); c != http.StatusUnauthorized {
		t.Fatalf("attempt 2 = %d, want 401", c)
	}
	if c := post(); c != http.StatusUnauthorized {
		t.Fatalf("attempt 3 = %d, want 401", c)
	}
	if c := post(); c != http.StatusTooManyRequests {
		t.Fatalf("attempt 4 = %d, want 429 (locked out)", c)
	}

	// Reset clears it (e.g. after a successful login elsewhere).
	_ = th.Reset(context.Background(), throttleKey("a@a.lk", "10.0.0.1"))
	if c := post(); c != http.StatusUnauthorized {
		t.Fatalf("after reset = %d, want 401 (not locked)", c)
	}
}
