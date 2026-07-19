package authkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// memSessionStore is an in-memory SessionStore for exercising the server-side
// session path without a database.
type memSessionStore struct {
	mu sync.Mutex
	m  map[string]*Session
}

func newMemStore() *memSessionStore { return &memSessionStore{m: map[string]*Session{}} }

func (s *memSessionStore) Create(_ context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.m[sess.ID] = &cp
	return nil
}

func (s *memSessionStore) Get(_ context.Context, id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil, nil
	}
	cp := *sess
	return &cp, nil
}

func (s *memSessionStore) Touch(_ context.Context, id string, lastSeen time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.m[id]; ok {
		sess.LastSeenAt = lastSeen
	}
	return nil
}

func (s *memSessionStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	return nil
}

func (s *memSessionStore) RevokeAllForUser(_ context.Context, tenantID, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.m {
		if sess.TenantID == tenantID && sess.Email == email {
			delete(s.m, id)
		}
	}
	return nil
}

func (s *memSessionStore) len() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.m) }

// stubUserStore satisfies the password-mode requirement; these tests drive the
// session methods directly, so its methods are never called.
type stubUserStore struct{}

func (stubUserStore) CreateUser(context.Context, string, string, string) error { return nil }
func (stubUserStore) GetUserByEmail(context.Context, string) (*PasswordUser, error) {
	return nil, ErrUserNotFound
}
func (stubUserStore) UpdatePassword(context.Context, string, string) error { return nil }

func newServerSessionAuth(t *testing.T, store SessionStore) *Auth {
	t.Helper()
	a, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "0123456789abcdef0123456789abcdef",
		UserStore:     stubUserStore{},
		Sessions: SessionConfig{
			Store:           store,
			IdleTimeout:     30 * time.Minute,
			AbsoluteTimeout: 2 * time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func userFixture() *User {
	return &User{Email: "a@a.lk", Name: "Anil", Provider: "password", Role: "owner", TenantID: "t1", permissions: []string{"invoice:issue"}}
}

// establishAndCookie logs in a fixture user and returns the Set-Cookie value.
func establishAndCookie(t *testing.T, a *Auth) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	if err := a.saveSession(WithTenant(req.Context(), "t1"), rec, req, userFixture()); err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	res := rec.Result()
	if len(res.Cookies()) == 0 {
		t.Fatal("no session cookie set")
	}
	return res.Cookies()[0]
}

func TestServerSession_RoundTrip(t *testing.T) {
	store := newMemStore()
	a := newServerSessionAuth(t, store)

	c := establishAndCookie(t, a)
	if c.Value == "" {
		t.Fatal("empty session id")
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	u, err := a.loadSession(req.Context(), req)
	if err != nil || u == nil {
		t.Fatalf("loadSession = (%v, %v), want a user", u, err)
	}
	if u.Email != "a@a.lk" || u.TenantID != "t1" || u.Role != "owner" {
		t.Fatalf("unexpected user: %+v", u)
	}
	if !u.Can("invoice:issue") {
		t.Fatal("permissions not restored from session")
	}
}

func TestServerSession_RevokeKillsNextRequest(t *testing.T) {
	store := newMemStore()
	a := newServerSessionAuth(t, store)
	c := establishAndCookie(t, a)

	// Revoke (e.g. fired employee), then the same cookie must fail.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(c)
	a.endSession(req.Context(), rec, req)

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(c)
	u, _ := a.loadSession(req2.Context(), req2)
	if u != nil {
		t.Fatal("revoked session still resolves a user")
	}
}

func TestServerSession_LogoutEverywhere(t *testing.T) {
	store := newMemStore()
	a := newServerSessionAuth(t, store)

	c1 := establishAndCookie(t, a)
	c2 := establishAndCookie(t, a) // second device
	if store.len() != 2 {
		t.Fatalf("want 2 sessions, got %d", store.len())
	}

	if err := a.RevokeUserSessions(WithTenant(context.Background(), "t1"), "t1", "a@a.lk"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}

	for _, c := range []*http.Cookie{c1, c2} {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(c)
		if u, _ := a.loadSession(req.Context(), req); u != nil {
			t.Fatal("session survived log-out-everywhere")
		}
	}
}

func TestServerSession_IdleAndAbsoluteExpiry(t *testing.T) {
	store := newMemStore()
	a := newServerSessionAuth(t, store) // idle 30m, absolute 2h

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nowFn = func() time.Time { return base }
	defer func() { nowFn = time.Now }()

	c := establishAndCookie(t, a)
	loggedIn := func() bool {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(c)
		u, _ := a.loadSession(req.Context(), req)
		return u != nil
	}

	// Within idle window — still valid (and slides LastSeenAt forward).
	nowFn = func() time.Time { return base.Add(20 * time.Minute) }
	if !loggedIn() {
		t.Fatal("session should be valid within idle window")
	}

	// 31 min after the last touch (12:20) → idle expiry.
	nowFn = func() time.Time { return base.Add(20*time.Minute + 31*time.Minute) }
	if loggedIn() {
		t.Fatal("session should have expired on idle timeout")
	}

	// Fresh session, then exceed the absolute cap despite continuous activity.
	store2 := newMemStore()
	a2 := newServerSessionAuth(t, store2)
	nowFn = func() time.Time { return base }
	c = establishAndCookie(t, a2)
	a = a2
	// Keep touching every 20m up to ~2h, then cross the absolute cap.
	for _, m := range []int{20, 40, 60, 80, 100} {
		nowFn = func() time.Time { return base.Add(time.Duration(m) * time.Minute) }
		if !loggedIn() {
			t.Fatalf("session should still be valid at +%dm (absolute cap 2h)", m)
		}
	}
	nowFn = func() time.Time { return base.Add(121 * time.Minute) }
	if loggedIn() {
		t.Fatal("session should have expired on absolute timeout")
	}
}

func TestServerSession_RotatesOnLogin(t *testing.T) {
	store := newMemStore()
	a := newServerSessionAuth(t, store)

	c1 := establishAndCookie(t, a)

	// Logging in again with the old cookie present must mint a NEW id and revoke
	// the old one (fixation prevention).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	req.AddCookie(c1)
	if err := a.saveSession(WithTenant(req.Context(), "t1"), rec, req, userFixture()); err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	c2 := rec.Result().Cookies()[0]

	if c2.Value == c1.Value {
		t.Fatal("session id did not rotate on login")
	}
	// Old id revoked.
	if s, _ := store.Get(context.Background(), c1.Value); s != nil {
		t.Fatal("old session not revoked on rotation")
	}
	// New id valid.
	if s, _ := store.Get(context.Background(), c2.Value); s == nil {
		t.Fatal("new session missing after rotation")
	}
}
