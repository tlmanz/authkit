package authkit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// cookieJar simulates a browser: it collects Set-Cookie from a response
// and replays them on the next request to the same store.
func cookieJar(t *testing.T, w *httptest.ResponseRecorder) func() *http.Request {
	t.Helper()
	return func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range w.Result().Cookies() {
			r.AddCookie(c)
		}
		return r
	}
}

func TestSessionRoundTrip(t *testing.T) {
	store := newCookieStore("this-secret-is-exactly-32-bytes!!", false)
	u := &User{
		Email:       "alice@example.com",
		Name:        "Alice",
		AvatarURL:   "https://example.com/avatar.png",
		Provider:    "github",
		Role:        "admin",
		permissions: []string{PermAll},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := saveUserToSession(store, w, r, u); err != nil {
		t.Fatalf("saveUserToSession: %v", err)
	}

	got, err := userFromSession(store, cookieJar(t, w)())
	if err != nil {
		t.Fatalf("userFromSession: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil user")
	}
	if got.Email != u.Email {
		t.Errorf("Email: got %q, want %q", got.Email, u.Email)
	}
	if got.Name != u.Name {
		t.Errorf("Name: got %q, want %q", got.Name, u.Name)
	}
	if got.Role != u.Role {
		t.Errorf("Role: got %q, want %q", got.Role, u.Role)
	}
	if got.Provider != u.Provider {
		t.Errorf("Provider: got %q, want %q", got.Provider, u.Provider)
	}
	if got.AvatarURL != u.AvatarURL {
		t.Errorf("AvatarURL: got %q, want %q", got.AvatarURL, u.AvatarURL)
	}
}

func TestSessionPermissionsRoundTrip(t *testing.T) {
	store := newCookieStore("this-secret-is-exactly-32-bytes!!", false)
	want := []string{"view", "upload", "manage"}
	u := &User{Email: "dev@example.com", permissions: want}

	w := httptest.NewRecorder()
	if err := saveUserToSession(store, w, httptest.NewRequest(http.MethodGet, "/", nil), u); err != nil {
		t.Fatalf("saveUserToSession: %v", err)
	}

	got, err := userFromSession(store, cookieJar(t, w)())
	if err != nil || got == nil {
		t.Fatalf("userFromSession: err=%v, user=%v", err, got)
	}
	if len(got.permissions) != len(want) {
		t.Fatalf("permissions len: got %d, want %d (perms=%v)", len(got.permissions), len(want), got.permissions)
	}
	for i, p := range want {
		if got.permissions[i] != p {
			t.Errorf("permissions[%d]: got %q, want %q", i, got.permissions[i], p)
		}
	}
}

func TestUserFromSession_NoCookie(t *testing.T) {
	store := newCookieStore("this-secret-is-exactly-32-bytes!!", false)
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	got, err := userFromSession(store, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil user, got %+v", got)
	}
}

func TestClearSession_SetsExpiredCookie(t *testing.T) {
	store := newCookieStore("this-secret-is-exactly-32-bytes!!", false)
	u := &User{Email: "eve@example.com", permissions: []string{"view"}}

	// Save — produces the auth cookie.
	w1 := httptest.NewRecorder()
	if err := saveUserToSession(store, w1, httptest.NewRequest(http.MethodGet, "/", nil), u); err != nil {
		t.Fatalf("saveUserToSession: %v", err)
	}

	// Clear — the response must contain a Set-Cookie with MaxAge <= 0.
	w2 := httptest.NewRecorder()
	clearSession(store, w2, cookieJar(t, w1)())

	var found bool
	for _, c := range w2.Result().Cookies() {
		if c.Name == sessionName {
			found = true
			if c.MaxAge > 0 {
				t.Errorf("expected MaxAge <= 0 after clear, got %d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Errorf("expected a Set-Cookie header for %q after clearSession", sessionName)
	}
}

func TestClearSession_NoCookieDoesNotPanic(t *testing.T) {
	// clearSession should be a no-op when there is no existing session cookie.
	store := newCookieStore("this-secret-is-exactly-32-bytes!!", false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	// Must not panic.
	clearSession(store, w, r)
}

func TestSessionWrongSecret(t *testing.T) {
	storeA := newCookieStore("secret-A-that-is-long-enough-aa!", false)
	storeB := newCookieStore("secret-B-that-is-long-enough-bb!", false)

	u := &User{Email: "mallory@example.com", permissions: []string{PermAll}}
	w := httptest.NewRecorder()
	if err := saveUserToSession(storeA, w, httptest.NewRequest(http.MethodGet, "/", nil), u); err != nil {
		t.Fatalf("saveUserToSession: %v", err)
	}

	// Decoding with a different secret should fail gracefully (nil, nil).
	got, err := userFromSession(storeB, cookieJar(t, w)())
	if err != nil {
		t.Fatalf("userFromSession with wrong secret: unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil user when decoding with wrong secret, got %+v", got)
	}
}
