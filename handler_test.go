package authkit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── Me handler tests ─────────────────────────────────────────────────────────

func TestMe_WithSession_ReturnsUser(t *testing.T) {
	u := &User{
		Email:       "alice@example.com",
		Name:        "Alice",
		AvatarURL:   "https://example.com/avatar.png",
		Provider:    "github",
		Role:        "admin",
		permissions: []string{PermAll},
	}
	a, cookies := buildAuthWithSession(t, u)

	w := httptest.NewRecorder()
	r := requestWithCookies(cookies)
	r.URL.Path = "/auth/me"
	a.Me(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	var got User
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Email != u.Email {
		t.Errorf("email: got %q, want %q", got.Email, u.Email)
	}
	if got.Name != u.Name {
		t.Errorf("name: got %q, want %q", got.Name, u.Name)
	}
	if got.Provider != u.Provider {
		t.Errorf("provider: got %q, want %q", got.Provider, u.Provider)
	}
	if got.Role != u.Role {
		t.Errorf("role: got %q, want %q", got.Role, u.Role)
	}
}

func TestMe_WithContext_ReturnsUser(t *testing.T) {
	u := &User{
		Email:    "bob@example.com",
		Name:     "Bob",
		Provider: "password",
		Role:     "viewer",
	}
	a := &Auth{
		store: newCookieStore("test-secret-that-is-32-bytes-ok!", false),
		rbacProvider:  &rbac{},
		log:   defaultLogger{},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	r = r.WithContext(withUser(r.Context(), u))
	a.Me(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}

	var got User
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Email != u.Email {
		t.Errorf("email: got %q, want %q", got.Email, u.Email)
	}
}

func TestMe_NoSession_Returns401(t *testing.T) {
	a := &Auth{
		store: newCookieStore("test-secret-that-is-32-bytes-ok!", false),
		rbacProvider:  &rbac{},
		log:   defaultLogger{},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	a.Me(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}

	body := w.Body.String()
	if body == "" {
		t.Error("expected non-empty error body")
	}
}

// ── Logout handler tests ────────────────────────────────────────────────────

func TestLogout_RedirectsToAfterLogoutURL(t *testing.T) {
	a := &Auth{
		store: newCookieStore("test-secret-that-is-32-bytes-ok!", false),
		cfg:   Config{AfterLogoutURL: "/goodbye"},
		rbacProvider:  &rbac{},
		log:   defaultLogger{},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	a.Logout(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusSeeOther)
	}
	if loc := w.Header().Get("Location"); loc != "/goodbye" {
		t.Errorf("redirect: got %q, want /goodbye", loc)
	}
}

func TestLogout_ClearsSession(t *testing.T) {
	secret := "test-secret-that-is-32-bytes-ok!"
	store := newCookieStore(secret, false)
	u := &User{Email: "alice@example.com", permissions: []string{"view"}}

	// Save a session.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	saveUserToSession(store, w1, r1, u)

	// Clear the session directly (what Logout does internally).
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	for _, c := range w1.Result().Cookies() {
		r2.AddCookie(c)
	}
	clearSession(store, w2, r2)

	// The response should contain an expired cookie.
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
		t.Error("expected Set-Cookie header after clearSession")
	}
}

func TestLogout_NoSession_DoesNotPanic(t *testing.T) {
	a := &Auth{
		store: newCookieStore("test-secret-that-is-32-bytes-ok!", false),
		cfg:   Config{AfterLogoutURL: "/"},
		log:   defaultLogger{},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	a.Logout(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusSeeOther)
	}
}
