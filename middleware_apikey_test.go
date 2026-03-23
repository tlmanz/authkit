package authkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockKeyValidator is a test double for APIKeyValidator.
type mockKeyValidator struct {
	user *User
	err  error
}

func (m *mockKeyValidator) ValidateKey(_ context.Context, _ string) (*User, error) {
	return m.user, m.err
}

// buildAuthWithAPIKey creates an Auth with a mock validator and a policy that
// grants the given permissions to the returned role.
func buildAuthWithAPIKey(t *testing.T, u *User, perms []string) *Auth {
	t.Helper()
	store := newCookieStore("middleware-test-secret-32-bytes!!", false)
	policy := Policy{
		Roles: map[string]RolePolicy{
			u.Role: {Permissions: perms},
		},
	}
	return &Auth{
		store:        store,
		rbacProvider:         newRBAC(policy),
		keyValidator: &mockKeyValidator{user: u},
	}
}

func requestWithBearer(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// ── RequireAuth + API key ─────────────────────────────────────────────────────

func TestRequireAuth_ValidAPIKey_CallsNext(t *testing.T) {
	u := &User{Email: "apikey:ci", Name: "ci", Provider: "apikey", Role: "developer"}
	a := buildAuthWithAPIKey(t, u, []string{"view", "upload"})

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.RequireAuth(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithBearer("ah_testkey"))

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if !called {
		t.Error("next handler was not called")
	}
	if captured == nil || captured.Email != u.Email {
		t.Errorf("user in ctx: got %v, want email=%q", captured, u.Email)
	}
}

func TestRequireAuth_InvalidAPIKey_NoSession_Returns401(t *testing.T) {
	store := newCookieStore("middleware-test-secret-32-bytes!!", false)
	a := &Auth{
		store:        store,
		rbacProvider:         &rbac{},
		keyValidator: &mockKeyValidator{user: nil}, // validator returns no user
	}

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.RequireAuth(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithBearer("ah_badkey"))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler should not have been called")
	}
}

func TestRequireAuth_APIKeyResolvesPermissionsFromRBAC(t *testing.T) {
	u := &User{Email: "apikey:ci", Provider: "apikey", Role: "developer"}
	a := buildAuthWithAPIKey(t, u, []string{"view", "upload"})

	var got *User
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = UserFromCtx(r.Context())
	})
	a.RequireAuth(handler).ServeHTTP(httptest.NewRecorder(), requestWithBearer("ah_key"))

	if got == nil {
		t.Fatal("user not injected")
	}
	if !got.Can("upload") {
		t.Error("expected Can('upload') true")
	}
	if got.Can("manage") {
		t.Error("expected Can('manage') false")
	}
}

// ── Require(permission) + API key ─────────────────────────────────────────────

func TestRequire_ValidAPIKeyWithPerm_CallsNext(t *testing.T) {
	u := &User{Email: "apikey:ci", Provider: "apikey", Role: "developer"}
	a := buildAuthWithAPIKey(t, u, []string{"view", "upload"})

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.Require("upload")(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithBearer("ah_key"))

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if !called {
		t.Error("next handler was not called")
	}
}

func TestRequire_ValidAPIKeyWithoutPerm_Returns403(t *testing.T) {
	u := &User{Email: "apikey:ci", Provider: "apikey", Role: "developer"}
	a := buildAuthWithAPIKey(t, u, []string{"view", "upload"})

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.Require("manage")(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithBearer("ah_key"))

	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
	if called {
		t.Error("next handler should not have been called")
	}
}

// ── RequireSessionAuth — rejects API keys ─────────────────────────────────────

func TestRequireSessionAuth_ValidAPIKey_Returns401(t *testing.T) {
	u := &User{Email: "apikey:ci", Provider: "apikey", Role: "developer"}
	a := buildAuthWithAPIKey(t, u, []string{"view", "upload"})

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.RequireSessionAuth(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithBearer("ah_key"))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401 (API keys rejected by RequireSessionAuth)", w.Code)
	}
	if called {
		t.Error("next handler should not have been called")
	}
}

func TestRequireSessionAuth_ValidSession_CallsNext(t *testing.T) {
	u := &User{Email: "alice@example.com", Role: "admin", permissions: []string{PermAll}}
	a, cookies := buildAuthWithSession(t, u)

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.RequireSessionAuth(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithCookies(cookies))

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if !called || captured == nil || captured.Email != u.Email {
		t.Errorf("user not correctly injected: called=%v captured=%v", called, captured)
	}
}

// ── RequireSession — rejects API keys ─────────────────────────────────────────

func TestRequireSession_ValidAPIKey_Returns401(t *testing.T) {
	u := &User{Email: "apikey:ci", Provider: "apikey", Role: "admin"}
	a := buildAuthWithAPIKey(t, u, []string{PermAll})

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.RequireSession("manage")(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithBearer("ah_key"))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401 (API keys rejected by RequireSession)", w.Code)
	}
	if called {
		t.Error("next handler should not have been called")
	}
}

func TestRequireSession_ValidSessionWithPerm_CallsNext(t *testing.T) {
	u := &User{Email: "admin@example.com", Role: "admin", permissions: []string{PermAll}}
	a, cookies := buildAuthWithSession(t, u)

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.RequireSession("manage")(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithCookies(cookies))

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if !called {
		t.Error("next handler was not called")
	}
}

func TestRequireSession_ValidSessionWithoutPerm_Returns403(t *testing.T) {
	u := &User{Email: "viewer@example.com", Role: "viewer", permissions: []string{"view"}}
	a, cookies := buildAuthWithSession(t, u)

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.RequireSession("manage")(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithCookies(cookies))

	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
	if called {
		t.Error("next handler should not have been called")
	}
}

// ── No APIKeyValidator configured — original behaviour preserved ───────────────

func TestRequireAuth_NoValidator_APIKeyInHeader_Returns401(t *testing.T) {
	// No keyValidator set — even with a bearer token, fall through to session.
	a := &Auth{store: newCookieStore("test-secret-that-is-32-bytes-ok!", false), rbacProvider: &rbac{}}

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.RequireAuth(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithBearer("ah_somekey"))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", w.Code)
	}
	if called {
		t.Error("next handler should not have been called")
	}
}
