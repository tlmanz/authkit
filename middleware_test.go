package authkit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// sentinelHandler records whether it was called and captures the user from ctx.
func sentinelHandler(called *bool, captured **User) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		*captured = UserFromCtx(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

// buildAuthWithSession creates an Auth instance with a CookieStore and saves u
// to a session, returning the Set-Cookie headers so tests can replay them.
func buildAuthWithSession(t *testing.T, u *User) (*Auth, []*http.Cookie) {
	t.Helper()
	store := newCookieStore("middleware-test-secret-32-bytes!!", false)
	a := &Auth{store: store, rbac: &rbac{}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := saveUserToSession(store, w, r, u); err != nil {
		t.Fatalf("saveUserToSession: %v", err)
	}
	return a, w.Result().Cookies()
}

func requestWithCookies(cookies []*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

// ── RequireAuth ────────────────────────────────────────────────────────────────

func TestRequireAuth_NoSession_Returns401(t *testing.T) {
	a := &Auth{store: newCookieStore("test-secret-that-is-32-bytes-ok!", false)}
	called := false
	var captured *User

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	a.RequireAuth(sentinelHandler(&called, &captured)).ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler should not have been called")
	}
}

func TestRequireAuth_ValidSession_CallsNext(t *testing.T) {
	u := &User{Email: "alice@example.com", Role: "admin", permissions: []string{PermAll}}
	a, cookies := buildAuthWithSession(t, u)

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.RequireAuth(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithCookies(cookies))

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

func TestRequireAuth_InjectsUserIntoContext(t *testing.T) {
	u := &User{Email: "ctx@example.com", Role: "viewer", permissions: []string{"view"}}
	a, cookies := buildAuthWithSession(t, u)

	var fromCtx *User
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fromCtx = UserFromCtx(r.Context())
	})

	a.RequireAuth(handler).ServeHTTP(httptest.NewRecorder(), requestWithCookies(cookies))

	if fromCtx == nil {
		t.Fatal("user not injected into context")
	}
	if fromCtx.Email != u.Email {
		t.Errorf("ctx user email: got %q, want %q", fromCtx.Email, u.Email)
	}
}

// ── Require(permission) ────────────────────────────────────────────────────────

func TestRequire_NoSession_Returns401(t *testing.T) {
	a := &Auth{store: newCookieStore("test-secret-that-is-32-bytes-ok!", false)}
	called := false
	var captured *User

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	a.Require("view")(sentinelHandler(&called, &captured)).ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler should not have been called")
	}
}

func TestRequire_InsufficientPermission_Returns403(t *testing.T) {
	u := &User{Email: "viewer@example.com", Role: "viewer", permissions: []string{"view"}}
	a, cookies := buildAuthWithSession(t, u)

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.Require("manage")(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithCookies(cookies))

	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
	if called {
		t.Error("next handler should not have been called")
	}
}

func TestRequire_SufficientPermission_CallsNext(t *testing.T) {
	u := &User{Email: "dev@example.com", Role: "developer", permissions: []string{"view", "upload"}}
	a, cookies := buildAuthWithSession(t, u)

	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.Require("upload")(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithCookies(cookies))

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

func TestRequire_WildcardPermission_PassesAllChecks(t *testing.T) {
	u := &User{Email: "admin@example.com", Role: "admin", permissions: []string{PermAll}}
	a, cookies := buildAuthWithSession(t, u)

	for _, perm := range []string{"view", "upload", "manage", "custom.perm"} {
		called := false
		var captured *User
		w := httptest.NewRecorder()
		a.Require(perm)(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithCookies(cookies))

		if w.Code != http.StatusOK {
			t.Errorf("perm=%q: status got %d, want %d", perm, w.Code, http.StatusOK)
		}
		if !called {
			t.Errorf("perm=%q: next handler not called", perm)
		}
	}
}

func TestRequire_CustomPermission(t *testing.T) {
	u := &User{Email: "deploy@example.com", permissions: []string{"deploy"}}
	a, cookies := buildAuthWithSession(t, u)

	// Should pass "deploy".
	called := false
	var captured *User
	w := httptest.NewRecorder()
	a.Require("deploy")(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithCookies(cookies))
	if w.Code != http.StatusOK || !called {
		t.Errorf("custom perm 'deploy': got status %d called=%v", w.Code, called)
	}

	// Should fail "manage".
	called = false
	w = httptest.NewRecorder()
	a.Require("manage")(sentinelHandler(&called, &captured)).ServeHTTP(w, requestWithCookies(cookies))
	if w.Code != http.StatusForbidden || called {
		t.Errorf("custom perm 'manage': got status %d called=%v", w.Code, called)
	}
}
