package authkit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// ── Mock UserStore ───────────────────────────────────────────────────────────

// failingUserStore always returns an internal error (not a sentinel error).
type failingUserStore struct{}

func (failingUserStore) CreateUser(_ context.Context, _, _, _ string) error {
	return fmt.Errorf("database connection failed")
}
func (failingUserStore) GetUserByEmail(_ context.Context, _ string) (*PasswordUser, error) {
	return nil, fmt.Errorf("database connection failed")
}

type mockUserStore struct {
	mu    sync.RWMutex
	users map[string]*PasswordUser
}

func newMockUserStore() *mockUserStore {
	return &mockUserStore{users: make(map[string]*PasswordUser)}
}

func (m *mockUserStore) CreateUser(_ context.Context, email, name, hashed string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.users[email]; exists {
		return ErrUserExists
	}
	m.users[email] = &PasswordUser{Email: email, Name: name, HashedPassword: hashed}
	return nil
}

func (m *mockUserStore) GetUserByEmail(_ context.Context, email string) (*PasswordUser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[email]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const testSecret = "password-handler-test-secret-32b!"

func buildPasswordAuth(t *testing.T, store *mockUserStore) *Auth {
	t.Helper()
	return &Auth{
		cfg: Config{
			Mode:          AuthModePassword,
			SessionSecret: testSecret,
			AfterLoginURL: "/dashboard",
			UserStore:     store,
		},
		store: newCookieStore(testSecret, false),
		rbac:  newRBAC(Policy{}),
	}
}

func buildPasswordAuthWithRBAC(t *testing.T, store *mockUserStore, policy Policy) *Auth {
	t.Helper()
	return &Auth{
		cfg: Config{
			Mode:          AuthModePassword,
			SessionSecret: testSecret,
			AfterLoginURL: "/dashboard",
			UserStore:     store,
		},
		store: newCookieStore(testSecret, false),
		rbac:  newRBAC(policy),
	}
}

func postForm(path string, values url.Values) *http.Request {
	body := strings.NewReader(values.Encode())
	r := httptest.NewRequest(http.MethodPost, path, body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// ── Register tests ───────────────────────────────────────────────────────────

func TestRegister_Success(t *testing.T) {
	a := buildPasswordAuth(t, newMockUserStore())

	w := httptest.NewRecorder()
	r := postForm("/auth/register", url.Values{
		"email":    {"alice@example.com"},
		"name":     {"Alice"},
		"password": {"strong-password-123"},
	})
	a.Register(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusSeeOther)
	}
	if loc := w.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("redirect: got %q, want /dashboard", loc)
	}
}

func TestRegister_SetsSession(t *testing.T) {
	store := newMockUserStore()
	a := buildPasswordAuth(t, store)

	w := httptest.NewRecorder()
	r := postForm("/auth/register", url.Values{
		"email":    {"bob@example.com"},
		"name":     {"Bob"},
		"password": {"strong-password-123"},
	})
	a.Register(w, r)

	// Replay cookies to verify session was created.
	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		r2.AddCookie(c)
	}

	u, err := userFromSession(a.store, r2)
	if err != nil {
		t.Fatalf("userFromSession: %v", err)
	}
	if u == nil {
		t.Fatal("expected user in session after registration")
	}
	if u.Email != "bob@example.com" {
		t.Errorf("email: got %q, want bob@example.com", u.Email)
	}
	if u.Provider != "password" {
		t.Errorf("provider: got %q, want password", u.Provider)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	store := newMockUserStore()
	a := buildPasswordAuth(t, store)

	// Register first time.
	w := httptest.NewRecorder()
	a.Register(w, postForm("/auth/register", url.Values{
		"email":    {"alice@example.com"},
		"password": {"strong-password-123"},
	}))

	// Register same email again.
	w = httptest.NewRecorder()
	a.Register(w, postForm("/auth/register", url.Values{
		"email":    {"alice@example.com"},
		"password": {"different-password-456"},
	}))

	if w.Code != http.StatusConflict {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestRegister_InvalidEmail(t *testing.T) {
	a := buildPasswordAuth(t, newMockUserStore())

	w := httptest.NewRecorder()
	a.Register(w, postForm("/auth/register", url.Values{
		"email":    {"not-an-email"},
		"password": {"strong-password-123"},
	}))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	a := buildPasswordAuth(t, newMockUserStore())

	w := httptest.NewRecorder()
	a.Register(w, postForm("/auth/register", url.Values{
		"email":    {"alice@example.com"},
		"password": {"short"},
	}))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRegister_OAuthModeDisabled(t *testing.T) {
	a := &Auth{
		cfg: Config{Mode: AuthModeOAuth},
	}

	w := httptest.NewRecorder()
	a.Register(w, postForm("/auth/register", url.Values{
		"email":    {"alice@example.com"},
		"password": {"strong-password-123"},
	}))

	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestRegister_RBACRoleAssigned(t *testing.T) {
	store := newMockUserStore()
	policy := Policy{
		Roles: map[string]RolePolicy{
			"admin": {
				Permissions: []string{PermAll},
				Members:     []string{"admin@example.com"},
			},
		},
	}
	a := buildPasswordAuthWithRBAC(t, store, policy)

	w := httptest.NewRecorder()
	a.Register(w, postForm("/auth/register", url.Values{
		"email":    {"admin@example.com"},
		"password": {"strong-password-123"},
	}))

	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		r2.AddCookie(c)
	}

	u, _ := userFromSession(a.store, r2)
	if u == nil {
		t.Fatal("expected user in session")
	}
	if u.Role != "admin" {
		t.Errorf("role: got %q, want admin", u.Role)
	}
	if !u.Can("manage") {
		t.Error("admin should have manage permission")
	}
}

// ── Login tests ──────────────────────────────────────────────────────────────

func TestLogin_Success(t *testing.T) {
	store := newMockUserStore()
	a := buildPasswordAuth(t, store)

	// Seed a user.
	hashed, _ := HashPassword("correct-password")
	store.users["alice@example.com"] = &PasswordUser{
		Email:          "alice@example.com",
		Name:           "Alice",
		HashedPassword: hashed,
	}

	w := httptest.NewRecorder()
	a.Login(w, postForm("/auth/login", url.Values{
		"email":    {"alice@example.com"},
		"password": {"correct-password"},
	}))

	if w.Code != http.StatusSeeOther {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusSeeOther)
	}
	if loc := w.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("redirect: got %q, want /dashboard", loc)
	}
}

func TestLogin_SessionContainsUser(t *testing.T) {
	store := newMockUserStore()
	a := buildPasswordAuth(t, store)

	hashed, _ := HashPassword("correct-password")
	store.users["bob@example.com"] = &PasswordUser{
		Email:          "bob@example.com",
		Name:           "Bob",
		HashedPassword: hashed,
	}

	w := httptest.NewRecorder()
	a.Login(w, postForm("/auth/login", url.Values{
		"email":    {"bob@example.com"},
		"password": {"correct-password"},
	}))

	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		r2.AddCookie(c)
	}

	u, err := userFromSession(a.store, r2)
	if err != nil {
		t.Fatalf("userFromSession: %v", err)
	}
	if u == nil {
		t.Fatal("expected user in session after login")
	}
	if u.Email != "bob@example.com" {
		t.Errorf("email: got %q, want bob@example.com", u.Email)
	}
	if u.Name != "Bob" {
		t.Errorf("name: got %q, want Bob", u.Name)
	}
	if u.Provider != "password" {
		t.Errorf("provider: got %q, want password", u.Provider)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	store := newMockUserStore()
	a := buildPasswordAuth(t, store)

	hashed, _ := HashPassword("correct-password")
	store.users["alice@example.com"] = &PasswordUser{
		Email:          "alice@example.com",
		HashedPassword: hashed,
	}

	w := httptest.NewRecorder()
	a.Login(w, postForm("/auth/login", url.Values{
		"email":    {"alice@example.com"},
		"password": {"wrong-password"},
	}))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestLogin_UnknownUser(t *testing.T) {
	a := buildPasswordAuth(t, newMockUserStore())

	w := httptest.NewRecorder()
	a.Login(w, postForm("/auth/login", url.Values{
		"email":    {"nobody@example.com"},
		"password": {"any-password"},
	}))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	// Ensure error message is the same as wrong-password (no user enumeration).
	body := w.Body.String()
	if !strings.Contains(body, "invalid email or password") {
		t.Errorf("body should say 'invalid email or password', got: %q", body)
	}
}

func TestLogin_OAuthModeDisabled(t *testing.T) {
	a := &Auth{
		cfg: Config{Mode: AuthModeOAuth},
	}

	w := httptest.NewRecorder()
	a.Login(w, postForm("/auth/login", url.Values{
		"email":    {"alice@example.com"},
		"password": {"any-password"},
	}))

	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusNotFound)
	}
}

// ── Mode validation tests ────────────────────────────────────────────────────

func TestNew_DefaultModeIsOAuth(t *testing.T) {
	// Empty Mode should default to OAuth and require CallbackBaseURL/providers.
	_, err := New(Config{
		SessionSecret:   "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:    true,
		CallbackBaseURL: "https://example.com",
	})
	if err == nil {
		t.Fatal("expected error when no providers given in default (OAuth) mode")
	}
	if !strings.Contains(err.Error(), "provider") {
		t.Errorf("error should mention providers: %v", err)
	}
}

func TestNew_PasswordMode_NoProviders_OK(t *testing.T) {
	_, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:  true,
		UserStore:     newMockUserStore(),
	})
	if err != nil {
		t.Fatalf("password mode should not require providers: %v", err)
	}
}

func TestNew_PasswordMode_RequiresUserStore(t *testing.T) {
	_, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:  true,
	})
	if err == nil {
		t.Fatal("expected error when UserStore is nil in password mode")
	}
	if !strings.Contains(err.Error(), "UserStore") {
		t.Errorf("error should mention UserStore: %v", err)
	}
}

func TestNew_BothMode_RequiresUserStoreAndProviders(t *testing.T) {
	// Missing UserStore.
	_, err := New(Config{
		Mode:            AuthModeBoth,
		SessionSecret:   "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:    true,
		CallbackBaseURL: "https://example.com",
		Providers: []ProviderConfig{
			{Name: "github", ClientID: "id", ClientSecret: "secret"},
		},
	})
	if err == nil {
		t.Fatal("expected error when UserStore is nil in both mode")
	}

	// Missing providers.
	_, err = New(Config{
		Mode:            AuthModeBoth,
		SessionSecret:   "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:    true,
		CallbackBaseURL: "https://example.com",
		UserStore:       newMockUserStore(),
	})
	if err == nil {
		t.Fatal("expected error when no providers in both mode")
	}
}

func TestNew_PasswordMode_NoCallbackBaseURL_OK(t *testing.T) {
	_, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:  true,
		UserStore:     newMockUserStore(),
	})
	if err != nil {
		t.Fatalf("password mode should not require CallbackBaseURL: %v", err)
	}
}

// ── Edge case: internal store error (not sentinel) ──────────────────────────

func TestRegister_InternalStoreError(t *testing.T) {
	a := &Auth{
		cfg: Config{
			Mode:          AuthModePassword,
			SessionSecret: testSecret,
			AfterLoginURL: "/dashboard",
			UserStore:     failingUserStore{},
		},
		store: newCookieStore(testSecret, false),
		rbac:  newRBAC(Policy{}),
		log:   defaultLogger{},
	}

	w := httptest.NewRecorder()
	a.Register(w, postForm("/auth/register", url.Values{
		"email":    {"alice@example.com"},
		"password": {"strong-password-123"},
	}))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestLogin_InternalStoreError(t *testing.T) {
	a := &Auth{
		cfg: Config{
			Mode:          AuthModePassword,
			SessionSecret: testSecret,
			AfterLoginURL: "/dashboard",
			UserStore:     failingUserStore{},
		},
		store: newCookieStore(testSecret, false),
		rbac:  newRBAC(Policy{}),
		log:   defaultLogger{},
	}

	w := httptest.NewRecorder()
	a.Login(w, postForm("/auth/login", url.Values{
		"email":    {"alice@example.com"},
		"password": {"any-password"},
	}))

	// failingUserStore returns a non-sentinel error, so the dummy bcrypt
	// compare runs and 401 is returned (same as unknown user).
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRegister_BothMode_Works(t *testing.T) {
	a := &Auth{
		cfg: Config{
			Mode:          AuthModeBoth,
			SessionSecret: testSecret,
			AfterLoginURL: "/dashboard",
			UserStore:     newMockUserStore(),
		},
		store: newCookieStore(testSecret, false),
		rbac:  newRBAC(Policy{}),
		log:   defaultLogger{},
	}

	w := httptest.NewRecorder()
	a.Register(w, postForm("/auth/register", url.Values{
		"email":    {"alice@example.com"},
		"password": {"strong-password-123"},
	}))

	if w.Code != http.StatusSeeOther {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusSeeOther)
	}
}

func TestLogin_BothMode_Works(t *testing.T) {
	store := newMockUserStore()
	hashed, _ := HashPassword("correct-password")
	store.users["alice@example.com"] = &PasswordUser{
		Email:          "alice@example.com",
		Name:           "Alice",
		HashedPassword: hashed,
	}

	a := &Auth{
		cfg: Config{
			Mode:          AuthModeBoth,
			SessionSecret: testSecret,
			AfterLoginURL: "/dashboard",
			UserStore:     store,
		},
		store: newCookieStore(testSecret, false),
		rbac:  newRBAC(Policy{}),
		log:   defaultLogger{},
	}

	w := httptest.NewRecorder()
	a.Login(w, postForm("/auth/login", url.Values{
		"email":    {"alice@example.com"},
		"password": {"correct-password"},
	}))

	if w.Code != http.StatusSeeOther {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusSeeOther)
	}
}

func TestRegister_EmailNormalized(t *testing.T) {
	store := newMockUserStore()
	a := buildPasswordAuth(t, store)

	w := httptest.NewRecorder()
	a.Register(w, postForm("/auth/register", url.Values{
		"email":    {"  Alice@Example.COM  "},
		"password": {"strong-password-123"},
	}))

	if w.Code != http.StatusSeeOther {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusSeeOther)
	}

	// Verify stored email is normalized.
	if _, ok := store.users["alice@example.com"]; !ok {
		t.Error("email should be normalized to lowercase")
	}
}
