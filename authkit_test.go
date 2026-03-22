package authkit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── New() validation tests ──────────────────────────────────────────────────

func TestNew_ShortSecret_ReturnsError(t *testing.T) {
	_, err := New(Config{
		SessionSecret: "too-short",
		Providers:     []ProviderConfig{{Name: "github", ClientID: "id", ClientSecret: "s"}},
		CallbackBaseURL: "https://example.com",
	})
	if err == nil {
		t.Fatal("expected error for short secret")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("error should mention 32 bytes: %v", err)
	}
}

func TestNew_EmptyCallbackBaseURL_OAuthMode(t *testing.T) {
	_, err := New(Config{
		SessionSecret: "test-secret-that-is-at-least-32-bytes-long!!",
		Providers:     []ProviderConfig{{Name: "github", ClientID: "id", ClientSecret: "s"}},
	})
	if err == nil {
		t.Fatal("expected error for empty CallbackBaseURL in OAuth mode")
	}
	if !strings.Contains(err.Error(), "CallbackBaseURL") {
		t.Errorf("error should mention CallbackBaseURL: %v", err)
	}
}

func TestNew_InvalidCallbackBaseURL(t *testing.T) {
	_, err := New(Config{
		SessionSecret:   "test-secret-that-is-at-least-32-bytes-long!!",
		CallbackBaseURL: "not a url",
		Providers:       []ProviderConfig{{Name: "github", ClientID: "id", ClientSecret: "s"}},
	})
	if err == nil {
		t.Fatal("expected error for invalid CallbackBaseURL")
	}
	if !strings.Contains(err.Error(), "not a valid URL") {
		t.Errorf("error should mention invalid URL: %v", err)
	}
}

func TestNew_NoProviders_OAuthMode(t *testing.T) {
	_, err := New(Config{
		SessionSecret:   "test-secret-that-is-at-least-32-bytes-long!!",
		CallbackBaseURL: "https://example.com",
	})
	if err == nil {
		t.Fatal("expected error when no providers in OAuth mode")
	}
	if !strings.Contains(err.Error(), "provider") {
		t.Errorf("error should mention provider: %v", err)
	}
}

func TestNew_OAuthMode_Success(t *testing.T) {
	auth, err := New(Config{
		SessionSecret:   "test-secret-that-is-at-least-32-bytes-long!!",
		CallbackBaseURL: "https://example.com",
		SecureCookie:    true,
		Providers:       []ProviderConfig{{Name: "github", ClientID: "id", ClientSecret: "s"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil Auth")
	}
	if auth.cfg.AfterLoginURL != "/" {
		t.Errorf("AfterLoginURL default: got %q, want /", auth.cfg.AfterLoginURL)
	}
	if auth.cfg.AfterLogoutURL != "/" {
		t.Errorf("AfterLogoutURL default: got %q, want /", auth.cfg.AfterLogoutURL)
	}
}

func TestNew_CustomAfterURLs(t *testing.T) {
	auth, err := New(Config{
		SessionSecret:   "test-secret-that-is-at-least-32-bytes-long!!",
		CallbackBaseURL: "https://example.com",
		SecureCookie:    true,
		Providers:       []ProviderConfig{{Name: "github", ClientID: "id", ClientSecret: "s"}},
		AfterLoginURL:   "/dashboard",
		AfterLogoutURL:  "/goodbye",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if auth.cfg.AfterLoginURL != "/dashboard" {
		t.Errorf("AfterLoginURL: got %q, want /dashboard", auth.cfg.AfterLoginURL)
	}
	if auth.cfg.AfterLogoutURL != "/goodbye" {
		t.Errorf("AfterLogoutURL: got %q, want /goodbye", auth.cfg.AfterLogoutURL)
	}
}

func TestNew_InvalidRBACPolicy(t *testing.T) {
	// Create a temporary invalid YAML file.
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte(":::invalid yaml"), 0644)

	_, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:  true,
		UserStore:     newMockUserStore(),
		RBAC:          RBACConfig{FilePath: path},
	})
	if err == nil {
		t.Fatal("expected error for invalid RBAC policy")
	}
	if !strings.Contains(err.Error(), "RBAC") {
		t.Errorf("error should mention RBAC: %v", err)
	}
}

func TestNew_UnsupportedProvider(t *testing.T) {
	_, err := New(Config{
		SessionSecret:   "test-secret-that-is-at-least-32-bytes-long!!",
		CallbackBaseURL: "https://example.com",
		SecureCookie:    true,
		Providers:       []ProviderConfig{{Name: "twitter", ClientID: "id", ClientSecret: "s"}},
	})
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error should mention unsupported: %v", err)
	}
}

func TestNew_BothMode_Success(t *testing.T) {
	auth, err := New(Config{
		Mode:            AuthModeBoth,
		SessionSecret:   "test-secret-that-is-at-least-32-bytes-long!!",
		CallbackBaseURL: "https://example.com",
		SecureCookie:    true,
		Providers:       []ProviderConfig{{Name: "github", ClientID: "id", ClientSecret: "s"}},
		UserStore:       newMockUserStore(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil Auth")
	}
}

func TestNew_DefaultLoggerUsedWhenNil(t *testing.T) {
	auth, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:  true,
		UserStore:     newMockUserStore(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if auth.log == nil {
		t.Error("expected non-nil logger")
	}
}

// ── WatchRBAC tests ─────────────────────────────────────────────────────────

func TestWatchRBAC_ReloadsPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	// Write initial policy.
	initial := `
roles:
  viewer:
    permissions: ["view"]
    members:
      - alice@example.com
`
	os.WriteFile(path, []byte(initial), 0644)

	auth, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:  true,
		UserStore:     newMockUserStore(),
		RBAC:          RBACConfig{FilePath: path},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Verify initial state.
	role, _ := auth.rbac.roleFor("alice@example.com")
	if role != "viewer" {
		t.Fatalf("initial role: got %q, want viewer", role)
	}

	// Update the policy file.
	updated := `
roles:
  admin:
    permissions: ["*"]
    members:
      - alice@example.com
`
	os.WriteFile(path, []byte(updated), 0644)

	// Run WatchRBAC with a short interval.
	ctx, cancel := context.WithCancel(context.Background())
	go auth.WatchRBAC(ctx, 50*time.Millisecond)

	// Wait for at least one reload.
	time.Sleep(200 * time.Millisecond)
	cancel()

	role, _ = auth.rbac.roleFor("alice@example.com")
	if role != "admin" {
		t.Errorf("reloaded role: got %q, want admin", role)
	}
}

func TestWatchRBAC_KeepsOldPolicyOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	initial := `
roles:
  viewer:
    permissions: ["view"]
    members:
      - alice@example.com
`
	os.WriteFile(path, []byte(initial), 0644)

	auth, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:  true,
		UserStore:     newMockUserStore(),
		RBAC:          RBACConfig{FilePath: path},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Corrupt the file.
	os.WriteFile(path, []byte(":::invalid yaml"), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	go auth.WatchRBAC(ctx, 50*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	cancel()

	// Old policy should be preserved.
	role, _ := auth.rbac.roleFor("alice@example.com")
	if role != "viewer" {
		t.Errorf("role after bad reload: got %q, want viewer (old policy kept)", role)
	}
}

func TestWatchRBAC_StopsOnCancel(t *testing.T) {
	auth := &Auth{
		cfg:  Config{RBAC: RBACConfig{}},
		rbac: newRBAC(Policy{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		auth.WatchRBAC(ctx, 10*time.Millisecond)
		close(done)
	}()

	cancel()
	select {
	case <-done:
		// Success — goroutine exited.
	case <-time.After(2 * time.Second):
		t.Error("WatchRBAC did not stop after context cancellation")
	}
}
