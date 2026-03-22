// Package authkit provides plug-and-play OAuth authentication with RBAC for
// Go HTTP services. It wraps markbates/goth for the OAuth dance, gorilla/sessions
// for encrypted cookie sessions, and a YAML-based role policy for access control.
//
// Quick start:
//
//	auth, err := authkit.New(authkit.Config{
//	    Providers: []authkit.ProviderConfig{
//	        {Name: "github", ClientID: os.Getenv("GITHUB_CLIENT_ID"), ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET")},
//	    },
//	    CallbackBaseURL: "https://example.com",
//	    SessionSecret:   os.Getenv("SESSION_SECRET"),
//	    RBAC: authkit.RBACConfig{FilePath: "policy.yaml"},
//	})
//
//	mux.Handle("GET /auth/{provider}",          http.HandlerFunc(auth.BeginAuth))
//	mux.Handle("GET /auth/{provider}/callback", http.HandlerFunc(auth.Callback))
//	mux.Handle("POST /auth/logout",             http.HandlerFunc(auth.Logout))
//	mux.Handle("GET /auth/me",                  http.HandlerFunc(auth.Me))
//
//	// Protected routes
//	mux.Handle("GET /api/reports", auth.RequireAuth(reportsHandler))
//	mux.Handle("POST /api/projects", auth.Require(authkit.PermManage)(createHandler))
package authkit

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

// AuthMode controls which authentication methods are enabled.
type AuthMode string

const (
	// AuthModeOAuth enables only OAuth providers (default).
	AuthModeOAuth AuthMode = "oauth"

	// AuthModePassword enables only email/password authentication.
	AuthModePassword AuthMode = "password"

	// AuthModeBoth enables both OAuth and email/password authentication.
	AuthModeBoth AuthMode = "both"
)

// Config holds all configuration needed to create an Auth instance.
type Config struct {
	// Mode controls which authentication methods are enabled.
	// Defaults to AuthModeOAuth for backward compatibility.
	Mode AuthMode

	// Providers is the list of OAuth providers to enable.
	// Required when Mode is AuthModeOAuth or AuthModeBoth.
	Providers []ProviderConfig

	// CallbackBaseURL is the externally-reachable base URL of the service
	// (e.g. "https://example.com"). The OAuth callback URLs are derived as
	// {CallbackBaseURL}/auth/{provider}/callback.
	// Required when Mode is AuthModeOAuth or AuthModeBoth.
	CallbackBaseURL string

	// SessionSecret is used to sign and encrypt session cookies.
	// Must be at least 32 bytes of random data.
	SessionSecret string

	// SecureCookie controls the Secure flag on session cookies.
	// Set to true in production (HTTPS only). Defaults to false.
	SecureCookie bool

	// AfterLoginURL is the URL the user is redirected to after a successful login.
	// Defaults to "/".
	AfterLoginURL string

	// AfterLogoutURL is the URL the user is redirected to after logout.
	// Defaults to "/".
	AfterLogoutURL string

	// RBAC configures the role policy. If FilePath is empty, all authenticated
	// users receive an empty role with no permissions.
	RBAC RBACConfig

	// UserStore provides user persistence for password-based authentication.
	// Required when Mode is AuthModePassword or AuthModeBoth.
	UserStore UserStore

	// PasswordPolicy configures password validation rules.
	// If nil, defaults are used (minimum 8 characters).
	PasswordPolicy *PasswordPolicy
}

// Auth is the central object. Create one with New() and attach its methods as
// HTTP handlers and middleware.
type Auth struct {
	cfg   Config
	store sessions.Store
	rbac  *rbac
}

// New validates the config, registers the OAuth providers with goth, loads the
// RBAC policy, and returns a ready-to-use Auth instance.
func New(cfg Config) (*Auth, error) {
	// Default mode for backward compatibility.
	if cfg.Mode == "" {
		cfg.Mode = AuthModeOAuth
	}

	// SessionSecret is always required.
	if len(cfg.SessionSecret) < 32 {
		return nil, fmt.Errorf("authkit: SessionSecret must be at least 32 bytes, got %d", len(cfg.SessionSecret))
	}

	// OAuth-specific validation.
	oauthEnabled := cfg.Mode == AuthModeOAuth || cfg.Mode == AuthModeBoth
	if oauthEnabled {
		if cfg.CallbackBaseURL == "" {
			return nil, fmt.Errorf("authkit: CallbackBaseURL is required when OAuth is enabled")
		}
		if _, err := url.ParseRequestURI(cfg.CallbackBaseURL); err != nil {
			return nil, fmt.Errorf("authkit: CallbackBaseURL is not a valid URL: %w", err)
		}
		if len(cfg.Providers) == 0 {
			return nil, fmt.Errorf("authkit: at least one provider is required when OAuth is enabled")
		}
	}

	// Password-specific validation.
	passwordEnabled := cfg.Mode == AuthModePassword || cfg.Mode == AuthModeBoth
	if passwordEnabled && cfg.UserStore == nil {
		return nil, fmt.Errorf("authkit: UserStore is required when password auth is enabled")
	}

	if !cfg.SecureCookie {
		log.Println("authkit: WARNING: SecureCookie is false — session cookies will be sent over HTTP. Set SecureCookie to true in production.")
	}

	if cfg.AfterLoginURL == "" {
		cfg.AfterLoginURL = "/"
	}
	if cfg.AfterLogoutURL == "" {
		cfg.AfterLogoutURL = "/"
	}

	// Build and register goth providers only when OAuth is enabled.
	if oauthEnabled {
		providers, err := buildProviders(cfg.Providers, cfg.CallbackBaseURL)
		if err != nil {
			return nil, err
		}
		goth.UseProviders(providers...)

		// Override gothic's provider name extraction to use Go 1.22+ path values
		// instead of gorilla/mux query params.
		gothic.GetProviderName = func(r *http.Request) (string, error) {
			name := r.PathValue("provider")
			if name == "" {
				return "", fmt.Errorf("authkit: provider not found in URL path")
			}
			return name, nil
		}
	}

	// Session store.
	store := newCookieStore(cfg.SessionSecret, cfg.SecureCookie)
	if oauthEnabled {
		gothic.Store = store
	}

	// RBAC policy.
	r, err := loadRBAC(cfg.RBAC)
	if err != nil {
		return nil, fmt.Errorf("authkit: load RBAC policy: %w", err)
	}

	return &Auth{cfg: cfg, store: store, rbac: r}, nil
}

// WatchRBAC starts a background goroutine that reloads the RBAC policy file
// every interval. It stops when ctx is cancelled. This allows operators to
// update the policy without restarting the service.
//
// Example:
//
//	go auth.WatchRBAC(ctx, 30*time.Second)
func (a *Auth) WatchRBAC(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r, err := loadRBAC(a.cfg.RBAC)
			if err != nil {
				// Keep the old policy on error — don't lock users out.
				continue
			}
			a.rbac = r
		}
	}
}
