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
//	mux.Handle("POST /api/projects", auth.Require("projects:write")(createHandler))
package authkit

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

// APIKeyValidator validates a raw API key string and returns the associated
// user. Implementations look up the key hash in a store and return a *User
// with Email, Name, Provider, and Role populated. Authkit then resolves the
// user's permissions from the RBAC policy based on the returned Role.
//
// Return nil, nil when the key is not found, expired, or inactive.
// Return nil, err only for unexpected infrastructure failures.
type APIKeyValidator interface {
	ValidateKey(ctx context.Context, rawKey string) (*User, error)
}

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

	// Providers is the list of OAuth providers to enable using the built-in
	// convenience wrappers (github, google, gitlab).
	// Required when Mode is AuthModeOAuth or AuthModeBoth, unless GothProviders
	// is supplied instead.
	Providers []ProviderConfig

	// GothProviders is a list of pre-constructed goth.Provider values.
	// Use this to enable any of the 80+ providers that goth supports beyond the
	// three built-in convenience wrappers. Import the provider package you need
	// from github.com/markbates/goth/providers/*, construct the provider, and
	// pass it here. It is merged with any providers built from Providers.
	//
	// Example — add Spotify and Discord:
	//
	//	import (
	//	    "github.com/markbates/goth/providers/spotify"
	//	    "github.com/markbates/goth/providers/discord"
	//	)
	//
	//	GothProviders: []goth.Provider{
	//	    spotify.New(clientID, secret, callbackURL, "user-read-email"),
	//	    discord.New(clientID, secret, callbackURL, "identify", "email"),
	//	},
	GothProviders []goth.Provider

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

	// Logger is used for diagnostic output. If nil, logs are written to the
	// standard library log package.
	Logger Logger

	// APIKeyValidator enables API key authentication alongside OAuth sessions.
	// When set, Require and RequireAuth middleware check the Authorization:
	// Bearer (or X-API-Key) header first. RequireSession and RequireSessionAuth
	// skip API key auth entirely (session-only routes).
	// If nil, API key auth is disabled and only sessions are accepted.
	APIKeyValidator APIKeyValidator

	// AuditSink receives security audit events (login, logout, refresh, revoke,
	// 2fa_*, role_change, permission_change, impersonate). If nil, a
	// NopAuditSink is installed so authkit can emit unconditionally.
	AuditSink AuditSink

	// LivePermissionResolution makes Require/RequireAuth re-resolve a session
	// user's permissions from the PolicyProvider on every request (through a
	// short TTL cache), so role and permission changes take effect within the
	// cache window rather than only on next login. Multi-tenant deploys want
	// this on; single-shop deploys can leave it off (cheaper login-time cache).
	// API-key credentials always resolve live regardless of this flag.
	LivePermissionResolution bool

	// PermissionCacheTTL bounds how stale a live-resolved permission set may be.
	// Defaults to 30s when LivePermissionResolution is enabled.
	PermissionCacheTTL time.Duration
}

// Auth is the central object. Create one with New() and attach its methods as
// HTTP handlers and middleware.
type Auth struct {
	cfg          Config
	store        sessions.Store
	rbacProvider PolicyProvider
	log          Logger
	keyValidator APIKeyValidator
	audit        AuditSink
	permCache    *permCache
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
		if len(cfg.Providers) == 0 && len(cfg.GothProviders) == 0 {
			return nil, fmt.Errorf("authkit: at least one provider is required when OAuth is enabled (use Providers or GothProviders)")
		}
	}

	// Password-specific validation.
	passwordEnabled := cfg.Mode == AuthModePassword || cfg.Mode == AuthModeBoth
	if passwordEnabled && cfg.UserStore == nil {
		return nil, fmt.Errorf("authkit: UserStore is required when password auth is enabled")
	}

	if cfg.Logger == nil {
		cfg.Logger = defaultLogger{}
	}

	if !cfg.SecureCookie {
		cfg.Logger.Info("authkit: WARNING: SecureCookie is false — session cookies will be sent over HTTP. Set SecureCookie to true in production.")
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
		providers = append(providers, cfg.GothProviders...)
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
	provider, err := resolveProvider(cfg.RBAC)
	if err != nil {
		return nil, fmt.Errorf("authkit: load RBAC policy: %w", err)
	}

	audit := cfg.AuditSink
	if audit == nil {
		audit = NopAuditSink{}
	}

	// Permission cache backs live per-request resolution. Built only when that
	// mode is on, so the cheaper login-time path stays allocation-free.
	var pc *permCache
	if cfg.LivePermissionResolution {
		ttl := cfg.PermissionCacheTTL
		if ttl <= 0 {
			ttl = 30 * time.Second
		}
		pc = newPermCache(ttl)
	}

	return &Auth{cfg: cfg, store: store, rbacProvider: provider, log: cfg.Logger, keyValidator: cfg.APIKeyValidator, audit: audit, permCache: pc}, nil
}

// WatchRBAC starts a background goroutine that reloads the RBAC policy file
// every interval. It stops when ctx is cancelled. This allows operators to
// update the policy without restarting the service.
//
// Example:
//
//	go auth.WatchRBAC(ctx, 30*time.Second)
func (a *Auth) WatchRBAC(ctx context.Context, interval time.Duration) {
	reloader, ok := a.rbacProvider.(PolicyReloader)
	if !ok {
		a.log.Info("authkit: WatchRBAC: provider does not implement PolicyReloader — live reloading is disabled")
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := reloader.Reload(); err != nil {
				// Keep the old policy on error — don't lock users out.
				a.log.Error("authkit: RBAC reload failed: %v", err)
			}
		}
	}
}
