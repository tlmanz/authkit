// Package authkit provides pluggable authentication and RBAC for Go HTTP
// services: OAuth (via markbates/goth), email/password with two-step TOTP,
// revocable server-side sessions, an OAuth2/PKCE token layer for native
// clients, API keys, device principals, a platform-operator axis for SaaS,
// and audit hooks. Storage is interface-driven — bring any database.
//
// Quick start:
//
//	auth, err := authkit.New(authkit.Config{
//	    OAuth: authkit.OAuthConfig{
//	        Providers: []authkit.ProviderConfig{
//	            {Name: "github", ClientID: os.Getenv("GITHUB_CLIENT_ID"), ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET")},
//	        },
//	        CallbackBaseURL: "https://example.com",
//	    },
//	    SessionSecret: os.Getenv("SESSION_SECRET"),
//	    RBAC:          authkit.RBACConfig{FilePath: "policy.yaml"},
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
	"log/slog"
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

// OAuthConfig groups the OAuth provider settings.
type OAuthConfig struct {
	// Providers is the list of OAuth providers to enable using the built-in
	// convenience wrappers (bitbucket, github, google, gitlab).
	// Required when Mode is AuthModeOAuth or AuthModeBoth, unless GothProviders
	// is supplied instead.
	Providers []ProviderConfig

	// GothProviders is a list of pre-constructed goth.Provider values.
	// Use this to enable any of the 80+ providers that goth supports beyond the
	// built-in convenience wrappers. Import the provider package you need from
	// github.com/markbates/goth/providers/*, construct the provider, and pass
	// it here. It is merged with any providers built from Providers.
	GothProviders []goth.Provider

	// CallbackBaseURL is the externally-reachable base URL of the service
	// (e.g. "https://example.com"). The OAuth callback URLs are derived as
	// {CallbackBaseURL}/auth/{provider}/callback.
	// Required when Mode is AuthModeOAuth or AuthModeBoth.
	CallbackBaseURL string
}

// SessionConfig groups the revocable server-side session settings.
type SessionConfig struct {
	// Store enables revocable, server-side sessions. When set, the cookie
	// carries only an opaque session ID and all identity state lives in the
	// store, allowing instant revocation and "log out everywhere". When nil,
	// authkit falls back to the legacy encrypted-cookie session.
	Store SessionStore

	// IdleTimeout expires a session after inactivity (sliding). Defaults to 30m.
	IdleTimeout time.Duration

	// AbsoluteTimeout caps a session's total lifetime regardless of activity.
	// Defaults to 24h.
	AbsoluteTimeout time.Duration
}

// CSRFConfig groups CSRF protection settings.
type CSRFConfig struct {
	// Enable turns on the CSRF middleware (signed double-submit) for
	// cookie-authenticated, state-changing requests. Token-authenticated
	// requests are always exempt.
	Enable bool

	// TrustedOrigins, when non-empty, additionally requires the Origin header
	// (when present) of unsafe requests to match one of these origins
	// (scheme://host[:port]). Defense in depth on top of the signed
	// double-submit token.
	TrustedOrigins []string
}

// TwoFactorConfig groups TOTP two-step authentication settings.
type TwoFactorConfig struct {
	// Store enables two-step auth (TOTP). When set, a user whose role is in
	// RequireForRoles must complete a TOTP challenge after the password step.
	// When nil, 2FA is disabled.
	Store TOTPStore

	// RequireForRoles lists the roles that must complete 2FA. Only consulted
	// when Store is set.
	RequireForRoles []string

	// TrustedDevices enables a "trust this device" option at the 2FA step: a
	// remembered device skips the TOTP prompt (the password is still required)
	// for TrustedDeviceTTL. The token is opaque + server-side, so it is
	// revocable (logout-everywhere, password change/reset, and disabling 2FA
	// all drop it). When nil, every 2FA login prompts for TOTP. NOT used for
	// platform admins (their 2FA is mandatory and never skipped).
	TrustedDevices TrustedDeviceStore

	// TrustedDeviceTTL bounds how long a trusted device skips 2FA. Defaults to 30d.
	TrustedDeviceTTL time.Duration
}

// TokenConfig groups the OAuth2/PKCE token layer for native clients.
type TokenConfig struct {
	// Enable turns on the OAuth2/PKCE token endpoints and the bearer-JWT
	// verifier. Requires SigningKeys and RefreshStore.
	Enable bool

	// SigningKeys is the Ed25519 rotation ring; the first key signs new access
	// tokens, all keys verify (and are published via JWKS).
	SigningKeys []SigningKey

	// AccessTTL is the access-JWT lifetime (default 15m); RefreshTTL the
	// refresh-token lifetime (default 30d).
	AccessTTL  time.Duration
	RefreshTTL time.Duration

	// RefreshStore persists opaque refresh tokens (rotation + reuse detection).
	RefreshStore RefreshTokenStore

	// AuthCodes, when set, makes PKCE authorization codes single-use: the
	// code's jti is claimed at redemption so a code cannot be exchanged twice
	// within its short TTL. Optional (nil keeps the stateless,
	// replayable-within-TTL behavior); a short-TTL store is the natural backing.
	AuthCodes AuthCodeStore

	// Issuer is the JWT `iss` claim; ClientID the public native client id
	// (also the JWT audience); RedirectURIs the allowed PKCE redirect URIs.
	Issuer       string
	ClientID     string
	RedirectURIs []string
}

// PlatformConfig groups the platform-operator (super-admin) axis — principals
// who operate the SaaS itself, across tenants, on a separate credential path.
type PlatformConfig struct {
	// Store + Policy enable the platform principal axis (separate from tenant
	// users). Platform login always requires TOTP.
	Store  PlatformAdminStore
	Policy PlatformPolicy

	// EnableImpersonation gates break-glass single-tenant access.
	EnableImpersonation bool
}

// ResetConfig groups the self-service password-reset flow.
type ResetConfig struct {
	// Store persists single-use, hashed reset tokens; Delivery sends the raw
	// token out-of-band (email/SMS). Both are required to enable the
	// ForgotPassword/ResetPassword (and platform) handlers.
	Store    PasswordResetStore
	Delivery ResetDelivery

	// TTL bounds a token's validity (default 30m).
	TTL time.Duration
}

// DeviceConfig groups the device-principal axis: headless machine clients
// (agents, kiosks, IoT devices) confined to a fixed capability allow-list.
type DeviceConfig struct {
	// Validator enables the device principal axis. When set, RequireDevice and
	// AuthenticateDevice validate opaque device tokens against it. When nil,
	// device auth is disabled.
	Validator DeviceTokenValidator

	// Capabilities is the fixed allow-list of capability strings a device
	// principal may ever hold. It is declared here, in code, precisely so a
	// device can never acquire a capability through policy data. Required when
	// Validator is set.
	Capabilities []string
}

// Config holds all configuration needed to create an Auth instance.
type Config struct {
	// Mode controls which authentication methods are enabled.
	// Defaults to AuthModeOAuth.
	Mode AuthMode

	// AppName is the product name shown to users where one is needed (e.g. the
	// issuer in authenticator apps for TOTP). Defaults to "App".
	AppName string

	// SessionSecret signs session cookies, CSRF tokens, and the short-lived
	// pending-step tokens. Must be at least 32 bytes of random data.
	SessionSecret string

	// SecureCookie controls the Secure flag (and __Host- prefix) on cookies.
	// Set to true in production (HTTPS only). Defaults to false.
	SecureCookie bool

	// CookiePrefix namespaces every cookie authkit sets (session ID, CSRF,
	// pending 2FA, platform, trusted device), so two authkit-based apps on one
	// host never collide. Defaults to "authkit".
	CookiePrefix string

	// AfterLoginURL is the URL the user is redirected to after a successful
	// browser login. Defaults to "/".
	AfterLoginURL string

	// AfterLogoutURL is the URL the user is redirected to after logout.
	// Defaults to "/".
	AfterLogoutURL string

	// Logger receives authkit's diagnostic output as structured logs. When
	// nil, slog.Default() is used. Secrets and tokens are never logged.
	Logger *slog.Logger

	// ClientIP resolves the client IP for throttling and audit events. When
	// nil, the host portion of RemoteAddr is used and forwarding headers are
	// deliberately NOT trusted — behind a reverse proxy, supply a function
	// that reads your vetted header.
	ClientIP func(*http.Request) string

	// ErrorWriter, when set, replaces authkit's JSON error envelope with the
	// host's own rendering. See the ErrCode* constants for the code catalog.
	ErrorWriter ErrorWriter

	// OAuth configures browser OAuth providers.
	// Required when Mode is AuthModeOAuth or AuthModeBoth.
	OAuth OAuthConfig

	// UserStore provides user persistence for password-based authentication.
	// Required when Mode is AuthModePassword or AuthModeBoth.
	UserStore UserStore

	// PasswordHasher hashes and verifies passwords. Defaults to bcrypt with
	// cost 12. Supply Argon2 or another KDF by implementing the interface.
	PasswordHasher PasswordHasher

	// PasswordPolicy configures password validation rules.
	// If nil, defaults are used (minimum 8 characters).
	PasswordPolicy *PasswordPolicy

	// RBAC configures the role policy. If FilePath is empty and Provider is
	// nil, all authenticated users receive an empty role with no permissions.
	RBAC RBACConfig

	// APIKeyValidator enables API key authentication alongside sessions.
	// When set, Require and RequireAuth middleware check the Authorization:
	// Bearer (or X-API-Key) header first. RequireSession and RequireSessionAuth
	// skip API key auth entirely (session-only routes).
	APIKeyValidator APIKeyValidator

	// AuditSink receives security audit events (login, logout, refresh, revoke,
	// 2fa_*, role_change, permission_change, impersonate). If nil, a
	// NopAuditSink is installed so authkit can emit unconditionally.
	AuditSink AuditSink

	// Throttler rate-limits password login and 2FA attempts (per account+IP).
	// When nil, no throttling is applied.
	Throttler LoginThrottler

	// LivePermissionResolution makes Require/RequireAuth re-resolve a session
	// user's permissions from the PolicyProvider on every request (through a
	// short TTL cache), so role and permission changes take effect within the
	// cache window rather than only on next login. Multi-tenant deploys want
	// this on; single-tenant deploys can leave it off (cheaper login-time
	// cache). API-key credentials always resolve live regardless of this flag.
	LivePermissionResolution bool

	// PermissionCacheTTL bounds how stale a live-resolved permission set may be.
	// Defaults to 30s when LivePermissionResolution is enabled.
	PermissionCacheTTL time.Duration

	// Sessions configures revocable server-side sessions.
	Sessions SessionConfig

	// CSRF configures CSRF protection for cookie-authenticated requests.
	CSRF CSRFConfig

	// TwoFactor configures TOTP two-step authentication.
	TwoFactor TwoFactorConfig

	// Tokens configures the OAuth2/PKCE token layer for native clients.
	Tokens TokenConfig

	// Platform configures the platform-operator (super-admin) axis.
	Platform PlatformConfig

	// Reset configures the self-service password-reset flow.
	Reset ResetConfig

	// Devices configures the device-principal axis.
	Devices DeviceConfig
}

// Auth is the central object. Create one with New() and attach its methods as
// HTTP handlers and middleware.
type Auth struct {
	cfg             Config
	store           sessions.Store
	rbacProvider    PolicyProvider
	log             *slog.Logger
	keyValidator    APIKeyValidator
	audit           AuditSink
	permCache       *permCache
	throttler       LoginThrottler
	keyring         *keyring
	deviceValidator DeviceTokenValidator
	deviceCaps      map[string]struct{}
	hasher          PasswordHasher
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
		if cfg.OAuth.CallbackBaseURL == "" {
			return nil, fmt.Errorf("authkit: OAuth.CallbackBaseURL is required when OAuth is enabled")
		}
		if _, err := url.ParseRequestURI(cfg.OAuth.CallbackBaseURL); err != nil {
			return nil, fmt.Errorf("authkit: OAuth.CallbackBaseURL is not a valid URL: %w", err)
		}
		if len(cfg.OAuth.Providers) == 0 && len(cfg.OAuth.GothProviders) == 0 {
			return nil, fmt.Errorf("authkit: at least one provider is required when OAuth is enabled (use OAuth.Providers or OAuth.GothProviders)")
		}
	}

	// Password-specific validation.
	passwordEnabled := cfg.Mode == AuthModePassword || cfg.Mode == AuthModeBoth
	if passwordEnabled && cfg.UserStore == nil {
		return nil, fmt.Errorf("authkit: UserStore is required when password auth is enabled")
	}

	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "authkit")

	if !cfg.SecureCookie {
		log.Warn("SecureCookie is false — cookies will be sent over plain HTTP; enable it in production")
	}

	if cfg.CookiePrefix == "" {
		cfg.CookiePrefix = "authkit"
	}
	if cfg.AfterLoginURL == "" {
		cfg.AfterLoginURL = "/"
	}
	if cfg.AfterLogoutURL == "" {
		cfg.AfterLogoutURL = "/"
	}

	hasher := cfg.PasswordHasher
	if hasher == nil {
		hasher = BcryptHasher{}
	}

	// Build and register goth providers only when OAuth is enabled.
	if oauthEnabled {
		providers, err := buildProviders(cfg.OAuth.Providers, cfg.OAuth.CallbackBaseURL)
		if err != nil {
			return nil, err
		}
		providers = append(providers, cfg.OAuth.GothProviders...)
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

	// Legacy encrypted-cookie session store (used when Sessions.Store is nil).
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

	// Token layer: build the Ed25519 keyring when enabled.
	var kr *keyring
	if cfg.Tokens.Enable {
		if cfg.Tokens.RefreshStore == nil {
			return nil, fmt.Errorf("authkit: Tokens.Enable requires a Tokens.RefreshStore")
		}
		kr, err = newKeyring(cfg.Tokens.SigningKeys)
		if err != nil {
			return nil, err
		}
	}

	// Device axis: the capability allow-list must be declared in code.
	var deviceCaps map[string]struct{}
	if cfg.Devices.Validator != nil {
		if len(cfg.Devices.Capabilities) == 0 {
			return nil, fmt.Errorf("authkit: Devices.Validator requires a non-empty Devices.Capabilities allow-list")
		}
		deviceCaps = make(map[string]struct{}, len(cfg.Devices.Capabilities))
		for _, c := range cfg.Devices.Capabilities {
			if !validPermName.MatchString(c) || c == PermAll {
				return nil, fmt.Errorf("authkit: invalid device capability %q", c)
			}
			deviceCaps[c] = struct{}{}
		}
	}

	return &Auth{
		cfg:             cfg,
		store:           store,
		rbacProvider:    provider,
		log:             log,
		keyValidator:    cfg.APIKeyValidator,
		audit:           audit,
		permCache:       pc,
		throttler:       cfg.Throttler,
		keyring:         kr,
		deviceValidator: cfg.Devices.Validator,
		deviceCaps:      deviceCaps,
		hasher:          hasher,
	}, nil
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
		a.log.Info("WatchRBAC: provider does not implement PolicyReloader — live reloading is disabled")
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
				a.log.Error("RBAC reload failed", "err", err)
			}
		}
	}
}

// cookieName builds a namespaced cookie name, applying the __Host- prefix in
// production (requires Secure + Path=/ + no Domain), which browsers reject
// over plain HTTP — so dev uses the bare name.
func (a *Auth) cookieName(base string) string {
	name := a.cfg.CookiePrefix + "_" + base
	if a.cfg.SecureCookie {
		return "__Host-" + name
	}
	return name
}
