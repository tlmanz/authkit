[![CI](https://github.com/tlmanz/authkit/actions/workflows/ci.yml/badge.svg)](https://github.com/tlmanz/authkit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tlmanz/authkit/actions/workflows/codequality.yml/badge.svg)](https://github.com/tlmanz/authkit/actions/workflows/codequality.yml)
[![Coverage Status](https://coveralls.io/repos/github/tlmanz/authkit/badge.svg)](https://coveralls.io/github/tlmanz/authkit)
[![Go Report Card](https://goreportcard.com/badge/github.com/tlmanz/authkit/v2)](https://goreportcard.com/report/github.com/tlmanz/authkit/v2)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/tlmanz/authkit)

# authkit

Batteries-included authentication and RBAC for Go HTTP services, built on
`net/http` (Go 1.22+ routing) with storage-agnostic interfaces.

- **OAuth 2.0** via [markbates/goth](https://github.com/markbates/goth) — GitHub, Google, GitLab, Bitbucket built in, [80+ more](#other-providers) via `GothProviders`
- **Email/password** authentication with a pluggable `PasswordHasher` (bcrypt default)
- **Revocable server-side sessions** (optional) — opaque-ID cookie, idle + absolute timeouts, session fixation rotation, "log out everywhere"; falls back to encrypted cookie sessions
- **Two-factor auth (TOTP)** — per-role enforcement, pending/confirmed enrollment, single-use recovery codes, optional anti-replay, "trust this device"
- **OAuth2 token layer for native clients** — Authorization Code + PKCE, Ed25519-signed access JWTs with key rotation + JWKS, rotating opaque refresh tokens with reuse detection, cookie-free password grant
- **API keys** — plug in any key store via a single-method interface
- **Device principals** — machine clients (agents, kiosks, IoT) confined to a host-declared capability allow-list, isolated from human credential paths
- **Platform-operator axis** — separate super-admin principals for multi-tenant SaaS, mandatory TOTP, audited break-glass single-tenant impersonation
- **Multi-tenant aware** — `TenantID` on every principal, tenant-scoped permission resolution, fail-closed tenant context helpers; single-tenant apps just leave it empty
- **Host-defined principal attributes** — an `Attrs` map that round-trips through sessions and JWT claims for your own scoping (org unit, locale, plan tier)
- **RBAC** — YAML file, layered YAML+database, or fully custom `PolicyProvider`; optional live per-request permission resolution with TTL cache; live policy reload
- **CSRF protection** — signed double-submit middleware, optional trusted-origin check
- **Login throttling** — pluggable per-account+IP rate limiting with `Retry-After`
- **Password reset** — single-use hashed tokens, delivery-channel agnostic, no user enumeration
- **Audit sink** — structured security events (login, logout, refresh, revoke, 2FA, reset, impersonate)
- **Structured logging** via `log/slog`; secrets never logged
- **Uniform JSON errors** — every error carries a stable machine-readable code; rendering is replaceable via `ErrorWriter`
- **JSON or form bodies** on every endpoint
- **Ready-made Redis stores** — the [`redisstore`](#redis-stores) module implements sessions, throttling, trusted devices, and PKCE code claims

Migrating from v1? See [MIGRATION.md](MIGRATION.md).

---

## Installation

```bash
go get github.com/tlmanz/authkit/v2
go get github.com/tlmanz/authkit/redisstore/v2   # optional Redis stores
```

---

## Quick Start

### 1. Define your policy (`policy.yaml`)

```yaml
roles:
  admin:
    permissions: ["*"]         # wildcard grants every permission
    members:
      - alice@company.com

  developer:
    permissions: ["view", "upload"]
    members:
      - bob@company.com

  viewer:
    permissions: ["view"]

# Fallback role for authenticated users not listed in any role.
# Omit to deny access to unlisted users entirely.
default_role: viewer
```

### 2. Construct

```go
import authkit "github.com/tlmanz/authkit/v2"

auth, err := authkit.New(authkit.Config{
    Mode:          authkit.AuthModeBoth, // OAuth + password (default: OAuth only)
    SessionSecret: os.Getenv("SESSION_SECRET"), // >= 32 random bytes
    SecureCookie:  true,                        // production (HTTPS)
    AfterLoginURL: "/dashboard",
    OAuth: authkit.OAuthConfig{
        Providers: []authkit.ProviderConfig{
            {Name: "github", ClientID: os.Getenv("GITHUB_CLIENT_ID"), ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET")},
        },
        CallbackBaseURL: "https://example.com",
    },
    UserStore: myUserStore, // implements authkit.UserStore (password mode)
    RBAC:      authkit.RBACConfig{FilePath: "policy.yaml"},
})
```

### 3. Wire up routes

```go
mux := http.NewServeMux()

// OAuth routes (when OAuth is enabled)
mux.HandleFunc("GET /auth/{provider}",          auth.BeginAuth)
mux.HandleFunc("GET /auth/{provider}/callback", auth.Callback)

// Password routes (when password auth is enabled)
mux.HandleFunc("POST /auth/register", auth.Register)
mux.HandleFunc("POST /auth/login",    auth.Login)

// Common routes
mux.HandleFunc("POST /auth/logout", auth.Logout)
mux.HandleFunc("GET /auth/me",      auth.Me)

// Protected routes
mux.Handle("GET /api/reports",   auth.RequireAuth(http.HandlerFunc(reportsHandler)))
mux.Handle("POST /api/projects", auth.Require("projects:write")(http.HandlerFunc(createHandler)))
```

Every POST endpoint accepts either `application/x-www-form-urlencoded` or an
`application/json` body with the same field names.

---

## HTTP routes

| Method | Path | Handler | Feature |
|--------|------|---------|---------|
| `GET`  | `/auth/{provider}` | `BeginAuth` | OAuth |
| `GET`  | `/auth/{provider}/callback` | `Callback` | OAuth |
| `POST` | `/auth/register` | `Register` | Password |
| `POST` | `/auth/login` | `Login` | Password |
| `POST` | `/auth/logout` | `Logout` | All |
| `POST` | `/auth/logout/all` | `LogoutEverywhere` | Server-side sessions |
| `GET`  | `/auth/me` | `Me` | All |
| `POST` | `/auth/password/change` | `ChangePassword` | Password |
| `POST` | `/auth/password/first-change` | `ChangeFirstPassword` | Must-change-password gate |
| `POST` | `/auth/password/forgot` | `ForgotPassword` | Reset |
| `POST` | `/auth/password/reset` | `ResetPassword` | Reset |
| `POST` | `/auth/2fa/enroll` | `Enroll2FA` | TOTP |
| `POST` | `/auth/2fa/verify` | `Verify2FA` | TOTP |
| `POST` | `/auth/2fa/confirm` | `ConfirmTwoFactor` | TOTP (self-service) |
| `POST` | `/auth/2fa/disable` | `DisableTwoFactor` | TOTP (self-service) |
| `POST` | `/auth/2fa/recovery/regenerate` | `RegenerateRecoveryCodes` | TOTP |
| `GET`  | `/auth/2fa/status` | `TwoFactorStatus` | TOTP |
| `GET`  | `/auth/csrf` | `CSRFToken` | CSRF |
| `GET`  | `/authorize` | `Authorize` | Token layer (PKCE) |
| `POST` | `/token` | `IssueToken` | Token layer |
| `POST` | `/token/refresh` | `RefreshAccessToken` | Token layer |
| `POST` | `/oauth/token/password` | `IssuePasswordToken` | Token layer (native password grant) |
| `POST` | `/oauth/token/2fa` | `IssuePasswordToken2FA` | Token layer |
| `GET`  | `/.well-known/jwks.json` | `JWKS` | Token layer |
| `POST` | `/platform/login` | `PlatformLogin` | Platform axis |
| `POST` | `/platform/2fa/enroll` | `PlatformEnroll2FA` | Platform axis |
| `POST` | `/platform/2fa/verify` | `PlatformVerify2FA` | Platform axis |
| `POST` | `/platform/logout` | `PlatformLogout` | Platform axis |
| `GET`  | `/platform/me` | `PlatformMe` | Platform axis |
| `POST` | `/platform/password/forgot` | `PlatformForgotPassword` | Reset |
| `POST` | `/platform/password/reset` | `PlatformResetPassword` | Reset |

Mount paths are suggestions — every handler is a plain `http.HandlerFunc`.

---

## Middleware

| Middleware | Bearer (JWT / API key) | Session | Use for |
|---|---|---|---|
| `RequireAuth(next)` | ✓ | ✓ | General protected routes |
| `Require(perm)(next)` | ✓ | ✓ | Permission-gated routes |
| `RequireSessionAuth(next)` | ✗ | ✓ | UI-only routes |
| `RequireSession(perm)(next)` | ✗ | ✓ | Management routes that must not accept tokens |
| `RequireDevice(cap)(next)` | device token only | ✗ | Device/agent routes |
| `RequirePlatformAdmin(perm)(next)` | ✗ | platform session | Platform-operator routes |
| `CSRF(next)` | exempt | enforced | State-changing cookie routes |

Inside a handler:

```go
u := authkit.UserFromCtx(r.Context())        // human principal (or nil)
tenantID, ok := authkit.TenantIDFromCtx(ctx) // fail closed when !ok
d := authkit.DeviceFromCtx(ctx)              // device principal (or nil)
p := authkit.PlatformAdminFromCtx(ctx)       // platform principal (or nil)

u.Can("projects:write") // permission check
u.Permissions()         // full resolved permission list (copy)
u.Attr("branch_id")     // host-defined attribute
```

---

## Error responses

Every error authkit writes is a JSON envelope with a stable machine code:

```json
{"error": "invalid_credentials", "error_description": "invalid email or password"}
```

Codes are the `ErrCode*` constants — `unauthenticated`, `invalid_credentials`,
`invalid_code`, `invalid_challenge`, `forbidden`, `csrf_invalid`,
`invalid_request`, `password_policy`, `invalid_grant`, `conflict`,
`rate_limited`, `not_enabled`, `server_error` — and are append-only API.
Clients branch and localize on the code, never the prose. To render errors
differently (e.g. RFC 9457 problem+json with a trace id), set
`Config.ErrorWriter`.

Step responses (not errors) are `200` JSON: `{"status":"2fa_required",
"action":"enroll"|"verify"}` and `{"status":"password_change_required"}`.

---

## Storage interfaces

authkit persists nothing itself. Implement only the interfaces for the
features you enable:

| Interface | Enables | Methods |
|---|---|---|
| `UserStore` | password auth | `CreateUser`, `GetUserByEmail`, `UpdatePassword` |
| `SessionStore` | revocable sessions | `Create`, `Get`, `Touch`, `Revoke`, `RevokeAllForUser` |
| `PolicyProvider` | RBAC | `RoleFor`, `PermissionsForRole` |
| `LoginThrottler` | rate limiting | `Allow`, `RecordFailure`, `Reset` |
| `TOTPStore` (+opt. `TOTPManager`, `TOTPReplayGuard`) | 2FA | `Enroll`, `Confirm`, `Secret`, `ConsumeRecovery` |
| `TrustedDeviceStore` | "remember this device" | `Trust`, `IsTrusted`, `RevokeAllForUser` |
| `RefreshTokenStore` | token layer | `Create`, `Get`, `Rotate`, `RevokeChain`, `RevokeAllForUser` |
| `AuthCodeStore` | single-use PKCE codes | `ClaimAuthCode` |
| `APIKeyValidator` | API keys | `ValidateKey` |
| `DeviceTokenValidator` | device principals | `ValidateDeviceToken` |
| `PlatformAdminStore` (+opt. `PlatformTOTPReplayGuard`) | platform axis | `GetPlatformAdmin`, `UpdatePassword`, `EnrollPlatformTOTP`, `ConfirmPlatformTOTP`, `ConsumePlatformRecovery` |
| `PlatformPolicy` | platform axis | `PermissionsForPlatformRole` |
| `PasswordResetStore` + `ResetDelivery` | password reset | `CreateResetToken`, `ConsumeResetToken`; `SendPasswordReset` |
| `AuditSink` | audit log | `Emit` |
| `PasswordHasher` | custom KDF | `Hash`, `Verify` |

Contract details live on each interface's doc comment. Rules that matter:
stores hash opaque tokens at rest; `UserStore` returns `ErrUserExists` /
`ErrUserNotFound` sentinels; `AuditSink.Emit` must never block the request
path.

### Redis stores

The `github.com/tlmanz/authkit/redisstore/v2` module (its own go.mod — the
core stays Redis-free) ships production implementations of the four stores
whose data is naturally self-expiring:

```go
import (
    "github.com/redis/go-redis/v9"
    redisstore "github.com/tlmanz/authkit/redisstore/v2"
)

rc := redis.NewClient(&redis.Options{Addr: "localhost:6379"})

cfg.Sessions.Store            = redisstore.NewSessions(rc, 30*time.Minute, 24*time.Hour)
cfg.Throttler                 = redisstore.NewThrottler(rc, 5, time.Minute, 15*time.Minute, time.Hour)
cfg.TwoFactor.TrustedDevices  = redisstore.NewTrustedDevices(rc)
cfg.Tokens.AuthCodes          = redisstore.NewAuthCodes(rc)
```

All constructors take any `redis.UniversalClient` (single node, Sentinel,
Cluster) and an optional `redisstore.WithKeyPrefix("myapp:")`.

---

## Multi-tenancy

Every principal carries an optional `TenantID` — the hard security boundary in
a multi-tenant deployment. Your stores populate it (email is global, so the
lookup determines the tenant); authkit puts it on the request context before
resolving permissions:

```go
tenantID, ok := authkit.TenantIDFromCtx(r.Context())
if !ok {
    http.Error(w, "no tenant", http.StatusForbidden) // fail closed
    return
}
// scope every query by tenantID (or set your per-transaction RLS variable)
```

A tenant-aware `PolicyProvider` reads the same context to resolve roles per
tenant. Single-tenant applications leave `TenantID` empty everywhere and
ignore all of this.

### Principal attributes

`User.Attrs` / `Session.Attrs` / `PasswordUser.Attrs` /
`DeviceRecord.Attrs` carry host-defined key/values (an org-unit scope, a plan
tier). authkit round-trips them through sessions and the access-token `attrs`
claim but never interprets them. Read with `u.Attr("key")`. Keep values small —
they travel in the JWT.

---

## Server-side sessions

Provide `Sessions.Store` for revocable sessions: the cookie carries only an
opaque 256-bit ID and all state lives in your store.

- Session-ID rotation on every login (fixation prevention)
- Sliding idle renewal (`Touch`, throttled to once a minute) + absolute cap
- `__Host-` cookie prefix when `SecureCookie` is true; all cookie names
  namespaced by `CookiePrefix`
- `auth.RevokeUserSessions(ctx, tenantID, email)` — "log out everywhere"
- `auth.EstablishSession(ctx, w, r, u)` — mint a first-class session from a
  host-driven login flow (SSO bridge, trial principal). The caller owns
  authentication; set the resolved permissions with `u.SetPermissions(...)`.

When `Sessions.Store` is nil, sessions fall back to encrypted cookies
(gorilla/sessions) — fine for small apps, no revocation.

---

## Two-factor authentication (TOTP)

Users whose role is in `TwoFactor.RequireForRoles` must complete a TOTP
challenge after the password step. Enrollment is two-phase (pending →
confirmed on first successful verify) so an abandoned enrollment never locks a
user out. Recovery codes are single-use and stored hashed. Optional:

- `TOTPManager` on your store → self-service disable / recovery-code regeneration
- `TOTPReplayGuard` on your store → each 30s time-step usable at most once
- `TwoFactor.TrustedDevices` → "remember this device" skips the TOTP prompt
  (password still required); revoked by logout-everywhere, password
  change/reset, and disabling 2FA

Login responds `{"status":"2fa_required","action":"enroll"|"verify"}`; the
client calls `/auth/2fa/enroll` (returns `otpauthUrl`, `secret`,
`recoveryCodes`) and/or `/auth/2fa/verify`.

---

## Token layer (native clients)

Ed25519-signed access JWTs + rotating opaque refresh tokens:

```go
signing, _ := authkit.NewSigningKey("key-2026-01", seed) // 32 random bytes

cfg.Tokens = authkit.TokenConfig{
    Enable:       true,
    SigningKeys:  []authkit.SigningKey{signing}, // first signs; all verify (rotation)
    RefreshStore: myRefreshStore,
    AccessTTL:    15 * time.Minute,
    RefreshTTL:   30 * 24 * time.Hour,
    Issuer:       "https://api.example.com",
    ClientID:     "example-mobile",
    RedirectURIs: []string{"com.example.app://callback"},
    AuthCodes:    redisstore.NewAuthCodes(rc), // optional: single-use codes
}
```

- **PKCE flow** (`/authorize` → `/token`) for browser-mediated login; **password
  grant** (`/oauth/token/password` + `/oauth/token/2fa`) for first-party native
  screens — both share rotation, reuse detection, and JWKS.
- **Permissions are never in the JWT** — resolved server-side per request, so
  role changes take effect within one access-token TTL.
- **Refresh rotation with reuse detection**: replaying a spent refresh token
  revokes the whole chain and emits an audit event.
- `auth.MintAccessToken(u, ttl)` mints a refresh-less access token for
  principals not backed by `UserStore` (ephemeral trials, service identities).

---

## Platform-operator axis

For multi-tenant SaaS: platform admins operate the platform itself, across
tenants, with no `TenantID`, on a separate cookie and login route. TOTP is
mandatory with no role exemption.

```go
cfg.Platform = authkit.PlatformConfig{
    Store:               myPlatformStore,
    Policy:              myPlatformPolicy, // small static capability catalog
    EnableImpersonation: true,
}

mux.Handle("GET /platform/tenants",
    auth.RequirePlatformAdmin("platform:tenants.read")(http.HandlerFunc(listTenants)))
```

Break-glass, audited, single-tenant support access:

```go
ctx, err := auth.ImpersonationContext(r.Context(), admin, tenantID)
// ctx is now scoped to exactly one tenant; requires "platform:impersonate".
```

`auth.EstablishPlatformSession` exists for host-controlled flows (dev
bypasses, test harnesses) — the caller takes on the authentication
responsibility the built-in password+TOTP flow normally enforces.

---

## Device principals

Machine clients (on-prem agents, kiosks, IoT) authenticate with opaque device
tokens and are confined to a capability allow-list you declare in code:

```go
cfg.Devices = authkit.DeviceConfig{
    Validator:    myDeviceValidator, // looks the token up by hash
    Capabilities: []string{"jobs:receive", "status:report"},
}

mux.Handle("GET /agent/jobs",
    auth.RequireDevice("jobs:receive")(http.HandlerFunc(jobsHandler)))
```

A device never resolves permissions from policy — it can never hold `"*"` or
any role-granted capability, no matter what a role table says. `RequireDevice`
panics at wire time on an undeclared capability. For non-HTTP channels (a
WebSocket upgrade), call `auth.AuthenticateDevice` and bind the principal with
`authkit.WithDevice` / `authkit.WithTenant` yourself.

---

## CSRF, throttling, audit

- **CSRF**: signed double-submit (`CSRF.Enable`), JS-readable cookie echoed in
  `X-CSRF-Token`, bearer requests exempt, optional `CSRF.TrustedOrigins`
  Origin allow-list. SPAs fetch the token from `GET /auth/csrf`.
- **Throttling**: plug a `LoginThrottler` (see `redisstore.NewThrottler`);
  authkit calls it around password login, 2FA, platform login, and password
  reset, keyed per account+IP. Locked-out attempts get `429` + `Retry-After`.
  Client IP comes from `RemoteAddr` unless you set `Config.ClientIP` (do this
  behind a reverse proxy with a vetted header).
- **Audit**: wire an `AuditSink` to receive `login`, `logout`, `refresh`,
  `revoke`, `2fa_*`, `password_*`, `role_change`, `permission_change`,
  `impersonate` events. `Emit` must not block the request path.

---

## RBAC options

1. **YAML file** — `RBAC: authkit.RBACConfig{FilePath: "policy.yaml"}`; live
   reload with `go auth.WatchRBAC(ctx, time.Minute)`.
2. **Layered** — YAML baseline + per-user database overrides:
   `authkit.NewLayeredProvider("policy.yaml", myUserRoleStore, authkit.WithLogger(slog.Default()))`.
3. **Custom `PolicyProvider`** — anything (per-tenant role tables, an IdP).
   Both methods receive the tenant on ctx via `authkit.TenantIDFromCtx`.

Set `LivePermissionResolution: true` to re-resolve session permissions per
request through a TTL cache (`PermissionCacheTTL`, default 30s), so role edits
take effect without re-login. Bearer credentials always resolve live.

---

## Configuration reference

```go
authkit.Config{
    Mode:          authkit.AuthModeOAuth | AuthModePassword | AuthModeBoth,
    AppName:       "Acme",              // TOTP issuer etc. (default "App")
    SessionSecret: "...",               // required, >= 32 bytes
    SecureCookie:  true,                // production
    CookiePrefix:  "authkit",           // cookie namespace (default)
    AfterLoginURL: "/", AfterLogoutURL: "/",
    Logger:        slog.Default(),      // *slog.Logger (default)
    ClientIP:      nil,                 // func(*http.Request) string — proxy hook
    ErrorWriter:   nil,                 // replace the JSON error envelope

    OAuth:          authkit.OAuthConfig{...},
    UserStore:      myUserStore,
    PasswordHasher: nil,                       // default bcrypt cost 12
    PasswordPolicy: &authkit.PasswordPolicy{MinLength: 8, MaxLength: 72},
    RBAC:           authkit.RBACConfig{...},
    APIKeyValidator: myKeyStore,
    AuditSink:       myAuditSink,
    Throttler:       myThrottler,
    LivePermissionResolution: false,
    PermissionCacheTTL:       30 * time.Second,

    Sessions:  authkit.SessionConfig{Store, IdleTimeout, AbsoluteTimeout},
    CSRF:      authkit.CSRFConfig{Enable, TrustedOrigins},
    TwoFactor: authkit.TwoFactorConfig{Store, RequireForRoles, TrustedDevices, TrustedDeviceTTL},
    Tokens:    authkit.TokenConfig{Enable, SigningKeys, AccessTTL, RefreshTTL, RefreshStore, AuthCodes, Issuer, ClientID, RedirectURIs},
    Platform:  authkit.PlatformConfig{Store, Policy, EnableImpersonation},
    Reset:     authkit.ResetConfig{Store, Delivery, TTL},
    Devices:   authkit.DeviceConfig{Validator, Capabilities},
}
```

---

## Other providers

authkit ships convenience wrappers for Bitbucket, GitHub, Google, and GitLab.
For any of the [80+ other providers](https://github.com/markbates/goth?tab=readme-ov-file#supported-providers)
goth supports, construct the provider yourself and pass it via
`OAuth.GothProviders`:

```go
import "github.com/markbates/goth/providers/discord"

OAuth: authkit.OAuthConfig{
    GothProviders: []goth.Provider{
        discord.New(id, secret, "https://example.com/auth/discord/callback", "identify", "email"),
    },
    CallbackBaseURL: "https://example.com",
},
```

The callback URL pattern is always `/auth/{providerName}/callback`.

---

## Security notes

- Generate `SessionSecret` with `openssl rand -hex 32`; rotate deliberately.
- Passwords: bcrypt cost 12 by default; constant-time unknown-user handling
  prevents timing-based enumeration; generic error messages prevent oracle
  responses; supply Argon2id via `PasswordHasher` if preferred.
- Refresh tokens, device tokens, reset tokens, and session IDs are 256-bit
  opaque values; your stores must hash refresh/device/reset tokens at rest.
- The forgot-password flow always answers 200 and rate-limits before any
  store work, so it leaks neither account existence nor delivery outcome.
- Get an external security review before real financial or personal data
  flows through your deployment.
