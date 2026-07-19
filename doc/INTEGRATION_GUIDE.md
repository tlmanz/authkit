# authkit v2 Integration Guide

Everything needed to integrate `github.com/tlmanz/authkit/v2` into a Go HTTP
application. Written to be consumed by AI agents or human developers during
implementation. The [README](../README.md) documents the full API surface;
this guide walks the integration order and the storage contracts you must
satisfy. Migrating from v1? Read [MIGRATION.md](../MIGRATION.md) instead.

## What authkit does

Authentication (OAuth, email/password, API keys, device tokens, platform
operators), sessions (revocable server-side or encrypted cookie), RBAC, TOTP
2FA, an OAuth2/PKCE token layer for native clients, CSRF, login throttling,
password reset, and audit events — all over `net/http`, with every piece of
persistence behind an interface you implement.

It does NOT include: database drivers, UI, email/SMS sending, or rate-limit
storage. Those are the consumer's responsibility (the `redisstore` module
covers the Redis-natured stores).

## Prerequisites

- Go 1.25+
- `go get github.com/tlmanz/authkit/v2`
- Optional: `go get github.com/tlmanz/authkit/redisstore/v2`

## Step 1: Choose auth mode

| Mode | Constant | Needs |
|------|----------|-------|
| OAuth only (default) | `authkit.AuthModeOAuth` | `OAuth.Providers` + `OAuth.CallbackBaseURL` |
| Password only | `authkit.AuthModePassword` | `UserStore` |
| Both | `authkit.AuthModeBoth` | both of the above |

## Step 2: Implement UserStore (password mode)

```go
type UserStore interface {
    CreateUser(ctx context.Context, email, name, hashedPassword string) error
    GetUserByEmail(ctx context.Context, email string) (*authkit.PasswordUser, error)
    UpdatePassword(ctx context.Context, email, hashedPassword string) error
}
```

Rules:

- `CreateUser` receives a **pre-hashed** password. Store as-is; never re-hash.
- `CreateUser` MUST return `authkit.ErrUserExists` on a duplicate email.
- `GetUserByEmail` MUST return `authkit.ErrUserNotFound` when no user matches.
  Emails are normalized to lowercase before authkit calls you.
- Populate `PasswordUser.TenantID` for multi-tenant apps and
  `PasswordUser.Attrs` for any host-defined scoping (both are copied onto the
  authenticated principal and round-tripped through sessions/JWTs).
- Set `PasswordUser.MustChangePassword` for temporary/onboarding credentials;
  authkit then gates login behind `POST /auth/password/first-change`.
- `UpdatePassword` is called by the change/reset flows and must also clear the
  must-change flag.

PostgreSQL example:

```go
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*authkit.PasswordUser, error) {
    var u authkit.PasswordUser
    err := s.db.QueryRowContext(ctx,
        `SELECT email, name, password_hash, tenant_id::text, password_change_required
         FROM users WHERE email = $1`, email,
    ).Scan(&u.Email, &u.Name, &u.HashedPassword, &u.TenantID, &u.MustChangePassword)
    if errors.Is(err, sql.ErrNoRows) {
        return nil, authkit.ErrUserNotFound
    }
    return &u, err
}
```

## Step 3: RBAC

Start with a YAML file (`RBAC: authkit.RBACConfig{FilePath: "policy.yaml"}`).
Move to `NewLayeredProvider` (YAML baseline + DB overrides) or a fully custom
`PolicyProvider` when roles become data:

```go
type PolicyProvider interface {
    RoleFor(ctx context.Context, email string) (role string, permissions []string)
    PermissionsForRole(ctx context.Context, role string) []string
}
```

Both methods receive the tenant on ctx (`authkit.TenantIDFromCtx`) so a
DB-backed provider can scope role definitions per tenant. Enable
`LivePermissionResolution` for runtime role editing.

## Step 4: Sessions

For anything beyond a toy, provide `Sessions.Store` (revocable server-side
sessions). Easiest path:

```go
import redisstore "github.com/tlmanz/authkit/redisstore/v2"

cfg.Sessions = authkit.SessionConfig{
    Store:           redisstore.NewSessions(rc, 30*time.Minute, 24*time.Hour),
    IdleTimeout:     30 * time.Minute,
    AbsoluteTimeout: 24 * time.Hour,
}
```

Implementing your own: `Get` is called before the tenant is known and must
resolve by ID alone; the other methods receive the session's tenant on ctx.
The 256-bit session ID is the security boundary — treat the store's contents
as sensitive.

## Step 5: Hardening (recommended order)

1. **Throttler** — `redisstore.NewThrottler(rc, 5, time.Minute, 15*time.Minute, time.Hour)`.
   Behind a reverse proxy, set `Config.ClientIP` to read your vetted header.
2. **CSRF** — `CSRF: authkit.CSRFConfig{Enable: true}` and wrap state-changing
   cookie routes with `auth.CSRF(...)`. The SPA fetches `GET /auth/csrf` and
   echoes `X-CSRF-Token`.
3. **2FA** — implement `TOTPStore` (encrypt the secret at rest; store recovery
   code hashes; `Confirm` must be idempotent; `ConsumeRecovery` must be
   atomic). Add `TOTPManager` for self-service management and
   `TOTPReplayGuard` for one-use time-steps. Configure
   `TwoFactor.RequireForRoles`.
4. **Trusted devices** — `redisstore.NewTrustedDevices(rc)` +
   `TwoFactor.TrustedDevices` for "remember this device".
5. **Password reset** — implement `PasswordResetStore` (store the token hash;
   `ConsumeResetToken` atomic + single-use) and `ResetDelivery` (send the raw
   token out-of-band). authkit guarantees no user enumeration.
6. **Audit** — implement `AuditSink.Emit` (must not block; hand off to a
   queue/goroutine).

## Step 6: Token layer (native/mobile clients)

```go
seed := make([]byte, 32) // from your secret manager
signing, _ := authkit.NewSigningKey("key-2026-01", seed)
cfg.Tokens = authkit.TokenConfig{
    Enable: true, SigningKeys: []authkit.SigningKey{signing},
    RefreshStore: myRefreshStore, // hash tokens at rest; Rotate must be atomic
    Issuer: "https://api.example.com", ClientID: "example-mobile",
    RedirectURIs: []string{"com.example.app://callback"},
    AuthCodes: redisstore.NewAuthCodes(rc), // optional single-use PKCE codes
}
```

`RefreshTokenStore` contract: `Rotate(rawOld, next)` MUST fail without side
effects when rawOld is already used/revoked (that failure is what triggers
chain revocation on replay). Key rotation: prepend a new SigningKey; keep the
old ones until their tokens expire.

## Step 7 (optional): Device principals and the platform axis

- **Devices**: implement `DeviceTokenValidator` (hash the token, look it up
  pre-tenant, return `DeviceRecord` with TenantID + Attrs) and declare
  `Devices.Capabilities` — the fixed allow-list a device may ever hold.
- **Platform operators** (multi-tenant SaaS): implement `PlatformAdminStore`
  (+ `PlatformPolicy`), mount the `/platform/*` handlers on a separate
  route/subdomain. TOTP is mandatory by design; seed the first admin
  in-process (never via an HTTP endpoint) with `MustChangePassword`-style
  handling in your own store.

## Host-driven login flows

When you authenticate a principal outside authkit's handlers (an SSO bridge,
an ephemeral trial tenant, a dev bypass):

```go
u := &authkit.User{Email: e, Role: r, TenantID: t, Provider: "trial"}
u.SetPermissions(perms)                            // you resolved these
err := auth.EstablishSession(ctx, w, r, u)         // first-class session
tok, err := auth.MintAccessToken(u, remainingTTL)  // refresh-less JWT
err = auth.EstablishPlatformSession(ctx, w, r, rec) // platform (caller owns authn!)
```

## Client contract

- Errors: `{"error": code, "error_description": prose}` — branch on `code`
  (see the `ErrCode*` constants). Success steps: `{"status": "..."}`.
- All POST endpoints accept form or JSON bodies.
- Cookie names are `{CookiePrefix}_*` (default `authkit_*`), `__Host-`-prefixed
  when `SecureCookie` is true.
