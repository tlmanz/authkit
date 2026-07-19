# Migrating from authkit v1 to v2

v2 generalizes authkit for any Go service: the configuration is grouped, the
principal model is host-extensible, device capabilities are declared by the
host, logging is structured (`log/slog`), and every error response carries a
machine-readable code. The storage interfaces are almost unchanged — most
implementations compile as-is.

```bash
go get github.com/tlmanz/authkit/v2
go get github.com/tlmanz/authkit/redisstore/v2   # optional ready-made Redis stores
```

## Import path

```go
import authkit "github.com/tlmanz/authkit/v2"
```

## Config: flat fields → grouped sub-structs

| v1 field | v2 location |
|---|---|
| `Providers`, `GothProviders`, `CallbackBaseURL` | `OAuth.Providers`, `OAuth.GothProviders`, `OAuth.CallbackBaseURL` |
| `SessionStore`, `IdleTimeout`, `AbsoluteTimeout` | `Sessions.Store`, `Sessions.IdleTimeout`, `Sessions.AbsoluteTimeout` |
| `EnableCSRF` | `CSRF.Enable` (+ new optional `CSRF.TrustedOrigins`) |
| `TOTPStore`, `Require2FAForRoles` | `TwoFactor.Store`, `TwoFactor.RequireForRoles` |
| `TrustedDeviceStore`, `TrustedDeviceTTL` | `TwoFactor.TrustedDevices`, `TwoFactor.TrustedDeviceTTL` |
| `EnableTokens`, `SigningKeys`, `AccessTokenTTL`, `RefreshTokenTTL` | `Tokens.Enable`, `Tokens.SigningKeys`, `Tokens.AccessTTL`, `Tokens.RefreshTTL` |
| `RefreshTokenStore`, `AuthCodeStore` | `Tokens.RefreshStore`, `Tokens.AuthCodes` |
| `TokenIssuer`, `TokenClientID`, `TokenRedirectURIs` | `Tokens.Issuer`, `Tokens.ClientID`, `Tokens.RedirectURIs` |
| `PlatformAdminStore`, `PlatformPolicy`, `EnableImpersonation` | `Platform.Store`, `Platform.Policy`, `Platform.EnableImpersonation` |
| `PasswordResetStore`, `ResetDelivery`, `PasswordResetTTL` | `Reset.Store`, `Reset.Delivery`, `Reset.TTL` |
| `DeviceTokenValidator` | `Devices.Validator` + **required** `Devices.Capabilities` |
| `Logger Logger` (printf-style interface) | `Logger *slog.Logger` |

New optional fields: `CookiePrefix` (default `"authkit"`), `ClientIP
func(*http.Request) string` (trusted-proxy hook), `ErrorWriter` (replace the
JSON error envelope), `PasswordHasher` (default bcrypt cost 12).

## Principal model: `BranchID` → `Attrs`

`User`, `PasswordUser`, `Session`, and `DeviceRecord` no longer have a
`BranchID` field. Host-specific principal attributes now live in a generic
`Attrs map[string]string`, round-tripped through sessions and the access-token
`attrs` claim:

```go
// v1                       // v2
u.BranchID                  u.Attr("branch_id")
pu.BranchID = b             pu.Attrs = map[string]string{"branch_id": b}
```

New accessors: `User.Permissions()` (copy of the resolved permission list —
stop probing `Can()` against a catalog), `User.SetPermissions()` (for
host-driven login flows), `User.Attr(key)`, `Device.Attr(key)`.

## Device principals: capabilities are yours now

The hardcoded `CapPrintJobReceive` / `CapPrintStatusReport` constants are gone.
Declare your device capability allow-list in config; it is required whenever
`Devices.Validator` is set:

```go
Devices: authkit.DeviceConfig{
    Validator:    myValidator,
    Capabilities: []string{"print:job.receive", "print:status.report"},
},
```

`RequireDevice` still panics on an undeclared capability at wire time.
`IsDeviceCapability` moved from a package function to a method on `*Auth`.

## Logging: `log/slog`

The two-method `Logger` interface is gone. Pass any `*slog.Logger`; when nil,
`slog.Default()` is used. `NewLayeredProvider`'s `WithLogger` also takes a
`*slog.Logger`.

## Error responses: JSON envelope with stable codes

v1 wrote plain-text `http.Error` bodies. v2 writes
`{"error": "<code>", "error_description": "<prose>"}` on every error — the
same shape the OAuth2 token endpoints already used. Codes are the `ErrCode*`
constants (`unauthenticated`, `invalid_credentials`, `rate_limited`, …) and
are append-only API. Clients should branch on the code, not the prose. Set
`Config.ErrorWriter` to render errors your own way (e.g. RFC 9457
problem+json).

## Request bodies: JSON now accepted everywhere

Every endpoint that read form values also accepts an `application/json` body
with the same field names. Form encoding continues to work unchanged.

## Replaced / removed APIs

| v1 | v2 |
|---|---|
| `IssueAccessTokenOnly(w, u, ttl) error` (wrote the HTTP response) | `MintAccessToken(u, ttl) (string, error)` (pure; you write the response) |
| — | `EstablishSession(ctx, w, r, u)` — mint a first-class session from a host-driven login flow |
| — | `EstablishPlatformSession(ctx, w, r, rec)` — same for platform admins (dev bypasses, SSO bridges; caller owns authentication) |
| `HashPassword` / `CheckPassword` | unchanged (bcrypt), but the flows use `Config.PasswordHasher` |

## Cookies

All cookies are namespaced by `CookiePrefix` (default `authkit`). With the
default prefix, only one name changes vs v1: the CSRF cookie `csrf_token` →
`authkit_csrf`. SPAs that fetch the token from `GET /auth/csrf` and echo the
`X-CSRF-Token` header are unaffected; only code that read the cookie by name
needs the new name. Session (`authkit_sid`), 2FA-pending, platform, and
trusted-device cookie names are unchanged.

## Password policy

`PasswordPolicy` gains `MaxLength` (default 72, bcrypt's input limit); a
too-long password is now a clean 400 instead of a 500 from the KDF.

## Redis stores (new)

If you implemented Redis-backed session/throttle/trusted-device/auth-code
stores yourself, the `redisstore` module now ships them:

```go
import redisstore "github.com/tlmanz/authkit/redisstore/v2"

sessions := redisstore.NewSessions(rc, idle, absolute)
throttle := redisstore.NewThrottler(rc, 5, time.Minute, 15*time.Minute, time.Hour)
trusted  := redisstore.NewTrustedDevices(rc)
codes    := redisstore.NewAuthCodes(rc)
```

Key shapes match the reference implementations that shipped in earlier
integrations (`sess:`, `usess:`, `throttle:*`, `td:`, `tdu:`, `authcode:`), so
existing Redis data stays valid; `WithKeyPrefix("app:")` namespaces multiple
apps on one Redis.
