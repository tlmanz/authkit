[![CI](https://github.com/tlmanz/authkit/actions/workflows/ci.yml/badge.svg)](https://github.com/tlmanz/authkit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tlmanz/authkit/actions/workflows/codequality.yml/badge.svg)](https://github.com/tlmanz/authkit/actions/workflows/codequality.yml)
[![Coverage Status](https://coveralls.io/repos/github/tlmanz/authkit/badge.svg)](https://coveralls.io/github/tlmanz/authkit)
![Open Issues](https://img.shields.io/github/issues/tlmanz/authkit)
[![Go Report Card](https://goreportcard.com/badge/github.com/tlmanz/authkit)](https://goreportcard.com/report/github.com/tlmanz/authkit)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/tlmanz/authkit)

# authkit

Plug-and-play authentication with YAML-based RBAC for Small Go HTTP services.

- **OAuth 2.0** via [markbates/goth](https://github.com/markbates/goth) — supports **GitHub**, **Google**, **GitLab**, **Bitbucket** out of the box, plus [80+ more providers](#other-providers) via `GothProviders`
- **Email/password** authentication with bcrypt hashing
- **API key authentication** — plug in any key store via a single-method interface
- **Two-factor auth (TOTP)** — per-role 2FA enforcement with authenticator apps + single-use recovery codes
- **Mobile token layer** — OAuth2 Authorization Code + PKCE, Ed25519-signed access JWTs, rotating refresh tokens with reuse detection, and a JWKS endpoint
- **Three modes**: OAuth only, password only, or both simultaneously
- **Multi-tenant aware** — every principal carries a `TenantID` (and optional `BranchID`) for RLS-scoped data access and per-tenant role resolution
- **Server-side sessions** (optional) — revocable, opaque-ID sessions with idle + absolute timeouts and "log out everywhere"; falls back to encrypted cookie sessions
- **CSRF protection** — signed double-submit middleware for cookie-authenticated requests
- **Login throttling** — pluggable per-account+IP rate limiting against brute force / credential stuffing
- **Platform super-admin axis** — separate platform principals with capability checks and audited, break-glass tenant impersonation
- **Device principals** — confined print-agent tokens with a fixed capability set, isolated from the human/API-key path
- **Audit sink** — emit structured security events (login, logout, refresh, revoke, 2FA, role/permission change, impersonate)
- Encrypted cookie sessions via [gorilla/sessions](https://github.com/gorilla/sessions)
- Role-Based Access Control via YAML file or a pluggable `PolicyProvider` interface
- **Layered RBAC** — seed roles from YAML, then let a UI override individual users via a database
- **Live permission resolution** (optional) — re-resolve a session's permissions per request through a short TTL cache so role changes take effect without re-login
- Live policy reload without restarts (`WatchRBAC`)
- Works with Go 1.22+ stdlib `net/http` (no external router required)
- Storage-agnostic — implement small interfaces for your database
- Pluggable logger — bring your own (`slog`, `zap`, `zerolog`) or use the default

---

## Installation

```bash
go get github.com/tlmanz/authkit
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
      - carol@company.com

  viewer:
    permissions: ["view"]

# Fallback role for authenticated users not listed in any role.
# Omit to deny access to unlisted users entirely.
default_role: viewer
```

### 2. Choose your auth mode

#### OAuth only (default)

```go
auth, err := authkit.New(authkit.Config{
    Providers: []authkit.ProviderConfig{
        {
            Name:         "github",
            ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
            ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
        },
    },
    CallbackBaseURL: "https://example.com",
    SessionSecret:   os.Getenv("SESSION_SECRET"),
    SecureCookie:    true,
    AfterLoginURL:   "/dashboard",
    RBAC:            authkit.RBACConfig{FilePath: "policy.yaml"},
})
```

#### Password only

```go
auth, err := authkit.New(authkit.Config{
    Mode:          authkit.AuthModePassword,
    SessionSecret: os.Getenv("SESSION_SECRET"),
    SecureCookie:  true,
    AfterLoginURL: "/dashboard",
    UserStore:     myUserStore, // implements authkit.UserStore
    RBAC:          authkit.RBACConfig{FilePath: "policy.yaml"},
})
```

#### Both (OAuth + password)

```go
auth, err := authkit.New(authkit.Config{
    Mode: authkit.AuthModeBoth,
    Providers: []authkit.ProviderConfig{
        {Name: "github", ClientID: "...", ClientSecret: "..."},
    },
    CallbackBaseURL: "https://example.com",
    SessionSecret:   os.Getenv("SESSION_SECRET"),
    SecureCookie:    true,
    AfterLoginURL:   "/dashboard",
    UserStore:       myUserStore,
    RBAC:            authkit.RBACConfig{FilePath: "policy.yaml"},
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

// Common routes (work with all modes)
mux.HandleFunc("POST /auth/logout", auth.Logout)
mux.HandleFunc("GET /auth/me",      auth.Me)

// Protected routes
mux.Handle("GET /api/reports",   auth.RequireAuth(http.HandlerFunc(reportsHandler)))
mux.Handle("POST /api/projects", auth.Require("projects:write")(http.HandlerFunc(createHandler)))
```

---

## Auth Modes

| Mode | Constant | Providers required | UserStore required | Use case |
|------|----------|-------------------|--------------------|----------|
| OAuth only | `authkit.AuthModeOAuth` | Yes | No | SSO with GitHub/Google/GitLab/Bitbucket/etc. |
| Password only | `authkit.AuthModePassword` | No | Yes | Traditional email/password |
| Both | `authkit.AuthModeBoth` | Yes | Yes | Let users choose their method |

When `Mode` is not set, it defaults to `AuthModeOAuth` for backward compatibility.

---

## Password Authentication

### UserStore interface

Implement this 2-method interface with your database of choice:

```go
type UserStore interface {
    CreateUser(ctx context.Context, email, name, hashedPassword string) error
    GetUserByEmail(ctx context.Context, email string) (*authkit.PasswordUser, error)
}
```

- `CreateUser` must return `authkit.ErrUserExists` if the email is already taken.
- `GetUserByEmail` must return `authkit.ErrUserNotFound` if no user matches.
- Passwords are pre-hashed with bcrypt before being passed to `CreateUser`.
- The returned `*PasswordUser` should populate `TenantID` (and optional `BranchID`) — authkit copies these onto the authenticated `User` and uses them for tenant-scoped permission resolution and RLS. See [Multi-Tenancy](#multi-tenancy).

### Password policy

```go
authkit.Config{
    PasswordPolicy: &authkit.PasswordPolicy{
        MinLength: 12, // default: 8
    },
}
```

### Hashing utility

`HashPassword` is exported for use in admin tooling or seed scripts:

```go
hashed, err := authkit.HashPassword("user-password")
```

### Security features

- **bcrypt cost 12** (~250ms per hash on modern hardware)
- **Constant-time responses** — failed logins for unknown users take the same time as wrong-password failures, preventing user enumeration
- **Generic error messages** — both wrong-user and wrong-password return `"invalid email or password"`
- **Rate limiting** — not built in (to stay storage-agnostic). Apply your own middleware:
  ```go
  mux.Handle("POST /auth/login", rateLimiter(http.HandlerFunc(auth.Login)))
  ```

---

## Custom Logger

By default, authkit logs to Go's standard `log` package. You can plug in your own logger by implementing the `Logger` interface:

```go
type Logger interface {
    Info(msg string, args ...any)
    Error(msg string, args ...any)
}
```

### Using the default logger

```go
// No Logger field needed — uses standard log package automatically.
auth, err := authkit.New(authkit.Config{...})
```

### Using slog

```go
type slogAdapter struct {
    l *slog.Logger
}

func (s slogAdapter) Info(msg string, args ...any)  { s.l.Info(fmt.Sprintf(msg, args...)) }
func (s slogAdapter) Error(msg string, args ...any) { s.l.Error(fmt.Sprintf(msg, args...)) }

auth, err := authkit.New(authkit.Config{
    Logger: slogAdapter{l: slog.Default()},
    // ...
})
```

### Using zap

```go
type zapAdapter struct {
    l *zap.SugaredLogger
}

func (z zapAdapter) Info(msg string, args ...any)  { z.l.Infof(msg, args...) }
func (z zapAdapter) Error(msg string, args ...any) { z.l.Errorf(msg, args...) }

auth, err := authkit.New(authkit.Config{
    Logger: zapAdapter{l: zapLogger.Sugar()},
    // ...
})
```

---

## OAuth Providers

### Bitbucket

```go
authkit.ProviderConfig{
    Name:         "bitbucket",
    ClientID:     os.Getenv("BITBUCKET_CLIENT_ID"),
    ClientSecret: os.Getenv("BITBUCKET_CLIENT_SECRET"),
    // Default scopes: ["account", "email"]
}
```

**Where to register:** Bitbucket → Settings → Workspace Settings → OAuth consumers → Add consumer

| Field | Value |
|-------|-------|
| Callback URL | `https://example.com/auth/bitbucket/callback` |
| Callback URL (local dev) | `http://localhost:8080/auth/bitbucket/callback` |
| Permissions | Account: **Read**, Email addresses: **Read** |

### GitHub

```go
authkit.ProviderConfig{
    Name:         "github",
    ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
    ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
    // Default scope: ["user:email"]
}
```

**Where to register:** [github.com/settings/developers](https://github.com/settings/developers) → New OAuth App

| Field | Value |
|-------|-------|
| Authorization callback URL | `https://example.com/auth/github/callback` |
| Authorization callback URL (local dev) | `http://localhost:8080/auth/github/callback` |

### Google

```go
authkit.ProviderConfig{
    Name:         "google",
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    // Default scopes: ["email", "profile"]
}
```

**Where to register:** Google Cloud Console → APIs & Services → Credentials → Create OAuth Client ID (type: Web application)

| Field | Value |
|-------|-------|
| Authorized redirect URIs | `https://example.com/auth/google/callback` |
| Authorized redirect URIs (local dev) | `http://localhost:8080/auth/google/callback` |

> Google allows multiple redirect URIs per client — add both production and localhost entries.

### GitLab

```go
authkit.ProviderConfig{
    Name:         "gitlab",
    ClientID:     os.Getenv("GITLAB_CLIENT_ID"),
    ClientSecret: os.Getenv("GITLAB_CLIENT_SECRET"),
    // Default scope: ["read_user"]
}
```

**Where to register:** GitLab → User Settings → Applications (or group/admin Applications for shared apps)

| Field | Value |
|-------|-------|
| Redirect URI | `https://example.com/auth/gitlab/callback` |
| Redirect URI (local dev) | `http://localhost:8080/auth/gitlab/callback` |
| Scopes to enable | `read_user` |

### Multiple providers at once

```go
Providers: []authkit.ProviderConfig{
    {Name: "bitbucket", ClientID: "...", ClientSecret: "..."},
    {Name: "github",    ClientID: "...", ClientSecret: "..."},
    {Name: "google",    ClientID: "...", ClientSecret: "..."},
    {Name: "gitlab",    ClientID: "...", ClientSecret: "..."},
},
```

Users can then choose their provider via the login URL:
- `GET /auth/bitbucket`
- `GET /auth/github`
- `GET /auth/google`
- `GET /auth/gitlab`

### Other providers

authkit ships convenience wrappers for Bitbucket, GitHub, Google, and GitLab. For any of the [80+ other providers](https://github.com/markbates/goth?tab=readme-ov-file#supported-providers) that goth supports (Spotify, Discord, Slack, Microsoft, Twitter, etc.), import the provider package directly and pass the pre-built value via `GothProviders`:

```go
import (
    "github.com/markbates/goth/providers/discord"
    "github.com/markbates/goth/providers/spotify"
)

auth, err := authkit.New(authkit.Config{
    // Built-in wrappers still work alongside GothProviders.
    Providers: []authkit.ProviderConfig{
        {Name: "github", ClientID: "...", ClientSecret: "..."},
    },
    GothProviders: []goth.Provider{
        spotify.New(os.Getenv("SPOTIFY_ID"), os.Getenv("SPOTIFY_SECRET"),
            "https://example.com/auth/spotify/callback", "user-read-email"),
        discord.New(os.Getenv("DISCORD_ID"), os.Getenv("DISCORD_SECRET"),
            "https://example.com/auth/discord/callback", "identify", "email"),
    },
    CallbackBaseURL: "https://example.com",
    // ...
})
```

The callback URL pattern is always `/auth/{providerName}/callback`, where `providerName` is whatever the goth provider reports via its `Name()` method (e.g. `"spotify"`, `"discord"`). Only the packages you import are compiled into your binary.

---

## HTTP Routes

| Method | Path | Handler | Mode | Description |
|--------|------|---------|------|-------------|
| `GET` | `/auth/{provider}` | `auth.BeginAuth` | OAuth / Both | Starts the OAuth flow |
| `GET` | `/auth/{provider}/callback` | `auth.Callback` | OAuth / Both | Completes the OAuth handshake |
| `POST` | `/auth/register` | `auth.Register` | Password / Both | Creates account with email+password |
| `POST` | `/auth/login` | `auth.Login` | Password / Both | Authenticates with email+password |
| `POST` | `/auth/logout` | `auth.Logout` | All | Clears the session |
| `GET` | `/auth/me` | `auth.Me` | All | Returns the current user as JSON |

### Optional routes (mount when the corresponding feature is enabled)

| Method | Path | Handler | Feature | Description |
|--------|------|---------|---------|-------------|
| `POST` | `/auth/2fa/enroll` | `auth.Enroll2FA` | TOTP | Provisions a TOTP secret + recovery codes |
| `POST` | `/auth/2fa/verify` | `auth.Verify2FA` | TOTP | Completes a pending 2FA login |
| `GET` | `/auth/csrf` | `auth.CSRFToken` | CSRF | Returns/issues a CSRF token as JSON |
| `GET` | `/authorize` | `auth.Authorize` | Token layer | PKCE authorization endpoint |
| `POST` | `/token` | `auth.IssueToken` | Token layer | Exchanges an auth code (+ PKCE verifier) for tokens |
| `POST` | `/token/refresh` | `auth.RefreshAccessToken` | Token layer | Rotates a refresh token for a new pair |
| `GET` | `/.well-known/jwks.json` | `auth.JWKS` | Token layer | Publishes the Ed25519 verification keys |
| `POST` | `/platform/login` | `auth.PlatformLogin` | Platform admin | Platform super-admin login (password + TOTP) |
| `POST` | `/platform/logout` | `auth.PlatformLogout` | Platform admin | Ends the platform session |

`/auth/me` example response:

```json
{
  "email": "alice@company.com",
  "name": "Alice",
  "avatarUrl": "https://avatars.githubusercontent.com/u/1234",
  "provider": "github",
  "role": "admin"
}
```

For password-auth users, `provider` will be `"password"` and `avatarUrl` will be empty.

---

## Middleware

### `RequireAuth` — enforce authentication (session or API key)

```go
mux.Handle("GET /api/reports", auth.RequireAuth(http.HandlerFunc(reportsHandler)))
```

Returns `401 Unauthenticated` if there is no valid credential. On success the current
`*authkit.User` is available via `authkit.UserFromCtx(r.Context())`.

Accepts API keys when `APIKeyValidator` is configured. Works identically for OAuth,
password-authenticated, and API key users.

### `Require(permission)` — enforce authentication + permission (session or API key)

```go
mux.Handle("POST /api/upload", auth.Require("upload")(http.HandlerFunc(handler)))
```

Returns `401` for missing credential, `403 Forbidden` when the user lacks the permission.
API keys are accepted when `APIKeyValidator` is configured.

### `RequireSessionAuth` — enforce a valid session (rejects API keys)

```go
mux.Handle("GET /auth/me", auth.RequireSessionAuth(http.HandlerFunc(meHandler)))
```

Same as `RequireAuth` but API key credentials are rejected even if `APIKeyValidator` is set.
Use this for UI-only routes that should never be accessible from automated clients.

### `RequireSession(permission)` — enforce session + permission (rejects API keys)

```go
mux.Handle("DELETE /api/environments/{id}", auth.RequireSession("manage")(http.HandlerFunc(handler)))
```

Same as `Require` but API keys are always rejected. Use this for management routes that
must only be operated by a logged-in human.

### Reading the current user inside a handler

```go
func reportsHandler(w http.ResponseWriter, r *http.Request) {
    u := authkit.UserFromCtx(r.Context())
    // u is always non-nil here because RequireAuth ran first.
    // Works for OAuth, password, and API key users.
    fmt.Fprintf(w, "Hello, %s (%s)", u.Name, u.Role)
}
```

---

## API Key Authentication

For programmatic access (CI/CD pipelines, scripts, service-to-service calls) authkit can validate API keys alongside OAuth/password sessions. Implement the `APIKeyValidator` interface and pass it to `Config`:

```go
type APIKeyValidator interface {
    ValidateKey(ctx context.Context, rawKey string) (*User, error)
}
```

Return `nil, nil` when the key is not found, inactive, or expired. Return `nil, err` only for unexpected infrastructure failures (e.g. a database connection error).

### Wiring it up

```go
auth, err := authkit.New(authkit.Config{
    // ... other fields ...
    APIKeyValidator: myKeyStore, // implements authkit.APIKeyValidator
})
```

### How it works

When `APIKeyValidator` is set, the middleware checks the `Authorization: Bearer <key>` header (or `X-API-Key: <key>` as a fallback) **before** the session cookie on every request. On a valid key:

1. `ValidateKey` returns a `*User` with `Email`, `Name`, `Provider`, and `Role` populated.
2. Authkit resolves `permissions` from the RBAC policy based on the returned `Role`.
3. The user is injected into the request context under the **same key** as session users — `UserFromCtx` works transparently for both.

### Middleware variants

| Middleware | API keys | Sessions | Use for |
|---|---|---|---|
| `auth.RequireAuth(next)` | ✓ | ✓ | General protected routes |
| `auth.Require(perm)(next)` | ✓ | ✓ | Permission-gated routes open to CI/CD |
| `auth.RequireSessionAuth(next)` | ✗ | ✓ | UI-only routes (e.g. `/auth/me`) |
| `auth.RequireSession(perm)(next)` | ✗ | ✓ | Management routes that must not accept keys |

```go
mux.Handle("GET /api/reports",   auth.Require("view")(reportsHandler))   // API keys OK
mux.Handle("POST /api/projects", auth.RequireSession("manage")(createH)) // session only
mux.Handle("GET /auth/me",       auth.RequireSessionAuth(meHandler))     // session only
```

### Example implementation

A minimal DB-backed key store:

```go
type KeyStore struct{ db *sql.DB }

func (s *KeyStore) ValidateKey(ctx context.Context, rawKey string) (*authkit.User, error) {
    hash := sha256Hex(rawKey)
    var name, role string
    err := s.db.QueryRowContext(ctx,
        "SELECT name, role FROM api_keys WHERE key_hash = ? AND is_active = 1", hash,
    ).Scan(&name, &role)
    if errors.Is(err, sql.ErrNoRows) {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    return &authkit.User{
        Email:    "apikey:" + name,
        Name:     name,
        Provider: "apikey",
        Role:     role,
    }, nil
}
```

The returned `User.Role` must match a role defined in `policy.yaml` for permissions to be resolved. If the role is not found in the policy the user is authenticated but has no permissions.

---

## Permissions

Permissions are **fully user-defined strings** — authkit does not prescribe any specific set. You define them in `policy.yaml` and enforce them in code.

The only built-in constant is `authkit.PermAll = "*"`, which is a wildcard that passes every permission check.

### Define permissions in policy.yaml

```yaml
roles:
  admin:
    permissions: ["*"]          # wildcard — passes every check

  editor:
    permissions: ["posts:write", "posts:publish", "media:upload"]

  reader:
    permissions: ["posts:read"]
```

### Enforce on a route

```go
mux.Handle("POST /posts",         auth.Require("posts:write")(http.HandlerFunc(createPost)))
mux.Handle("POST /posts/publish", auth.Require("posts:publish")(http.HandlerFunc(publishPost)))
mux.Handle("POST /media",         auth.Require("media:upload")(http.HandlerFunc(uploadMedia)))
```

### Check inline in a handler

```go
func handler(w http.ResponseWriter, r *http.Request) {
    u := authkit.UserFromCtx(r.Context())
    if !u.Can("posts:publish") {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    // ...
}
```

### Permission string format

Any alphanumeric string with `.` `:` `-` `_` is valid. Common conventions:

| Style | Example |
|-------|---------|
| Simple | `"read"`, `"write"`, `"delete"` |
| Namespaced | `"posts:read"`, `"posts:write"` |
| Dot-separated | `"reports.view"`, `"reports.export"` |
| Action-resource | `"create-project"`, `"delete-user"` |

There is no hierarchy — `"posts:read"` does not automatically grant `"posts"`. Each string is matched exactly.

---

## Live Policy Reload

`WatchRBAC` reloads the policy on every tick. If the reload fails the old policy is kept — users are never accidentally locked out. Works with any `PolicyProvider` that implements `PolicyReloader` (both the built-in YAML provider and `LayeredPolicyProvider` support this).

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Reload every 60 seconds.
go auth.WatchRBAC(ctx, 60*time.Second)
```

For the YAML-only provider: edit `policy.yaml` and wait for the next tick. No restart needed.

For `LayeredPolicyProvider`: the YAML baseline is reloaded on each tick. Database overrides are always read live on each login request.

If you supply a custom `PolicyProvider` that manages its own cache, simply do not implement `PolicyReloader` and `WatchRBAC` will exit immediately — your provider controls its own refresh strategy.

---

## Database-backed RBAC

By default, roles are read from a YAML file. For applications that need a management UI where operators can change user roles at runtime without touching files, authkit provides two additional mechanisms.

### Option 1: Layered provider (YAML baseline + database overrides)

Roles and their initial members are defined in `policy.yaml` as usual. Any user whose role is changed through your UI writes to a `UserRoleStore` — authkit checks the store first, falling back to YAML for everyone else.

**1. Implement `UserRoleStore`**

```go
type UserRoleStore interface {
    GetOverride(ctx context.Context, email string) (role string, permissions []string, found bool, err error)
    SetOverride(ctx context.Context, email, role string, permissions []string) error
    DeleteOverride(ctx context.Context, email string) error
}
```

A minimal Postgres implementation:

```go
type RoleStore struct{ db *sql.DB }

func (s *RoleStore) GetOverride(ctx context.Context, email string) (string, []string, bool, error) {
    var role, permsJSON string
    err := s.db.QueryRowContext(ctx,
        "SELECT role, permissions FROM role_overrides WHERE email = $1", email,
    ).Scan(&role, &permsJSON)
    if errors.Is(err, sql.ErrNoRows) {
        return "", nil, false, nil
    }
    if err != nil {
        return "", nil, false, err
    }
    var perms []string
    json.Unmarshal([]byte(permsJSON), &perms)
    return role, perms, true, nil
}

func (s *RoleStore) SetOverride(ctx context.Context, email, role string, permissions []string) error {
    permsJSON, _ := json.Marshal(permissions)
    _, err := s.db.ExecContext(ctx,
        `INSERT INTO role_overrides (email, role, permissions)
         VALUES ($1, $2, $3)
         ON CONFLICT (email) DO UPDATE SET role = $2, permissions = $3`,
        email, role, string(permsJSON),
    )
    return err
}

func (s *RoleStore) DeleteOverride(ctx context.Context, email string) error {
    _, err := s.db.ExecContext(ctx, "DELETE FROM role_overrides WHERE email = $1", email)
    return err
}
```

Required table:

```sql
CREATE TABLE role_overrides (
    email       TEXT PRIMARY KEY,
    role        TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]'
);
```

**2. Wire it up**

```go
roleStore := &RoleStore{db: db}

provider, err := authkit.NewLayeredProvider("policy.yaml", roleStore,
    authkit.WithLogger(myLogger), // optional: logs DB errors during role lookups
)
if err != nil {
    log.Fatal(err)
}

auth, err := authkit.New(authkit.Config{
    RBAC: authkit.RBACConfig{Provider: provider},
    // ... rest of config
})

go auth.WatchRBAC(ctx, 30*time.Second) // reloads the YAML baseline
```

**3. Change a user's role from a management handler**

Use `provider.SetOverride` — it validates the role name against the YAML policy and checks permission string format before writing to the store.

```go
func setRoleHandler(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    role  := r.FormValue("role")
    perms := rolesMap[role] // your app's role→permissions lookup

    if err := provider.SetOverride(r.Context(), email, role, perms); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    // Change takes effect on the user's next login.
}
```

> **Session note:** role changes take effect on the **next login** only. Existing sessions keep their current permissions until they expire (7 days by default) or the user logs out. If you need immediate enforcement for demotions, implement session invalidation at the application level.

**4. Reset a user to the YAML baseline**

```go
provider.DeleteOverride(ctx, "bob@example.com")
```

### Option 2: Fully custom `PolicyProvider`

If neither YAML nor the layered approach fits your needs, implement the `PolicyProvider` interface directly:

```go
type PolicyProvider interface {
    RoleFor(ctx context.Context, email string) (role string, permissions []string)
    PermissionsForRole(ctx context.Context, role string) []string
}
```

> **Tenant-aware resolution:** both methods receive a `context.Context` carrying the tenant (read it with `authkit.TenantIDFromCtx(ctx)`), so a DB-backed provider can scope role definitions per tenant. `PermissionsForRole` taking a `ctx` is required for API-key and live per-request resolution.

Pass your implementation via `RBACConfig.Provider`:

```go
auth, err := authkit.New(authkit.Config{
    RBAC: authkit.RBACConfig{Provider: myCustomProvider},
})
```

Optionally implement `PolicyReloader` to participate in `WatchRBAC`:

```go
type PolicyReloader interface {
    Reload() error
}
```

---

## Multi-Tenancy

Every authenticated principal carries a `TenantID` (and optional `BranchID`), making authkit suitable for multi-tenant SaaS where data is isolated per tenant (e.g. Postgres Row-Level Security).

```go
type User struct {
    Email     string
    Name      string
    AvatarURL string
    Provider  string
    Role      string
    TenantID  string // the hard security boundary
    BranchID  string // optional in-tenant scope (a row filter, not a permission)
    // ...
}
```

- **Where it comes from:** your `UserStore` (`PasswordUser.TenantID`/`BranchID`), the OAuth callback mapping, or the `APIKeyValidator` populate it. Email is global, so the lookup determines the tenant.
- **How authkit uses it:** before resolving permissions, authkit puts the tenant on the request context via `WithTenant`. Read it in your handlers and DB layer:

  ```go
  func handler(w http.ResponseWriter, r *http.Request) {
      tenantID, ok := authkit.TenantIDFromCtx(r.Context())
      if !ok {
          http.Error(w, "no tenant", http.StatusForbidden) // fail closed
          return
      }
      // e.g. set the per-transaction RLS GUC to tenantID before querying.
  }
  ```

- **Fail-closed:** `TenantIDFromCtx` returns `ok == false` for an empty/unset tenant — treat that as a hard deny.
- A tenant-aware `PolicyProvider` reads the same context to resolve roles per tenant (see [Database-backed RBAC](#database-backed-rbac)).

---

## Server-Side Sessions

By default authkit stores the session in an encrypted cookie (stateless). For instant revocation and "log out everywhere", provide a `SessionStore` — the cookie then carries only an opaque session ID and all identity state lives in your store (DB or Redis).

```go
type SessionStore interface {
    Create(ctx context.Context, s *authkit.Session) error
    Get(ctx context.Context, id string) (*authkit.Session, error)
    Touch(ctx context.Context, id string, lastSeen time.Time) error
    Revoke(ctx context.Context, id string) error
    RevokeAllForUser(ctx context.Context, tenantID, email string) error
}
```

```go
auth, err := authkit.New(authkit.Config{
    SessionStore:    myStore,           // implements authkit.SessionStore
    IdleTimeout:     30 * time.Minute,  // sliding; default 30m
    AbsoluteTimeout: 24 * time.Hour,    // hard cap; default 24h
    // ...
})
```

- **Session fixation prevention:** a fresh session ID is minted on every login; any prior session is revoked.
- **Sliding idle renewal:** `LastSeenAt` is advanced at most once per minute (throttled writes).
- **`__Host-` cookie prefix** is used when `SecureCookie` is true.
- **Log out everywhere** (e.g. on password reset or firing an employee):

  ```go
  err := auth.RevokeUserSessions(ctx, tenantID, "bob@example.com")
  ```

  `ctx` must carry the user's tenant. No-op when no `SessionStore` is configured.

> The token layer, platform admin, and 2FA features require a `SessionStore` for their session/revocation semantics.

---

## Two-Factor Authentication (TOTP)

Enforce a second factor for sensitive roles. After the password step, users whose role is in `Require2FAForRoles` must complete a TOTP challenge (authenticator app) before a session is minted.

```go
type TOTPStore interface {
    Enroll(ctx context.Context, tenantID, email, secret string, recoveryCodeHashes []string) error
    Secret(ctx context.Context, tenantID, email string) (secret string, enrolled bool, err error)
    ConsumeRecovery(ctx context.Context, tenantID, email, codeHash string) (bool, error)
}
```

```go
auth, err := authkit.New(authkit.Config{
    TOTPStore:          myTOTPStore,                  // implements authkit.TOTPStore
    Require2FAForRoles: []string{"owner", "manager"}, // which roles must complete 2FA
    AppName:            "Acme",                       // issuer shown in authenticator apps
    Throttler:          myThrottler,                  // recommended — throttles 2FA attempts too
    // ...
})

mux.HandleFunc("POST /auth/2fa/enroll", auth.Enroll2FA)
mux.HandleFunc("POST /auth/2fa/verify", auth.Verify2FA)
```

**Flow:**

1. `POST /auth/login` with a 2FA-required role responds `{"status":"2fa_required","action":"enroll"|"verify"}` and sets a short-lived (5 min) pending cookie instead of a session.
2. If `action == "enroll"`, call `POST /auth/2fa/enroll` to get an `otpauthUrl` (render as a QR code), the raw `secret`, and one-time `recoveryCodes` to display once.
3. `POST /auth/2fa/verify` with form value `code` (6-digit TOTP) **or** `recovery_code` completes the login and establishes the session.

- The host store is responsible for **encrypting the secret at rest** — authkit passes plaintext at the interface boundary.
- Recovery codes are single-use; authkit stores only SHA-256 hashes and `ConsumeRecovery` must mark them used atomically.
- `Enroll2FA` also works for voluntary enrollment from an already-authenticated session.

---

## Mobile Token Layer (OAuth2 + PKCE)

For native/mobile clients, authkit can issue Ed25519-signed access JWTs and rotating opaque refresh tokens via the OAuth2 Authorization Code flow with PKCE.

```go
signing, _ := authkit.NewSigningKey("key-2026-01", seed) // seed is 32 random bytes

auth, err := authkit.New(authkit.Config{
    EnableTokens:      true,
    SigningKeys:       []authkit.SigningKey{signing}, // first key signs; all verify (key rotation)
    RefreshTokenStore: myRefreshStore,                // implements authkit.RefreshTokenStore
    AccessTokenTTL:    15 * time.Minute,              // default 15m
    RefreshTokenTTL:   30 * 24 * time.Hour,           // default 30d
    TokenIssuer:       "https://api.example.com",     // JWT `iss`
    TokenClientID:     "mobile-app",                  // public client id + JWT audience
    TokenRedirectURIs: []string{"acme://callback"},   // allowed PKCE redirect URIs
    // ...
})

mux.HandleFunc("GET  /authorize",              auth.Authorize)
mux.HandleFunc("POST /token",                  auth.IssueToken)
mux.HandleFunc("POST /token/refresh",          auth.RefreshAccessToken)
mux.HandleFunc("GET  /.well-known/jwks.json",  auth.JWKS)
```

```go
type RefreshTokenStore interface {
    Create(ctx context.Context, t *authkit.RefreshToken) error
    Get(ctx context.Context, rawToken string) (*authkit.RefreshToken, error)
    Rotate(ctx context.Context, rawOld string, next *authkit.RefreshToken) error
    RevokeChain(ctx context.Context, chainID string) error
}
```

**Flow:**

1. The app opens `GET /authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...&code_challenge_method=S256` in the system browser. The user must already have a web session (the browser carries the cookie); otherwise they are bounced to login.
2. authkit redirects back to `redirect_uri?code=...`. The app calls `POST /token` with `grant_type=authorization_code`, `code`, `code_verifier`, and `redirect_uri` to receive `{access_token, refresh_token, token_type, expires_in}`.
3. The app calls protected APIs with `Authorization: Bearer <access_token>`. `Require`/`RequireAuth` verify the JWT against the JWKS.
4. `POST /token/refresh` with `refresh_token` rotates the pair.

**Security properties:**

- **Permissions are never in the JWT** — they're resolved server-side per request, so role/permission changes take effect within one access-token TTL.
- **Refresh-token rotation with reuse detection:** presenting an already-used or revoked refresh token revokes the entire chain (theft response) and emits an audit `revoke` event.
- **Refresh tokens are opaque**; the store must hash them at rest.
- **Key rotation:** the first `SigningKey` signs; all keys verify and are published via JWKS, so a key can be retired without invalidating tokens it already signed.

---

## Platform Super-Admin

A platform principal is a SaaS operator acting across tenants — a separate axis from tenant RBAC, with **no `TenantID`**. Platform login requires password **and** mandatory TOTP, and uses its own cookie (never crosses with tenant sessions).

```go
type PlatformAdminStore interface {
    GetPlatformAdmin(ctx context.Context, email string) (*authkit.PlatformAdminRecord, error)
}

type PlatformPolicy interface {
    PermissionsForPlatformRole(role string) []string // small static capability catalog
}
```

```go
auth, err := authkit.New(authkit.Config{
    SessionStore:        myStore, // required for platform sessions
    PlatformAdminStore:  myPlatformStore,
    PlatformPolicy:      myPlatformPolicy,
    EnableImpersonation: true, // gates break-glass single-tenant access
    // ...
})

mux.HandleFunc("POST /platform/login",  auth.PlatformLogin)  // form: email, password, code
mux.HandleFunc("POST /platform/logout", auth.PlatformLogout)

// Protect platform routes with a platform capability check:
mux.Handle("GET /platform/tenants",
    auth.RequirePlatformAdmin("platform:tenants.read")(http.HandlerFunc(listTenants)))
```

- Read the principal inside a handler with `authkit.PlatformAdminFromCtx(r.Context())`.
- `RequirePlatformAdmin` **never** sets a tenant GUC — a platform admin's DB role has no cross-tenant bypass.
- **Break-glass impersonation** lets an admin act within exactly one tenant; it requires the `platform:impersonate` capability and is audited:

  ```go
  ctx, err := auth.ImpersonationContext(r.Context(), admin, tenantID)
  // ctx is now tenant-scoped; downstream queries run under normal RLS for that one tenant.
  ```

---

## Device Principals

A device principal is a headless print agent (not a human) confined to a fixed, tiny capability set defined in code — it can receive print jobs and report status, and **nothing else** in the API. It is a separate credential path from the human/API-key flow.

```go
type DeviceTokenValidator interface {
    ValidateDeviceToken(ctx context.Context, rawToken string) (*authkit.DeviceRecord, error)
}
```

```go
auth, err := authkit.New(authkit.Config{
    DeviceTokenValidator: myDeviceValidator,
    // ...
})

// Fixed device capabilities (the whole of what a device may ever do):
//   authkit.CapPrintJobReceive   = "print:job.receive"
//   authkit.CapPrintStatusReport = "print:status.report"
mux.Handle("GET /agent/jobs",
    auth.RequireDevice(authkit.CapPrintJobReceive)(http.HandlerFunc(jobsHandler)))
```

- The device presents an opaque token via `Authorization: Bearer` / `X-API-Key`; the store hashes it at rest and looks it up pre-tenant.
- On success, `RequireDevice` binds the device's tenant **and** branch on the context. Read the principal with `authkit.DeviceFromCtx(ctx)`.
- A device never resolves permissions from a policy — it can never hold `"*"` or any tenant capability.
- `RequireDevice` **panics at startup** if given a non-device capability (a wiring mistake caught early). `AuthenticateDevice` is also exposed for non-HTTP paths (e.g. a WebSocket upgrade).

---

## CSRF Protection

For cookie-authenticated SPAs, enable signed double-submit CSRF protection. Token-authenticated requests (Bearer / API key) carry no ambient cookie credential and are always exempt.

```go
auth, err := authkit.New(authkit.Config{
    EnableCSRF: true,
    // ...
})

// Wrap state-changing, cookie-authenticated routes:
mux.Handle("POST /api/projects", auth.CSRF(auth.Require("projects:write")(createHandler)))

// Optional explicit token endpoint for SPAs that fetch it:
mux.HandleFunc("GET /auth/csrf", auth.CSRFToken)
```

- The token is delivered in a JS-readable cookie and must be echoed back in the `X-CSRF-Token` header on unsafe methods (`POST`/`PUT`/`PATCH`/`DELETE`).
- The server checks both that the header matches the cookie **and** that the token carries a valid HMAC (signed with `SessionSecret`), so a subdomain that can set cookies still can't forge a signed token.
- Safe methods (`GET`/`HEAD`/`OPTIONS`/`TRACE`) pass through and bootstrap the cookie.

---

## Login Throttling

Blunt brute-force and credential-stuffing attacks by plugging in a rate limiter (e.g. backed by Redis). authkit calls it around password login, 2FA verification, and platform login, keyed per account+IP.

```go
type LoginThrottler interface {
    Allow(ctx context.Context, key string) (retryAfter time.Duration, ok bool)
    RecordFailure(ctx context.Context, key string) error
    Reset(ctx context.Context, key string) error
}
```

```go
auth, err := authkit.New(authkit.Config{
    Throttler: myThrottler, // implements authkit.LoginThrottler
    // ...
})
```

- When locked out, authkit responds `429 Too Many Requests` with a `Retry-After` header.
- A successful login calls `Reset` to clear the failure counter.
- authkit uses `RemoteAddr` for the client IP and **does not** trust `X-Forwarded-For` — behind a proxy, set `RemoteAddr` from a vetted header before authkit sees the request.

---

## Live Permission Resolution

By default a session's permissions are resolved once at login and cached in the session, so role changes take effect on next login. Enable `LivePermissionResolution` to re-resolve permissions from the `PolicyProvider` on every request, through a short TTL cache — useful for multi-tenant deployments where operators change roles at runtime.

```go
auth, err := authkit.New(authkit.Config{
    LivePermissionResolution: true,
    PermissionCacheTTL:       30 * time.Second, // default 30s
    // ...
})
```

- API-key and token (JWT) credentials **always** resolve live, regardless of this flag.
- Leave it off for single-shop deployments to keep the cheaper login-time cache.

---

## Audit Events

Wire an `AuditSink` to persist structured security events to your audit log.

```go
type AuditSink interface {
    Emit(ctx context.Context, ev authkit.AuditEvent)
}

type AuditEvent struct {
    Type     string // see constants below
    TenantID string
    Actor    string // who performed the action
    Subject  string // who/what it acted on
    IP       string
    At       time.Time
    Meta     map[string]any
}
```

```go
auth, err := authkit.New(authkit.Config{
    AuditSink: myAuditSink, // defaults to a no-op sink when nil
    // ...
})
```

Well-known event types: `AuditLogin`, `AuditLogout`, `AuditRefresh`, `AuditRevoke`, `Audit2FAEnroll`, `Audit2FAVerify`, `AuditRoleChange`, `AuditPermissionChange`, `AuditImpersonate`.

> **Don't block the request path** — implementations must buffer or hand off slow I/O. `Emit` is best-effort and never returns an error to authkit.

---

## Policy YAML Reference

```yaml
roles:
  <role-name>:
    # List of permission strings granted to this role.
    # Use "*" for superuser access.
    permissions: ["view", "upload"]

    # Emails assigned to this role (case-insensitive).
    members:
      - user@example.com

# Optional: role assigned to authenticated users whose email is not
# listed under any role. Omit to deny access to unknown users.
default_role: viewer
```

Role names must be alphanumeric (with hyphens/underscores). Permission names must be alphanumeric (with dots, colons, hyphens, underscores, or `*`). Member emails are validated for basic format.

---

## Configuration Reference

```go
authkit.Config{
    // Optional: auth mode. Default: authkit.AuthModeOAuth
    // Options: authkit.AuthModeOAuth, authkit.AuthModePassword, authkit.AuthModeBoth
    Mode: authkit.AuthModeOAuth,

    // Required when OAuth is enabled: providers to register.
    Providers: []authkit.ProviderConfig{...},

    // Required when OAuth is enabled: externally-reachable base URL (no trailing slash).
    CallbackBaseURL: "https://example.com",

    // Required: secret used to sign+encrypt session cookies.
    // Must be at least 32 bytes. Generate with: openssl rand -hex 32
    SessionSecret: "...",

    // Optional: set true for production HTTPS deployments. Default: false
    SecureCookie: true,

    // Optional: redirect target after successful login. Default: "/"
    AfterLoginURL: "/dashboard",

    // Optional: redirect target after logout. Default: "/"
    AfterLogoutURL: "/",

    // Optional: RBAC policy.
    // YAML only (default):
    RBAC: authkit.RBACConfig{FilePath: "policy.yaml"},
    // Layered (YAML baseline + database overrides):
    // RBAC: authkit.RBACConfig{Provider: authkit.NewLayeredProvider("policy.yaml", store)},
    // Fully custom:
    // RBAC: authkit.RBACConfig{Provider: myProvider},

    // Required when password auth is enabled: storage backend.
    UserStore: myUserStore,

    // Optional: password validation rules. Default: min 8 characters.
    PasswordPolicy: &authkit.PasswordPolicy{MinLength: 12},

    // Optional: custom logger. Default: standard log package.
    Logger: myLogger, // implements authkit.Logger

    // Optional: enables API key authentication alongside sessions.
    // When set, Require/RequireAuth accept Bearer tokens validated by this.
    // RequireSession/RequireSessionAuth always reject API keys regardless.
    APIKeyValidator: myKeyStore, // implements authkit.APIKeyValidator

    // Optional: structured security audit events. Default: no-op sink.
    AuditSink: myAuditSink, // implements authkit.AuditSink

    // Optional: re-resolve session permissions per request (TTL-cached).
    // Default: false (resolve once at login). PermissionCacheTTL default: 30s.
    LivePermissionResolution: true,
    PermissionCacheTTL:       30 * time.Second,

    // Optional: revocable server-side sessions. When nil, encrypted cookie sessions.
    SessionStore:    myStore,          // implements authkit.SessionStore
    IdleTimeout:     30 * time.Minute, // sliding; default 30m
    AbsoluteTimeout: 24 * time.Hour,   // hard cap; default 24h

    // Optional: CSRF double-submit middleware for cookie auth.
    EnableCSRF: true,

    // Optional: per-account+IP login rate limiting.
    Throttler: myThrottler, // implements authkit.LoginThrottler

    // Optional: two-factor auth (TOTP).
    TOTPStore:          myTOTPStore, // implements authkit.TOTPStore
    Require2FAForRoles: []string{"owner", "manager"},
    AppName:            "Acme", // issuer shown in authenticator apps; default "App"

    // Optional: mobile token layer (OAuth2 + PKCE + Ed25519 JWTs).
    EnableTokens:      true,
    SigningKeys:       []authkit.SigningKey{signingKey},
    RefreshTokenStore: myRefreshStore, // implements authkit.RefreshTokenStore
    AccessTokenTTL:    15 * time.Minute,    // default 15m
    RefreshTokenTTL:   30 * 24 * time.Hour, // default 30d
    TokenIssuer:       "https://api.example.com",
    TokenClientID:     "mobile-app",
    TokenRedirectURIs: []string{"acme://callback"},

    // Optional: platform super-admin axis + break-glass impersonation.
    PlatformAdminStore:  myPlatformStore,  // implements authkit.PlatformAdminStore
    PlatformPolicy:      myPlatformPolicy, // implements authkit.PlatformPolicy
    EnableImpersonation: true,

    // Optional: device principals (confined print agents).
    DeviceTokenValidator: myDeviceValidator, // implements authkit.DeviceTokenValidator
}
```

---

## Session Security

By default, sessions are stored in encrypted cookies (stateless). For revocable, server-side sessions with idle/absolute timeouts and "log out everywhere", see [Server-Side Sessions](#server-side-sessions).

- Sessions are stored in **encrypted, signed cookies** (`gorilla/sessions` + `securecookie`).
- Cookie flags: `HttpOnly`, `SameSite=Lax`, 7-day `MaxAge`.
- Set `SecureCookie: true` in production to add the `Secure` flag (HTTPS only).
- The `SessionSecret` must be at least 32 bytes of cryptographically random data:
  ```bash
  openssl rand -hex 32
  ```
- A startup warning is logged if `SecureCookie` is `false`.
