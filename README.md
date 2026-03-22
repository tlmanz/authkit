[![CI](https://github.com/tlmanz/authkit/actions/workflows/ci.yml/badge.svg)](https://github.com/tlmanz/authkit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tlmanz/authkit/actions/workflows/codequality.yml/badge.svg)](https://github.com/tlmanz/authkit/actions/workflows/codequality.yml)
[![Coverage Status](https://coveralls.io/repos/github/tlmanz/authkit/badge.svg)](https://coveralls.io/github/tlmanz/authkit)
![Open Issues](https://img.shields.io/github/issues/tlmanz/authkit)
[![Go Report Card](https://goreportcard.com/badge/github.com/tlmanz/authkit)](https://goreportcard.com/report/github.com/tlmanz/authkit)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/tlmanz/authkit)

# authkit

Plug-and-play authentication with YAML-based RBAC for Small Go HTTP services.

- **OAuth 2.0** via [markbates/goth](https://github.com/markbates/goth) — supports **GitHub**, **Google**, **GitLab** out of the box
- **Email/password** authentication with bcrypt hashing
- **API key authentication** — plug in any key store via a single-method interface
- **Three modes**: OAuth only, password only, or both simultaneously
- Encrypted cookie sessions via [gorilla/sessions](https://github.com/gorilla/sessions)
- Role-Based Access Control defined in a single YAML file
- Live policy reload without restarts (`WatchRBAC`)
- Works with Go 1.22+ stdlib `net/http` (no external router required)
- Storage-agnostic — implement a 2-method interface for your database
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
| OAuth only | `authkit.AuthModeOAuth` | Yes | No | SSO with GitHub/Google/GitLab |
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
    {Name: "github", ClientID: "...", ClientSecret: "..."},
    {Name: "google", ClientID: "...", ClientSecret: "..."},
    {Name: "gitlab", ClientID: "...", ClientSecret: "..."},
},
```

Users can then choose their provider via the login URL:
- `GET /auth/github`
- `GET /auth/google`
- `GET /auth/gitlab`

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

`WatchRBAC` reloads the policy file on every tick. If the file is invalid the old
policy is kept — users are never accidentally locked out.

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Reload every 60 seconds.
go auth.WatchRBAC(ctx, 60*time.Second)
```

To apply a change: edit `policy.yaml` and wait for the next tick. No restart needed.

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

    // Optional: RBAC policy. Leave FilePath empty to start with no policy.
    RBAC: authkit.RBACConfig{FilePath: "policy.yaml"},

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
}
```

---

## Session Security

- Sessions are stored in **encrypted, signed cookies** (`gorilla/sessions` + `securecookie`).
- Cookie flags: `HttpOnly`, `SameSite=Lax`, 7-day `MaxAge`.
- Set `SecureCookie: true` in production to add the `Secure` flag (HTTPS only).
- The `SessionSecret` must be at least 32 bytes of cryptographically random data:
  ```bash
  openssl rand -hex 32
  ```
- A startup warning is logged if `SecureCookie` is `false`.
