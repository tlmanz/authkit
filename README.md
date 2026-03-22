# authkit

Plug-and-play authentication with YAML-based RBAC for Small Go HTTP services.

- **OAuth 2.0** via [markbates/goth](https://github.com/markbates/goth) — supports **GitHub**, **Google**, **GitLab** out of the box
- **Email/password** authentication with bcrypt hashing
- **Three modes**: OAuth only, password only, or both simultaneously
- Encrypted cookie sessions via [gorilla/sessions](https://github.com/gorilla/sessions)
- Role-Based Access Control defined in a single YAML file
- Live policy reload without restarts (`WatchRBAC`)
- Works with Go 1.22+ stdlib `net/http` (no external router required)
- Storage-agnostic — implement a 2-method interface for your database

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
mux.Handle("POST /api/projects", auth.Require(authkit.PermManage)(http.HandlerFunc(createHandler)))
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

Callback URL to register in GitHub: `https://example.com/auth/github/callback`

### Google

```go
authkit.ProviderConfig{
    Name:         "google",
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    // Default scopes: ["email", "profile"]
}
```

Callback URL to register in Google Cloud Console: `https://example.com/auth/google/callback`

### GitLab

```go
authkit.ProviderConfig{
    Name:         "gitlab",
    ClientID:     os.Getenv("GITLAB_CLIENT_ID"),
    ClientSecret: os.Getenv("GITLAB_CLIENT_SECRET"),
    // Default scope: ["read_user"]
}
```

Callback URL to register in GitLab: `https://example.com/auth/gitlab/callback`

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

### `RequireAuth` — enforce a valid session

```go
mux.Handle("GET /api/reports", auth.RequireAuth(http.HandlerFunc(reportsHandler)))
```

Returns `401 Unauthenticated` if there is no valid session. On success the current
`*authkit.User` is available via `authkit.UserFromCtx(r.Context())`.

Works identically for OAuth and password-authenticated users.

### `Require(permission)` — enforce a permission

```go
mux.Handle("POST /api/projects", auth.Require(authkit.PermManage)(http.HandlerFunc(handler)))
```

Returns `401` for missing session, `403 Forbidden` when the user lacks the permission.

### Reading the current user inside a handler

```go
func reportsHandler(w http.ResponseWriter, r *http.Request) {
    u := authkit.UserFromCtx(r.Context())
    // u is always non-nil here because RequireAuth ran first.
    fmt.Fprintf(w, "Hello, %s (%s)", u.Name, u.Role)
}
```

---

## Permissions

Built-in permission constants:

| Constant | Value | Intended use |
|----------|-------|-------------|
| `authkit.PermView` | `"view"` | Read-only access |
| `authkit.PermUpload` | `"upload"` | Upload / trigger actions |
| `authkit.PermManage` | `"manage"` | Create / update / delete |
| `authkit.PermAll` | `"*"` | Wildcard — grants every check |

You can define your own permission strings in the YAML and check them with `Require` or `User.Can`:

```go
// Custom permission string in policy.yaml: ["view", "upload", "deploy"]
mux.Handle("POST /deploy", auth.Require("deploy")(deployHandler))

// Or check inline:
func handler(w http.ResponseWriter, r *http.Request) {
    u := authkit.UserFromCtx(r.Context())
    if !u.Can("deploy") {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    // ...
}
```

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
