# authkit Integration Guide

This document contains everything needed to integrate `github.com/tlmanz/authkit` into a Go HTTP application. It is designed to be consumed by AI agents, human developers, or used as a reference during implementation.

---

## What authkit does

authkit is a Go authentication library that provides:

- OAuth 2.0 login (GitHub, Google, GitLab)
- Email/password login with bcrypt
- Encrypted cookie-based sessions
- Role-based access control (RBAC) via YAML file or a pluggable `PolicyProvider` interface
- Layered RBAC: seed from YAML, let a UI override individual users via a database
- `net/http` middleware for protecting routes
- Pluggable logger interface (bring your own or use the default)

It does NOT include: database drivers, user registration UI, rate limiting, or email verification. These are the consumer's responsibility.

---

## Prerequisites

- Go 1.22 or later (uses `net/http` path values like `{provider}`)
- `go get github.com/tlmanz/authkit`

---

## Step-by-step integration

### Step 1: Decide on auth mode

authkit supports three modes. Choose one:

| Mode | Constant | When to use |
|------|----------|-------------|
| OAuth only | `authkit.AuthModeOAuth` | Apps using GitHub/Google/GitLab SSO |
| Password only | `authkit.AuthModePassword` | Traditional email+password apps |
| Both | `authkit.AuthModeBoth` | Apps offering both OAuth and password login |

If you omit `Mode`, it defaults to `AuthModeOAuth`.

### Step 2: Implement UserStore (password mode only)

If using password or both mode, implement the `authkit.UserStore` interface. This is how authkit reads and writes user data — you provide the storage layer.

```go
type UserStore interface {
    CreateUser(ctx context.Context, email, name, hashedPassword string) error
    GetUserByEmail(ctx context.Context, email string) (*authkit.PasswordUser, error)
}
```

**Important rules for your implementation:**

- `CreateUser` receives a **pre-hashed** bcrypt password. Store it as-is. Never re-hash it.
- `CreateUser` MUST return `authkit.ErrUserExists` if a user with that email already exists.
- `GetUserByEmail` MUST return `authkit.ErrUserNotFound` if no user matches.
- Email lookups should be case-insensitive (authkit normalizes to lowercase before calling).

**Example implementation with PostgreSQL:**

```go
package store

import (
    "context"
    "database/sql"
    "errors"

    "github.com/tlmanz/authkit"
)

type PostgresUserStore struct {
    db *sql.DB
}

func NewPostgresUserStore(db *sql.DB) *PostgresUserStore {
    return &PostgresUserStore{db: db}
}

func (s *PostgresUserStore) CreateUser(ctx context.Context, email, name, hashedPassword string) error {
    _, err := s.db.ExecContext(ctx,
        `INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3)`,
        email, name, hashedPassword,
    )
    if err != nil {
        // Check for unique constraint violation — adapt to your driver.
        if isUniqueViolation(err) {
            return authkit.ErrUserExists
        }
        return err
    }
    return nil
}

func (s *PostgresUserStore) GetUserByEmail(ctx context.Context, email string) (*authkit.PasswordUser, error) {
    var u authkit.PasswordUser
    err := s.db.QueryRowContext(ctx,
        `SELECT email, name, password_hash FROM users WHERE email = $1`,
        email,
    ).Scan(&u.Email, &u.Name, &u.HashedPassword)
    if errors.Is(err, sql.ErrNoRows) {
        return nil, authkit.ErrUserNotFound
    }
    if err != nil {
        return nil, err
    }
    return &u, nil
}
```

**Required database table (PostgreSQL example):**

```sql
CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Example implementation with in-memory map (for testing/prototyping):**

```go
package store

import (
    "context"
    "sync"

    "github.com/tlmanz/authkit"
)

type MemoryUserStore struct {
    mu    sync.RWMutex
    users map[string]*authkit.PasswordUser
}

func NewMemoryUserStore() *MemoryUserStore {
    return &MemoryUserStore{users: make(map[string]*authkit.PasswordUser)}
}

func (m *MemoryUserStore) CreateUser(_ context.Context, email, name, hashed string) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    if _, exists := m.users[email]; exists {
        return authkit.ErrUserExists
    }
    m.users[email] = &authkit.PasswordUser{Email: email, Name: name, HashedPassword: hashed}
    return nil
}

func (m *MemoryUserStore) GetUserByEmail(_ context.Context, email string) (*authkit.PasswordUser, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    u, ok := m.users[email]
    if !ok {
        return nil, authkit.ErrUserNotFound
    }
    return u, nil
}
```

### Step 3: Configure RBAC

authkit supports three RBAC backends. Choose one:

| Backend | `RBACConfig` | When to use |
|---------|-------------|-------------|
| YAML only | `FilePath: "policy.yaml"` | Roles managed entirely in files; no UI needed |
| Layered (YAML + DB) | `Provider: NewLayeredProvider(...)` | YAML defines initial roles; UI can override per user |
| Fully custom | `Provider: myProvider` | You supply your own `PolicyProvider` implementation |

#### Option A — YAML only (default)

Create a `policy.yaml` file. This controls who has which permissions.

```yaml
roles:
  admin:
    permissions: ["*"]           # wildcard — passes every permission check
    members:
      - alice@company.com

  editor:
    permissions: ["posts:write", "posts:publish", "media:upload"]
    members:
      - bob@company.com
      - carol@company.com

  reader:
    permissions: ["posts:read"]  # no members — used as default_role below

default_role: reader
```

**Permissions are fully user-defined.** Choose names that match your application's domain. Common naming conventions:

| Style | Example |
|-------|---------|
| Simple verbs | `"read"`, `"write"`, `"delete"` |
| Namespaced | `"posts:read"`, `"posts:write"`, `"posts:publish"` |
| Dot-separated | `"reports.view"`, `"reports.export"` |
| Action-resource | `"create-project"`, `"delete-user"` |

The only built-in constant is `authkit.PermAll = "*"` — a wildcard that passes every `Can()` check. All other permission strings are yours to define.

**Rules:**
- Role names must be alphanumeric with hyphens or underscores (e.g., `admin`, `power-user`, `team_lead`)
- Permission names must be alphanumeric with dots, colons, hyphens, or underscores, or `"*"`
- Permission strings are matched exactly — `"posts"` does not grant `"posts:read"`
- `default_role` is optional — fallback for authenticated users not listed under any role. Omit to deny access to unlisted users entirely.
- Members are matched case-insensitively

#### Option B — Layered provider (YAML baseline + database overrides)

Use this when you want operators to change user roles through a management UI without editing files. The YAML file defines roles and their initial members. Per-user overrides are stored in a database and take precedence over YAML.

**1. Implement `UserRoleStore`**

```go
type UserRoleStore interface {
    // Return found=false when no DB override exists — authkit falls back to YAML.
    GetOverride(ctx context.Context, email string) (role string, permissions []string, found bool, err error)
    // Called from your management UI to change a user's role.
    SetOverride(ctx context.Context, email, role string, permissions []string) error
    // Revert a user to the YAML baseline by removing their override.
    DeleteOverride(ctx context.Context, email string) error
}
```

A Postgres example:

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

**2. Create the provider and pass it to `New()`**

Pass `authkit.WithLogger(l)` so that DB errors during role lookups are logged rather than silently swallowed.

```go
provider, err := authkit.NewLayeredProvider("policy.yaml", &RoleStore{db: db},
    authkit.WithLogger(myLogger),
)
if err != nil {
    log.Fatal(err)
}

auth, err := authkit.New(authkit.Config{
    RBAC: authkit.RBACConfig{Provider: provider},
    // ... rest of config
})

// WatchRBAC reloads the YAML baseline; DB overrides are always read live.
go auth.WatchRBAC(ctx, 30*time.Second)
```

**3. Change a user's role from a management handler**

Use `provider.SetOverride` — it validates the role name against the YAML policy and checks permission string format before writing to the store. Do **not** call `provider.Store().SetOverride` directly from handlers, as it bypasses these checks.

```go
func setRoleHandler(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    role  := r.FormValue("role")
    perms := rolesMap[role] // your app's role→permissions lookup

    if err := provider.SetOverride(r.Context(), email, role, perms); err != nil {
        // err is descriptive: invalid email, unknown role, bad permission format
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    // Change takes effect on the user's next login.
}
```

> **Session note:** role changes take effect on the **next login** only. Existing sessions keep their current permissions until they expire (7 days by default) or the user logs out. If a demotion must be enforced immediately, the application must invalidate the user's session — this requires a server-side session store and is outside the scope of authkit.

**4. Revert a user to their YAML role**

```go
provider.DeleteOverride(ctx, "bob@example.com")
```

#### Option C — Fully custom `PolicyProvider`

For complete control, implement the `PolicyProvider` interface and supply it via `RBACConfig.Provider`. See the API reference below for the interface definition.

### Step 4: Generate a session secret

```bash
openssl rand -hex 32
```

Store this as an environment variable. Never hardcode it.

### Step 5: Set up OAuth provider credentials (if using OAuth)

For each provider you want to support:

**GitHub**

1. Go to [github.com/settings/developers](https://github.com/settings/developers) → New OAuth App
2. Set **Authorization callback URL** to:
   - Production: `https://your-domain.com/auth/github/callback`
   - Local dev: `http://localhost:8080/auth/github/callback`
3. Copy the **Client ID** and generate a **Client Secret**

**Google**

1. Go to Google Cloud Console → APIs & Services → Credentials → Create OAuth Client ID
2. Choose application type: **Web application**
3. Under **Authorized redirect URIs**, add:
   - Production: `https://your-domain.com/auth/google/callback`
   - Local dev: `http://localhost:8080/auth/google/callback`
4. Google allows multiple URIs per client — add both at once
5. Copy the **Client ID** and **Client Secret**

**GitLab**

1. Go to GitLab → User Settings → Applications (or group/admin Applications for shared apps)
2. Set **Redirect URI** to:
   - Production: `https://your-domain.com/auth/gitlab/callback`
   - Local dev: `http://localhost:8080/auth/gitlab/callback`
3. Enable scope: `read_user`
4. Copy the **Application ID** (this is the Client ID) and **Secret**

> The callback URL pattern is always `{CallbackBaseURL}/auth/{provider}/callback`. If you change `CallbackBaseURL` in your config, update the registered URL in the provider console to match.

Store client IDs and secrets as environment variables — never hardcode them in source.

### Step 6: Initialize authkit and register routes

Below are complete `main.go` examples for each mode.

**OAuth only:**

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/tlmanz/authkit"
)

func main() {
    auth, err := authkit.New(authkit.Config{
        Providers: []authkit.ProviderConfig{
            {
                Name:         "github",
                ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
                ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
            },
        },
        CallbackBaseURL: os.Getenv("BASE_URL"), // e.g. "https://example.com"
        SessionSecret:   os.Getenv("SESSION_SECRET"),
        SecureCookie:    os.Getenv("ENV") == "production",
        AfterLoginURL:   "/dashboard",
        AfterLogoutURL:  "/",
        RBAC:            authkit.RBACConfig{FilePath: "policy.yaml"},
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()
    go auth.WatchRBAC(ctx, 30*time.Second)

    mux := http.NewServeMux()

    // Auth routes
    mux.HandleFunc("GET /auth/{provider}",          auth.BeginAuth)
    mux.HandleFunc("GET /auth/{provider}/callback", auth.Callback)
    mux.HandleFunc("POST /auth/logout",             auth.Logout)
    mux.HandleFunc("GET /auth/me",                  auth.Me)

    // Protected routes
    mux.Handle("GET /api/data", auth.RequireAuth(http.HandlerFunc(dataHandler)))
    mux.Handle("POST /api/admin", auth.Require("admin:write")(http.HandlerFunc(adminHandler)))

    log.Println("listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
    u := authkit.UserFromCtx(r.Context())
    w.Write([]byte("Hello, " + u.Name))
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("admin action completed"))
}
```

**Password only:**

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/tlmanz/authkit"
)

func main() {
    userStore := NewYourUserStore() // your UserStore implementation

    auth, err := authkit.New(authkit.Config{
        Mode:          authkit.AuthModePassword,
        SessionSecret: os.Getenv("SESSION_SECRET"),
        SecureCookie:  os.Getenv("ENV") == "production",
        AfterLoginURL: "/dashboard",
        UserStore:     userStore,
        RBAC:          authkit.RBACConfig{FilePath: "policy.yaml"},
        PasswordPolicy: &authkit.PasswordPolicy{
            MinLength: 10,
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()
    go auth.WatchRBAC(ctx, 30*time.Second)

    mux := http.NewServeMux()

    // Password auth routes
    mux.HandleFunc("POST /auth/register", auth.Register)
    mux.HandleFunc("POST /auth/login",    auth.Login)
    mux.HandleFunc("POST /auth/logout",   auth.Logout)
    mux.HandleFunc("GET /auth/me",        auth.Me)

    // Protected routes
    mux.Handle("GET /api/data", auth.RequireAuth(http.HandlerFunc(dataHandler)))

    log.Println("listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
    u := authkit.UserFromCtx(r.Context())
    w.Write([]byte("Hello, " + u.Name))
}
```

**Both (OAuth + password):**

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/tlmanz/authkit"
)

func main() {
    userStore := NewYourUserStore()

    auth, err := authkit.New(authkit.Config{
        Mode: authkit.AuthModeBoth,
        Providers: []authkit.ProviderConfig{
            {
                Name:         "github",
                ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
                ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
            },
            {
                Name:         "google",
                ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
                ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
            },
        },
        CallbackBaseURL: os.Getenv("BASE_URL"),
        SessionSecret:   os.Getenv("SESSION_SECRET"),
        SecureCookie:    os.Getenv("ENV") == "production",
        AfterLoginURL:   "/dashboard",
        UserStore:       userStore,
        RBAC:            authkit.RBACConfig{FilePath: "policy.yaml"},
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()
    go auth.WatchRBAC(ctx, 30*time.Second)

    mux := http.NewServeMux()

    // OAuth routes
    mux.HandleFunc("GET /auth/{provider}",          auth.BeginAuth)
    mux.HandleFunc("GET /auth/{provider}/callback", auth.Callback)

    // Password routes
    mux.HandleFunc("POST /auth/register", auth.Register)
    mux.HandleFunc("POST /auth/login",    auth.Login)

    // Common routes
    mux.HandleFunc("POST /auth/logout", auth.Logout)
    mux.HandleFunc("GET /auth/me",      auth.Me)

    // Protected routes
    mux.Handle("GET /api/data",    auth.RequireAuth(http.HandlerFunc(dataHandler)))
    mux.Handle("POST /api/admin",  auth.Require(authkit.PermManage)(http.HandlerFunc(adminHandler)))

    log.Println("listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
    u := authkit.UserFromCtx(r.Context())
    w.Write([]byte("Hello, " + u.Name))
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("admin action completed"))
}
```

### Step 7: Configure a custom logger (optional)

By default, authkit logs to Go's standard `log` package. To route authkit's logs into your application's logging system, implement the `authkit.Logger` interface:

```go
type Logger interface {
    Info(msg string, args ...any)
    Error(msg string, args ...any)
}
```

- `Info` is called for informational messages (e.g. startup warnings about `SecureCookie`).
- `Error` is called for error conditions (e.g. failed OAuth callbacks, session errors, registration errors).
- The `msg` parameter uses `fmt.Sprintf`-style formatting with `args`.
- If `Logger` is nil in `Config`, a default implementation using the standard `log` package is used.

**Example: slog adapter**

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

**Example: zap adapter**

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

**Example: zerolog adapter**

```go
type zerologAdapter struct {
    l zerolog.Logger
}

func (z zerologAdapter) Info(msg string, args ...any)  { z.l.Info().Msgf(msg, args...) }
func (z zerologAdapter) Error(msg string, args ...any) { z.l.Error().Msgf(msg, args...) }
```

### Step 8: Set environment variables

```bash
# Required for all modes
export SESSION_SECRET="$(openssl rand -hex 32)"

# Required for OAuth mode
export BASE_URL="https://your-domain.com"
export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"

# Optional
export ENV="production"  # enables SecureCookie when using the pattern above
```

---

## API reference

### Types

```go
// AuthMode controls which auth methods are enabled.
type AuthMode string

const (
    AuthModeOAuth    AuthMode = "oauth"    // default
    AuthModePassword AuthMode = "password"
    AuthModeBoth     AuthMode = "both"
)

// User represents an authenticated user (available in handler context).
type User struct {
    Email     string `json:"email"`
    Name      string `json:"name"`
    AvatarURL string `json:"avatarUrl"`
    Provider  string `json:"provider"` // "github", "google", "gitlab", or "password"
    Role      string `json:"role"`
}

// PasswordUser is the record returned by UserStore.GetUserByEmail.
type PasswordUser struct {
    Email          string
    Name           string
    HashedPassword string
}

// PasswordPolicy configures password validation.
type PasswordPolicy struct {
    MinLength int // default: 8
}

// Logger is the interface for authkit diagnostic output.
// Implement this to route logs into your logging system.
// If nil in Config, defaults to the standard log package.
type Logger interface {
    Info(msg string, args ...any)
    Error(msg string, args ...any)
}
```

### Functions

```go
// Initialize authkit.
func New(cfg Config) (*Auth, error)

// Hash a password (exported for admin tooling / seed scripts).
func HashPassword(password string) (string, error)

// Verify a password against a bcrypt hash.
func CheckPassword(hashedPassword, password string) bool

// Get the current user from request context (set by RequireAuth middleware).
func UserFromCtx(ctx context.Context) *User
```

### Auth methods

```go
// OAuth handlers
func (a *Auth) BeginAuth(w http.ResponseWriter, r *http.Request)  // GET /auth/{provider}
func (a *Auth) Callback(w http.ResponseWriter, r *http.Request)   // GET /auth/{provider}/callback

// Password handlers
func (a *Auth) Register(w http.ResponseWriter, r *http.Request)   // POST /auth/register
func (a *Auth) Login(w http.ResponseWriter, r *http.Request)      // POST /auth/login

// Common handlers
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request)     // POST /auth/logout
func (a *Auth) Me(w http.ResponseWriter, r *http.Request)         // GET /auth/me

// Middleware
func (a *Auth) RequireAuth(next http.Handler) http.Handler
func (a *Auth) Require(permission string) func(http.Handler) http.Handler

// Background policy reload
func (a *Auth) WatchRBAC(ctx context.Context, interval time.Duration)
```

### User methods

```go
// Check if user has a specific permission.
func (u *User) Can(permission string) bool
```

### Sentinel errors

```go
var ErrUserExists   = errors.New("authkit: user already exists")
var ErrUserNotFound = errors.New("authkit: user not found")
```

### Permission constants

```go
const (
    PermAll = "*" // wildcard — passes every permission check
)
```

Permissions are fully user-defined strings. `PermAll` is the only constant authkit provides — all other permission names are defined by you in `policy.yaml` and matched exactly in code. See the [Permissions](#permissions) section for naming conventions.

### RBAC interfaces

```go
// PolicyProvider resolves a user's role and permissions at login time.
// Supply a custom implementation via RBACConfig.Provider to back RBAC with
// any storage system (database, remote config service, etc.).
type PolicyProvider interface {
    // RoleFor returns the role name and permissions for the given email.
    // Called on every login and API key auth.
    RoleFor(ctx context.Context, email string) (role string, permissions []string)

    // PermissionsForRole returns the permissions for a named role.
    // Used to resolve permissions for API key users.
    PermissionsForRole(role string) []string
}

// PolicyReloader is an optional interface for PolicyProvider implementations
// that support live reloading via WatchRBAC. If your provider does not
// implement this, WatchRBAC exits immediately and your provider controls
// its own refresh strategy.
type PolicyReloader interface {
    Reload() error
}

// UserRoleStore persists per-user role overrides for LayeredPolicyProvider.
// Implement against your preferred database and pass to NewLayeredProvider.
type UserRoleStore interface {
    GetOverride(ctx context.Context, email string) (role string, permissions []string, found bool, err error)
    SetOverride(ctx context.Context, email, role string, permissions []string) error
    DeleteOverride(ctx context.Context, email string) error
}
```

### RBAC constructors

```go
// NewLayeredProvider creates a YAML-baseline + database-override policy provider.
// Pass WithLogger(l) to log DB errors during role lookups.
func NewLayeredProvider(filePath string, store UserRoleStore, opts ...func(*LayeredPolicyProvider)) (*LayeredPolicyProvider, error)

// WithLogger sets a Logger on a LayeredPolicyProvider (functional option).
func WithLogger(l Logger) func(*LayeredPolicyProvider)

// LayeredPolicyProvider methods

// SetOverride validates and stores a per-user role override.
// Returns an error if the email/role/permissions are invalid or if the role
// is not defined in the current YAML policy.
// NOTE: changes take effect on the user's next login — existing sessions are not invalidated.
func (l *LayeredPolicyProvider) SetOverride(ctx context.Context, email, role string, permissions []string) error

// DeleteOverride reverts a user to the YAML baseline on their next login.
func (l *LayeredPolicyProvider) DeleteOverride(ctx context.Context, email string) error

// Store returns the raw UserRoleStore (e.g. for listing overrides in a management UI).
func (l *LayeredPolicyProvider) Store() UserRoleStore
```

### RBACConfig

```go
type RBACConfig struct {
    // FilePath is the path to the YAML policy file.
    // Used when Provider is nil (YAML-only mode).
    FilePath string

    // Provider is a custom PolicyProvider. When set, FilePath is ignored.
    // Use NewLayeredProvider or supply your own implementation.
    Provider PolicyProvider
}
```

---

## Handler request/response reference

### POST /auth/register

**Content-Type:** `application/x-www-form-urlencoded`

| Field | Required | Description |
|-------|----------|-------------|
| `email` | Yes | User's email address |
| `password` | Yes | Plaintext password (validated against PasswordPolicy) |
| `name` | No | Display name |

**Responses:**

| Status | Meaning |
|--------|---------|
| 303 | Success — redirects to `AfterLoginURL`, session cookie set |
| 400 | Invalid email or password too short |
| 404 | Password auth not enabled (OAuth-only mode) |
| 409 | Email already registered |
| 500 | Internal error |

### POST /auth/login

**Content-Type:** `application/x-www-form-urlencoded`

| Field | Required | Description |
|-------|----------|-------------|
| `email` | Yes | User's email address |
| `password` | Yes | Plaintext password |

**Responses:**

| Status | Meaning |
|--------|---------|
| 303 | Success — redirects to `AfterLoginURL`, session cookie set |
| 401 | Invalid email or password (deliberately vague to prevent enumeration) |
| 404 | Password auth not enabled (OAuth-only mode) |
| 500 | Internal error |

### POST /auth/logout

No body required.

**Responses:**

| Status | Meaning |
|--------|---------|
| 303 | Success — redirects to `AfterLogoutURL`, session cookie cleared |

### GET /auth/me

No body required. Requires a valid session cookie.

**Responses:**

| Status | Body | Meaning |
|--------|------|---------|
| 200 | `{"email":"...","name":"...","avatarUrl":"...","provider":"...","role":"..."}` | Authenticated |
| 401 | `{"error":"unauthenticated"}` | No valid session |

---

## Middleware behavior

### RequireAuth

- Reads the session cookie
- If no valid session: responds with `401` and body `"unauthenticated\n"`. Does NOT call next handler.
- If valid session: injects `*User` into request context and calls next handler
- Retrieve the user in your handler with: `u := authkit.UserFromCtx(r.Context())`

### Require(permission)

- First checks for a valid session (same as RequireAuth)
- Then checks if the user has the required permission via `user.Can(permission)`
- If the user lacks the permission: responds with `403` and body `"forbidden\n"`. Does NOT call next handler.
- `PermAll` (`"*"`) passes every permission check

---

## Common patterns

### Protecting an entire API group with a middleware chain

```go
apiMux := http.NewServeMux()
apiMux.HandleFunc("GET /reports", reportsHandler)
apiMux.HandleFunc("POST /projects", createProjectHandler)

// All /api/* routes require authentication
mux.Handle("/api/", http.StripPrefix("/api", auth.RequireAuth(apiMux)))
```

### Checking permissions inline

```go
func handler(w http.ResponseWriter, r *http.Request) {
    u := authkit.UserFromCtx(r.Context())
    if u.Can("deploy") {
        // show deploy button
    }
}
```

### Seeding an admin user (password mode)

```go
hashed, err := authkit.HashPassword("initial-admin-password")
if err != nil {
    log.Fatal(err)
}
err = userStore.CreateUser(context.Background(), "admin@company.com", "Admin", hashed)
if err != nil && !errors.Is(err, authkit.ErrUserExists) {
    log.Fatal(err)
}
```

### Frontend login form (HTML)

```html
<form method="POST" action="/auth/login">
    <input type="email" name="email" required>
    <input type="password" name="password" required>
    <button type="submit">Log In</button>
</form>
```

### Frontend registration form (HTML)

```html
<form method="POST" action="/auth/register">
    <input type="text" name="name">
    <input type="email" name="email" required>
    <input type="password" name="password" required minlength="8">
    <button type="submit">Sign Up</button>
</form>
```

### Frontend OAuth login links (HTML)

```html
<a href="/auth/github">Sign in with GitHub</a>
<a href="/auth/google">Sign in with Google</a>
```

### JSON API login (fetch)

```javascript
const res = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email: "user@example.com", password: "secret" }),
    redirect: "manual",  // handle redirect yourself
});

if (res.status === 303) {
    window.location.href = res.headers.get("Location");
} else {
    const text = await res.text();
    alert(text);  // "invalid email or password"
}
```

### Getting current user (fetch)

```javascript
const res = await fetch("/auth/me");
if (res.ok) {
    const user = await res.json();
    console.log(user.email, user.role, user.provider);
} else {
    // Not logged in
}
```

---

## Checklist for integration

Use this checklist to verify your integration is complete:

- [ ] Chose auth mode (`AuthModeOAuth`, `AuthModePassword`, or `AuthModeBoth`)
- [ ] Generated a session secret (`openssl rand -hex 32`) and stored in env var
- [ ] Chose an RBAC backend:
  - [ ] **YAML only** — created `policy.yaml` with roles, permissions, and members; set `RBACConfig{FilePath: "policy.yaml"}`
  - [ ] **Layered** — created `policy.yaml`, implemented `UserRoleStore`, called `NewLayeredProvider`; set `RBACConfig{Provider: provider}`
  - [ ] **Custom** — implemented `PolicyProvider`; set `RBACConfig{Provider: myProvider}`
- [ ] If using OAuth: registered OAuth apps and stored client credentials in env vars
- [ ] If using OAuth: set `CallbackBaseURL` to your public URL
- [ ] If using password: implemented `UserStore` interface with correct error returns
- [ ] If using password: created the users table in your database
- [ ] If using layered RBAC: created the `role_overrides` table in your database
- [ ] Called `authkit.New()` with your config
- [ ] Registered auth route handlers on your mux
- [ ] Protected API routes with `RequireAuth` or `Require(permission)` middleware
- [ ] Set `SecureCookie: true` for production
- [ ] Started `WatchRBAC` goroutine if you want live policy reload
- [ ] Applied rate limiting middleware to `/auth/login` and `/auth/register`
- [ ] (Optional) Configured custom `Logger` to route authkit logs to your logging system
- [ ] Tested login, logout, session persistence, and permission checks
