package authkit

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

var (
	validRoleName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	validPermName = regexp.MustCompile(`^(\*|[a-zA-Z0-9_.:-]+)$`)
	validEmail    = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

// ── RBAC types ────────────────────────────────────────────────────────────────

// PolicyProvider resolves a user's role and permissions at login time.
// Implement this interface to back RBAC with any storage system.
// The built-in implementations are the YAML file provider (default) and
// LayeredPolicyProvider (YAML baseline + database overrides).
type PolicyProvider interface {
	// RoleFor returns the role name and permission list for the given email.
	// Called on every login and API key auth. Return empty strings/nil when
	// the user has no assigned role.
	RoleFor(ctx context.Context, email string) (role string, permissions []string)

	// PermissionsForRole returns the permissions for a named role. The ctx
	// carries the tenant (via TenantIDFromCtx) so role definitions can be
	// per-tenant — a DB-backed provider scopes its lookup to that tenant.
	// Used to resolve permissions for API key users and for per-request live
	// resolution (LivePermissionResolution).
	PermissionsForRole(ctx context.Context, role string) []string
}

// PolicyReloader is an optional interface that PolicyProvider implementations
// can satisfy to support live policy reloading via WatchRBAC.
type PolicyReloader interface {
	Reload() error
}

// RBACConfig tells the Auth instance how to load the role policy.
type RBACConfig struct {
	// FilePath is the path to the rbac.yaml policy file.
	// Used when Provider is nil.
	FilePath string

	// Provider supplies a custom PolicyProvider implementation (e.g. a
	// database-backed or layered provider). When set, FilePath is ignored.
	Provider PolicyProvider
}

// Policy is the top-level structure of an rbac.yaml file.
type Policy struct {
	// Roles maps role names to their definition.
	Roles map[string]RolePolicy `yaml:"roles"`

	// DefaultRole is assigned to authenticated users whose email is not listed
	// under any role. Leave empty to deny access to unlisted users.
	DefaultRole string `yaml:"default_role"`
}

// RolePolicy defines the permissions and member emails for a single role.
type RolePolicy struct {
	// Permissions is the list of allowed permissions for this role.
	// Use "*" to grant all permissions (admin).
	Permissions []string `yaml:"permissions"`

	// Members is the list of email addresses assigned to this role.
	Members []string `yaml:"members"`
}

// ── Permission constants ───────────────────────────────────────────────────────

const (
	// PermAll grants every permission check. Use "*" in policy.yaml to assign
	// it to a role. All other permission strings are user-defined.
	PermAll = "*"
)

// ── RBAC engine ───────────────────────────────────────────────────────────────

// rbac is the internal concurrency-safe policy engine.
// It implements PolicyProvider and PolicyReloader.
type rbac struct {
	mu         sync.RWMutex
	policy     Policy
	emailIndex map[string]string // lower(email) → role name
	filePath   string            // path to reload from; empty means no file
}

func newRBAC(p Policy) *rbac {
	r := &rbac{}
	r.load(p)
	return r
}

// RoleFor implements PolicyProvider.
func (r *rbac) RoleFor(_ context.Context, email string) (string, []string) {
	return r.roleFor(email)
}

// PermissionsForRole implements PolicyProvider. The YAML provider is not
// tenant-aware (single-tenant fallback), so ctx is ignored.
func (r *rbac) PermissionsForRole(_ context.Context, role string) []string {
	return r.permissionsForRole(role)
}

// Reload implements PolicyReloader. Re-reads the YAML file and atomically
// replaces the running policy. Returns an error without changing state if
// the file cannot be read or parsed, so the old policy is preserved.
func (r *rbac) Reload() error {
	if r.filePath == "" {
		return nil
	}
	data, err := os.ReadFile(r.filePath)
	if err != nil {
		return fmt.Errorf("read rbac file %q: %w", r.filePath, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse rbac file %q: %w", r.filePath, err)
	}
	if p.Roles == nil {
		p.Roles = make(map[string]RolePolicy)
	}
	if err := validatePolicy(p); err != nil {
		return fmt.Errorf("validate rbac file %q: %w", r.filePath, err)
	}
	r.load(p)
	return nil
}

// load replaces the running policy atomically.
func (r *rbac) load(p Policy) {
	idx := make(map[string]string, 64)
	for role, def := range p.Roles {
		for _, email := range def.Members {
			idx[strings.ToLower(strings.TrimSpace(email))] = role
		}
	}
	r.mu.Lock()
	r.policy = p
	r.emailIndex = idx
	r.mu.Unlock()
}

// roleFor normalises email and delegates to roleForNormalized.
func (r *rbac) roleFor(email string) (role string, permissions []string) {
	return r.roleForNormalized(strings.ToLower(strings.TrimSpace(email)))
}

// roleForNormalized is the hot path — email must already be lower-cased and
// trimmed. Used internally and by LayeredPolicyProvider to avoid a second
// normalisation when the caller has already done it.
func (r *rbac) roleForNormalized(email string) (role string, permissions []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	role = r.emailIndex[email]
	if role == "" {
		role = r.policy.DefaultRole
	}
	if role == "" {
		return "", nil
	}
	def, ok := r.policy.Roles[role]
	if !ok {
		return role, nil
	}
	// Return a copy so callers cannot accidentally mutate the live policy.
	perms := make([]string, len(def.Permissions))
	copy(perms, def.Permissions)
	return role, perms
}

// hasRole reports whether a role name is defined in the current policy.
// Used by LayeredPolicyProvider to validate SetOverride inputs.
func (r *rbac) hasRole(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.policy.Roles[name]
	return ok
}

// permissionsForRole returns a copy of the permission slice for the named role.
// Returns nil if the role is not defined in the current policy.
func (r *rbac) permissionsForRole(role string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.policy.Roles[role]
	if !ok {
		return nil
	}
	perms := make([]string, len(def.Permissions))
	copy(perms, def.Permissions)
	return perms
}

// ── YAML loader ───────────────────────────────────────────────────────────────

// resolveProvider returns the PolicyProvider for New(). If cfg.Provider is
// set it is used directly; otherwise the YAML file at cfg.FilePath is loaded.
func resolveProvider(cfg RBACConfig) (PolicyProvider, error) {
	if cfg.Provider != nil {
		return cfg.Provider, nil
	}
	return loadRBAC(cfg)
}

// loadRBAC reads and parses the YAML policy file and returns the internal
// *rbac engine. If FilePath is empty the engine starts with an empty policy.
// Used internally and by tests that exercise the YAML implementation directly.
func loadRBAC(cfg RBACConfig) (*rbac, error) {
	if cfg.FilePath == "" {
		return newRBAC(Policy{}), nil
	}
	data, err := os.ReadFile(cfg.FilePath)
	if err != nil {
		return nil, fmt.Errorf("read rbac file %q: %w", cfg.FilePath, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse rbac file %q: %w", cfg.FilePath, err)
	}
	if p.Roles == nil {
		p.Roles = make(map[string]RolePolicy)
	}
	if err := validatePolicy(p); err != nil {
		return nil, fmt.Errorf("validate rbac file %q: %w", cfg.FilePath, err)
	}
	r := newRBAC(p)
	r.filePath = cfg.FilePath
	return r, nil
}

// validatePolicy checks that role names, permissions, and member emails
// conform to expected formats.
func validatePolicy(p Policy) error {
	if p.DefaultRole != "" {
		if _, ok := p.Roles[p.DefaultRole]; !ok {
			return fmt.Errorf("default_role %q does not match any defined role", p.DefaultRole)
		}
	}
	for name, role := range p.Roles {
		if !validRoleName.MatchString(name) {
			return fmt.Errorf("invalid role name %q: must be alphanumeric, hyphens, or underscores", name)
		}
		for _, perm := range role.Permissions {
			if !validPermName.MatchString(perm) {
				return fmt.Errorf("invalid permission %q in role %q: must be alphanumeric with dots, colons, hyphens, or underscores", perm, name)
			}
		}
		for _, email := range role.Members {
			if !validEmail.MatchString(email) {
				return fmt.Errorf("invalid email %q in role %q", email, name)
			}
		}
	}
	return nil
}
