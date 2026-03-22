package authkit

import (
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

// RBACConfig tells the Auth instance where to load the policy file from.
type RBACConfig struct {
	// FilePath is the path to the rbac.yaml policy file.
	FilePath string
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
type rbac struct {
	mu         sync.RWMutex
	policy     Policy
	emailIndex map[string]string // lower(email) → role name
}

func newRBAC(p Policy) *rbac {
	r := &rbac{}
	r.load(p)
	return r
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

// roleFor returns the role name and resolved permissions for the given email.
// Falls back to DefaultRole if the email is not explicitly listed.
func (r *rbac) roleFor(email string) (role string, permissions []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	role = r.emailIndex[strings.ToLower(strings.TrimSpace(email))]
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
	return role, def.Permissions
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

// loadRBAC reads and parses the YAML policy file. If FilePath is empty the
// engine starts with an empty policy (all authenticated users have no role).
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
	return newRBAC(p), nil
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
