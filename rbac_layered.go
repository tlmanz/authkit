package authkit

import (
	"context"
	"fmt"
	"strings"
)

// UserRoleStore persists per-user role overrides to a database.
// Implement this interface against your preferred database (Postgres, SQLite,
// etc.) and pass it to NewLayeredProvider.
//
// Only users whose roles have been changed via your UI need a row in the store.
// Everyone else falls through to the YAML baseline automatically.
type UserRoleStore interface {
	// GetOverride returns the role and permissions for email if a UI-managed
	// override exists. Return found=false when no override has been set for
	// this user — authkit will fall back to the YAML baseline.
	// The email argument is always lower-cased and trimmed before being passed.
	GetOverride(ctx context.Context, email string) (role string, permissions []string, found bool, err error)

	// SetOverride creates or replaces the role override for a user.
	// Prefer calling LayeredPolicyProvider.SetOverride instead — it validates
	// the role name and permission strings before writing to the store.
	SetOverride(ctx context.Context, email, role string, permissions []string) error

	// DeleteOverride removes the override for email, reverting that user to
	// whatever the YAML baseline assigns them.
	DeleteOverride(ctx context.Context, email string) error
}

// LayeredPolicyProvider combines a YAML baseline with per-user database
// overrides. The YAML file defines roles and their initial members. A
// management UI can call SetOverride to change individual users without
// editing the file.
//
// Lookup order per request:
//  1. Database override for this email  (UI-managed, takes precedence)
//  2. YAML baseline                     (file-managed, fallback)
//
// Implements PolicyProvider and PolicyReloader.
type LayeredPolicyProvider struct {
	yaml  *rbac
	store UserRoleStore
	log   Logger // nil → silent
}

// WithLogger configures a Logger for LayeredPolicyProvider. When set, DB
// errors during role lookups are logged so operators can detect store outages.
//
// Example:
//
//	provider, err := authkit.NewLayeredProvider("policy.yaml", store,
//	    authkit.WithLogger(myLogger),
//	)
func WithLogger(l Logger) func(*LayeredPolicyProvider) {
	return func(p *LayeredPolicyProvider) { p.log = l }
}

// NewLayeredProvider creates a LayeredPolicyProvider that reads the initial
// policy from filePath and looks up per-user overrides from store.
//
// Example:
//
//	provider, err := authkit.NewLayeredProvider("policy.yaml", myDBStore,
//	    authkit.WithLogger(myLogger),
//	)
//	auth, err := authkit.New(authkit.Config{
//	    RBAC: authkit.RBACConfig{Provider: provider},
//	    ...
//	})
//	go auth.WatchRBAC(ctx, 30*time.Second) // reloads YAML baseline
func NewLayeredProvider(filePath string, store UserRoleStore, opts ...func(*LayeredPolicyProvider)) (*LayeredPolicyProvider, error) {
	r, err := loadRBAC(RBACConfig{FilePath: filePath})
	if err != nil {
		return nil, err
	}
	p := &LayeredPolicyProvider{yaml: r, store: store}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// RoleFor implements PolicyProvider. Checks the DB override first, then falls
// back to the YAML baseline. If the DB returns an error the fallback is used
// and the error is logged (if a Logger was configured). This prevents a store
// outage from locking users out, but means a user whose DB override was a
// demotion will temporarily regain their YAML role. Monitor store errors.
func (l *LayeredPolicyProvider) RoleFor(ctx context.Context, email string) (string, []string) {
	email = strings.ToLower(strings.TrimSpace(email))
	role, perms, found, err := l.store.GetOverride(ctx, email)
	if err != nil {
		if l.log != nil {
			l.log.Error("authkit: role override lookup failed for %q: %v — falling back to YAML baseline", email, err)
		}
		// fall through to YAML
	} else if found {
		return role, perms
	}
	// Pass already-normalised email to avoid a second ToLower/TrimSpace.
	return l.yaml.roleForNormalized(email)
}

// PermissionsForRole implements PolicyProvider. Resolves permissions for a
// named role from the YAML baseline — role definitions are always file-managed.
// ctx is unused: the layered provider's role definitions are not per-tenant.
func (l *LayeredPolicyProvider) PermissionsForRole(_ context.Context, role string) []string {
	return l.yaml.permissionsForRole(role)
}

// Reload implements PolicyReloader. Re-reads the YAML baseline without
// affecting any database overrides. Called automatically by WatchRBAC.
func (l *LayeredPolicyProvider) Reload() error {
	return l.yaml.Reload()
}

// SetOverride validates and stores a per-user role override.
// Returns an error if the email format is invalid, the role name is not
// defined in the current YAML policy, or any permission string is invalid.
//
// NOTE: role changes take effect on the user's next login — existing sessions
// retain their current permissions until they expire or the user logs out and
// back in. There is no built-in session invalidation.
func (l *LayeredPolicyProvider) SetOverride(ctx context.Context, email, role string, permissions []string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if !validEmail.MatchString(email) {
		return fmt.Errorf("authkit: invalid email %q", email)
	}
	if !validRoleName.MatchString(role) {
		return fmt.Errorf("authkit: invalid role name %q", role)
	}
	if !l.yaml.hasRole(role) {
		return fmt.Errorf("authkit: role %q is not defined in the policy", role)
	}
	for _, perm := range permissions {
		if !validPermName.MatchString(perm) {
			return fmt.Errorf("authkit: invalid permission %q", perm)
		}
	}
	return l.store.SetOverride(ctx, email, role, permissions)
}

// DeleteOverride removes the role override for email, reverting that user to
// the YAML baseline on their next login.
func (l *LayeredPolicyProvider) DeleteOverride(ctx context.Context, email string) error {
	return l.store.DeleteOverride(ctx, strings.ToLower(strings.TrimSpace(email)))
}

// Store returns the raw UserRoleStore for operations not covered by
// SetOverride/DeleteOverride (e.g. listing all overrides in a management UI).
func (l *LayeredPolicyProvider) Store() UserRoleStore {
	return l.store
}
