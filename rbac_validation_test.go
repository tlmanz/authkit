package authkit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePolicy_InvalidRoleName(t *testing.T) {
	p := Policy{
		Roles: map[string]RolePolicy{
			"invalid role!": {Permissions: []string{"view"}},
		},
	}
	err := validatePolicy(p)
	if err == nil {
		t.Fatal("expected error for invalid role name")
	}
	if !strings.Contains(err.Error(), "invalid role name") {
		t.Errorf("error should mention role name: %v", err)
	}
}

func TestValidatePolicy_InvalidPermission(t *testing.T) {
	p := Policy{
		Roles: map[string]RolePolicy{
			"admin": {Permissions: []string{"valid", "bad perm!"}},
		},
	}
	err := validatePolicy(p)
	if err == nil {
		t.Fatal("expected error for invalid permission")
	}
	if !strings.Contains(err.Error(), "invalid permission") {
		t.Errorf("error should mention permission: %v", err)
	}
}

func TestValidatePolicy_InvalidEmail(t *testing.T) {
	p := Policy{
		Roles: map[string]RolePolicy{
			"admin": {
				Permissions: []string{"view"},
				Members:     []string{"not-an-email"},
			},
		},
	}
	err := validatePolicy(p)
	if err == nil {
		t.Fatal("expected error for invalid email")
	}
	if !strings.Contains(err.Error(), "invalid email") {
		t.Errorf("error should mention email: %v", err)
	}
}

func TestValidatePolicy_InvalidDefaultRole(t *testing.T) {
	p := Policy{
		Roles:       map[string]RolePolicy{"viewer": {Permissions: []string{"view"}}},
		DefaultRole: "nonexistent",
	}
	err := validatePolicy(p)
	if err == nil {
		t.Fatal("expected error for invalid default_role")
	}
	if !strings.Contains(err.Error(), "default_role") {
		t.Errorf("error should mention default_role: %v", err)
	}
}

func TestValidatePolicy_ValidPolicy(t *testing.T) {
	p := Policy{
		Roles: map[string]RolePolicy{
			"admin": {
				Permissions: []string{"*"},
				Members:     []string{"admin@example.com"},
			},
			"dev-team": {
				Permissions: []string{"view", "upload", "deploy.prod", "reports:export"},
				Members:     []string{"dev@example.com"},
			},
		},
		DefaultRole: "admin",
	}
	if err := validatePolicy(p); err != nil {
		t.Errorf("expected no error for valid policy: %v", err)
	}
}

func TestValidatePolicy_EmptyPolicy(t *testing.T) {
	if err := validatePolicy(Policy{Roles: map[string]RolePolicy{}}); err != nil {
		t.Errorf("expected no error for empty policy: %v", err)
	}
}

func TestRoleFor_DefaultRoleReturnsPermissions(t *testing.T) {
	p := Policy{
		Roles: map[string]RolePolicy{
			"viewer": {Permissions: []string{"view"}},
		},
		DefaultRole: "viewer",
	}
	r := newRBAC(p)
	role, perms := r.roleFor("unknown@example.com")
	if role != "viewer" {
		t.Errorf("role: got %q, want viewer", role)
	}
	if len(perms) != 1 || perms[0] != "view" {
		t.Errorf("perms: got %v, want [view]", perms)
	}
}

func TestLoadRBAC_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	data := `
roles:
  admin:
    permissions: ["*"]
    members:
      - admin@example.com
default_role: admin
`
	os.WriteFile(path, []byte(data), 0644)

	r, err := loadRBAC(RBACConfig{FilePath: path})
	if err != nil {
		t.Fatalf("loadRBAC: %v", err)
	}
	role, _ := r.roleFor("admin@example.com")
	if role != "admin" {
		t.Errorf("role: got %q, want admin", role)
	}
}

func TestLoadRBAC_ValidationError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	data := `
roles:
  "bad role!":
    permissions: ["view"]
`
	os.WriteFile(path, []byte(data), 0644)

	_, err := loadRBAC(RBACConfig{FilePath: path})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "validate") {
		t.Errorf("error should mention validate: %v", err)
	}
}

func TestLoadRBAC_MissingFile(t *testing.T) {
	_, err := loadRBAC(RBACConfig{FilePath: "/nonexistent/path.yaml"})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadRBAC_EmptyRolesInitialized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte("{}"), 0644)

	r, err := loadRBAC(RBACConfig{FilePath: path})
	if err != nil {
		t.Fatalf("loadRBAC: %v", err)
	}
	role, perms := r.roleFor("anyone@example.com")
	if role != "" {
		t.Errorf("role: got %q, want empty", role)
	}
	if perms != nil {
		t.Errorf("perms: got %v, want nil", perms)
	}
}
