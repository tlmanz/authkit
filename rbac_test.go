package authkit

import (
	"os"
	"path/filepath"
	"testing"
)

const testPolicy = `
roles:
  admin:
    permissions: ["*"]
    members:
      - admin@example.com
  developer:
    permissions: ["view", "upload"]
    members:
      - dev@example.com
  viewer:
    permissions: ["view"]
    members:
      - guest@example.com
default_role: viewer
`

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

func TestRoleFor_KnownUser(t *testing.T) {
	path := writePolicyFile(t, testPolicy)
	r, err := loadRBAC(RBACConfig{FilePath: path})
	if err != nil {
		t.Fatalf("loadRBAC: %v", err)
	}

	tests := []struct {
		email       string
		wantRole    string
		wantPermLen int
	}{
		{"admin@example.com", "admin", 1},   // ["*"]
		{"dev@example.com", "developer", 2}, // ["view","upload"]
		{"guest@example.com", "viewer", 1},  // ["view"]
	}

	for _, tt := range tests {
		role, perms := r.roleFor(tt.email)
		if role != tt.wantRole {
			t.Errorf("roleFor(%q): role = %q, want %q", tt.email, role, tt.wantRole)
		}
		if len(perms) != tt.wantPermLen {
			t.Errorf("roleFor(%q): len(perms) = %d, want %d (perms: %v)", tt.email, len(perms), tt.wantPermLen, perms)
		}
	}
}

func TestRoleFor_UnknownUserFallsBackToDefaultRole(t *testing.T) {
	path := writePolicyFile(t, testPolicy)
	r, err := loadRBAC(RBACConfig{FilePath: path})
	if err != nil {
		t.Fatalf("loadRBAC: %v", err)
	}

	role, perms := r.roleFor("unknown@example.com")
	if role != "viewer" {
		t.Errorf("unknown user: role = %q, want viewer", role)
	}
	if len(perms) != 1 || perms[0] != "view" {
		t.Errorf("unknown user: perms = %v, want [%q]", perms, "view")
	}
}

func TestRoleFor_UnknownUserNoDefaultRole(t *testing.T) {
	path := writePolicyFile(t, `
roles:
  admin:
    permissions: ["*"]
    members:
      - admin@example.com
`)
	r, err := loadRBAC(RBACConfig{FilePath: path})
	if err != nil {
		t.Fatalf("loadRBAC: %v", err)
	}

	role, perms := r.roleFor("unknown@example.com")
	if role != "" {
		t.Errorf("no default_role: role = %q, want empty", role)
	}
	if len(perms) != 0 {
		t.Errorf("no default_role: perms = %v, want empty", perms)
	}
}

func TestUserCan(t *testing.T) {
	adminUser := &User{permissions: []string{PermAll}}
	devUser := &User{permissions: []string{"view", "upload"}}
	viewerUser := &User{permissions: []string{"view"}}
	var nilUser *User

	tests := []struct {
		name       string
		user       *User
		permission string
		want       bool
	}{
		{"admin can view", adminUser, "view", true},
		{"admin can upload", adminUser, "upload", true},
		{"admin can manage", adminUser, "manage", true},
		{"dev can view", devUser, "view", true},
		{"dev can upload", devUser, "upload", true},
		{"dev cannot manage", devUser, "manage", false},
		{"viewer can view", viewerUser, "view", true},
		{"viewer cannot upload", viewerUser, "upload", false},
		{"nil user returns false", nilUser, "view", false},
	}

	for _, tt := range tests {
		got := tt.user.Can(tt.permission)
		if got != tt.want {
			t.Errorf("%s: Can(%q) = %v, want %v", tt.name, tt.permission, got, tt.want)
		}
	}
}

func TestLoadRBAC_EmptyFilePath(t *testing.T) {
	// No policy file — should succeed and return empty role for all users.
	r, err := loadRBAC(RBACConfig{})
	if err != nil {
		t.Fatalf("loadRBAC with empty config: %v", err)
	}
	role, perms := r.roleFor("anyone@example.com")
	if role != "" {
		t.Errorf("empty policy: role = %q, want empty", role)
	}
	if len(perms) != 0 {
		t.Errorf("empty policy: perms = %v, want empty", perms)
	}
}

func TestLoadRBAC_InvalidFile(t *testing.T) {
	_, err := loadRBAC(RBACConfig{FilePath: "/nonexistent/policy.yaml"})
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestRBACEmailCaseInsensitive(t *testing.T) {
	path := writePolicyFile(t, testPolicy)
	r, err := loadRBAC(RBACConfig{FilePath: path})
	if err != nil {
		t.Fatalf("loadRBAC: %v", err)
	}

	role, _ := r.roleFor("Admin@Example.COM")
	if role != "admin" {
		t.Errorf("case-insensitive lookup: role = %q, want admin", role)
	}
}

func TestRBACReload(t *testing.T) {
	// Verify that a new loadRBAC call gets the new policy (old instance unchanged).
	path := writePolicyFile(t, testPolicy)
	oldR, err := loadRBAC(RBACConfig{FilePath: path})
	if err != nil {
		t.Fatalf("loadRBAC: %v", err)
	}

	updatedPolicy := `
roles:
  admin:
    permissions: ["*"]
    members:
      - dev@example.com
`
	if err := os.WriteFile(path, []byte(updatedPolicy), 0600); err != nil {
		t.Fatalf("rewrite policy: %v", err)
	}

	newR, err := loadRBAC(RBACConfig{FilePath: path})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	role, _ := newR.roleFor("dev@example.com")
	if role != "admin" {
		t.Errorf("after reload: dev@example.com role = %q, want admin", role)
	}

	// Old instance should still see developer role for dev@example.com.
	oldRole, _ := oldR.roleFor("dev@example.com")
	if oldRole != "developer" {
		t.Errorf("old instance: dev@example.com role = %q, want developer", oldRole)
	}
}
