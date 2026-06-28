package authkit

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// ── UserStore interface ─────────────────────────────────────────────────────

// UserStore is the interface consumers implement to provide user persistence
// for password-based authentication. authkit is storage-agnostic — the
// consumer chooses the backing store (PostgreSQL, SQLite, in-memory, etc.).
type UserStore interface {
	// CreateUser persists a new user with the given email and bcrypt-hashed
	// password. Implementations MUST return ErrUserExists if the email is
	// already taken.
	CreateUser(ctx context.Context, email, name, hashedPassword string) error

	// GetUserByEmail retrieves a user by email. Returns ErrUserNotFound if
	// no user matches.
	GetUserByEmail(ctx context.Context, email string) (*PasswordUser, error)
}

// PasswordUser is the record returned by UserStore.GetUserByEmail.
type PasswordUser struct {
	Email          string
	Name           string
	HashedPassword string

	// TenantID binds this credential to one tenant; BranchID is an optional
	// in-tenant scope. The store populates them (email is global, so the lookup
	// determines the tenant). They are copied onto the authenticated User.
	TenantID string
	BranchID string
}

// Sentinel errors for UserStore implementations.
var (
	ErrUserExists   = errors.New("authkit: user already exists")
	ErrUserNotFound = errors.New("authkit: user not found")
)

// ── Password policy ─────────────────────────────────────────────────────────

// PasswordPolicy configures password validation constraints.
type PasswordPolicy struct {
	// MinLength is the minimum password length. Defaults to 8.
	MinLength int
}

const defaultMinPasswordLength = 8

func (a *Auth) validatePassword(password string) error {
	minLen := defaultMinPasswordLength
	if a.cfg.PasswordPolicy != nil && a.cfg.PasswordPolicy.MinLength > 0 {
		minLen = a.cfg.PasswordPolicy.MinLength
	}
	if len(password) < minLen {
		return fmt.Errorf("password must be at least %d characters", minLen)
	}
	return nil
}

// ── Bcrypt helpers ──────────────────────────────────────────────────────────

const defaultBcryptCost = 12

// HashPassword hashes a plaintext password using bcrypt.
// Exported so consumers can use it in admin/seed tooling.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), defaultBcryptCost)
	if err != nil {
		return "", fmt.Errorf("authkit: hash password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword compares a plaintext password against a bcrypt hash.
func CheckPassword(hashedPassword, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}

// dummyHash is a pre-computed bcrypt hash used for constant-time comparison
// when the user is not found, preventing timing-based user enumeration.
var dummyHash = []byte("$2a$12$000000000000000000000uGbBMsHCkFEU0VLmTJGGOF/bfYVxEau")
