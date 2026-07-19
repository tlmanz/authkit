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
	// CreateUser persists a new user with the given email and pre-hashed
	// password. Implementations MUST return ErrUserExists if the email is
	// already taken.
	CreateUser(ctx context.Context, email, name, hashedPassword string) error

	// GetUserByEmail retrieves a user by email. Returns ErrUserNotFound if
	// no user matches.
	GetUserByEmail(ctx context.Context, email string) (*PasswordUser, error)

	// UpdatePassword sets the hashed password for the user with this (global)
	// email. Called by the password-reset and password-change flows. ctx
	// carries the user's tenant, so a tenant-scoped store can apply its own
	// row-level scoping.
	UpdatePassword(ctx context.Context, email, hashedPassword string) error
}

// PasswordUser is the record returned by UserStore.GetUserByEmail.
type PasswordUser struct {
	Email          string
	Name           string
	HashedPassword string

	// TenantID binds this credential to one tenant (email is global, so the
	// lookup determines the tenant). Attrs carries host-defined principal
	// attributes. Both are copied onto the authenticated User.
	TenantID string
	Attrs    map[string]string

	// MustChangePassword is set when the credential is a temporary/onboarding
	// one the user must replace before doing anything else. When true, Login
	// stops before 2FA and asks the client to collect a new password (see
	// ChangeFirstPassword); the store clears it on the next UpdatePassword.
	MustChangePassword bool
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

	// MaxLength caps the password length in bytes. Defaults to 72, the hard
	// limit of the default bcrypt hasher (longer inputs would otherwise be
	// rejected by the KDF with an opaque error). Raise it when using a hasher
	// without that limit (e.g. Argon2).
	MaxLength int
}

const (
	defaultMinPasswordLength = 8
	defaultMaxPasswordLength = 72 // bcrypt's input limit
)

func (a *Auth) validatePassword(password string) error {
	minLen, maxLen := defaultMinPasswordLength, defaultMaxPasswordLength
	if p := a.cfg.PasswordPolicy; p != nil {
		if p.MinLength > 0 {
			minLen = p.MinLength
		}
		if p.MaxLength > 0 {
			maxLen = p.MaxLength
		}
	}
	if len(password) < minLen {
		return fmt.Errorf("password must be at least %d characters", minLen)
	}
	if len(password) > maxLen {
		return fmt.Errorf("password must be at most %d bytes", maxLen)
	}
	return nil
}

// ── Password hashing ────────────────────────────────────────────────────────

// PasswordHasher hashes and verifies passwords. The default is bcrypt with
// cost 12; supply an implementation backed by Argon2id (or any KDF) to change
// the algorithm. Verify must return false — never panic or error — for a hash
// produced by a different algorithm, so deployments can migrate hashers
// gradually.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hashedPassword, password string) bool
}

// BcryptHasher is the default PasswordHasher (bcrypt, cost 12 — roughly 250ms
// per hash on modern hardware).
type BcryptHasher struct {
	// Cost overrides the bcrypt cost. Zero means the default (12).
	Cost int
}

const defaultBcryptCost = 12

// Hash implements PasswordHasher.
func (h BcryptHasher) Hash(password string) (string, error) {
	cost := h.Cost
	if cost == 0 {
		cost = defaultBcryptCost
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("authkit: hash password: %w", err)
	}
	return string(hash), nil
}

// Verify implements PasswordHasher.
func (h BcryptHasher) Verify(hashedPassword, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}

// passwordHasher returns the configured hasher, defaulting to bcrypt. Nil-safe
// so an Auth value constructed without New (tests) still hashes correctly.
func (a *Auth) passwordHasher() PasswordHasher {
	if a.hasher != nil {
		return a.hasher
	}
	return BcryptHasher{}
}

// hashPassword hashes through the configured hasher.
func (a *Auth) hashPassword(password string) (string, error) {
	return a.passwordHasher().Hash(password)
}

// checkPassword verifies through the configured hasher.
func (a *Auth) checkPassword(hashed, password string) bool {
	return a.passwordHasher().Verify(hashed, password)
}

// HashPassword hashes a plaintext password with the default bcrypt hasher.
// Exported so consumers can use it in admin/seed tooling. Applications that
// configured a custom PasswordHasher should hash through that instead.
func HashPassword(password string) (string, error) {
	return BcryptHasher{}.Hash(password)
}

// CheckPassword compares a plaintext password against a bcrypt hash.
func CheckPassword(hashedPassword, password string) bool {
	return BcryptHasher{}.Verify(hashedPassword, password)
}

// dummyVerify burns the same time as a real verification when the user is not
// found, preventing timing-based user enumeration.
func (a *Auth) dummyVerify(password string) {
	a.passwordHasher().Verify(string(dummyHash), password)
}

// dummyHash is a pre-computed bcrypt hash used for constant-time comparison
// when the user is not found.
var dummyHash = []byte("$2a$12$000000000000000000000uGbBMsHCkFEU0VLmTJGGOF/bfYVxEau")
