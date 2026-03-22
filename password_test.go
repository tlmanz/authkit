package authkit

import (
	"testing"
)

func TestHashPassword_RoundTrip(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
	if hash == "correct-horse-battery-staple" {
		t.Fatal("hash should not equal plaintext")
	}
}

func TestCheckPassword_Correct(t *testing.T) {
	hash, err := HashPassword("my-secret-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !CheckPassword(hash, "my-secret-password") {
		t.Error("CheckPassword should return true for correct password")
	}
}

func TestCheckPassword_Wrong(t *testing.T) {
	hash, err := HashPassword("my-secret-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if CheckPassword(hash, "wrong-password") {
		t.Error("CheckPassword should return false for wrong password")
	}
}

func TestValidatePassword_TooShort(t *testing.T) {
	a := &Auth{cfg: Config{}}
	if err := a.validatePassword("short"); err == nil {
		t.Error("expected error for short password")
	}
}

func TestValidatePassword_Valid(t *testing.T) {
	a := &Auth{cfg: Config{}}
	if err := a.validatePassword("long-enough-password"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidatePassword_CustomPolicy(t *testing.T) {
	a := &Auth{cfg: Config{
		PasswordPolicy: &PasswordPolicy{MinLength: 12},
	}}

	if err := a.validatePassword("only-11chr"); err == nil {
		t.Error("expected error for password shorter than custom policy")
	}
	if err := a.validatePassword("twelve-chars!"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
