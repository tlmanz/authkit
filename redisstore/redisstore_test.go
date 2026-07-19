package redisstore

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	authkit "github.com/tlmanz/authkit/v2"
)

func testClient(t *testing.T) (redis.UniversalClient, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()}), mr
}

func TestSessions_CreateGetTouchRevoke(t *testing.T) {
	rc, mr := testClient(t)
	s := NewSessions(rc, 30*time.Minute, 2*time.Hour, WithKeyPrefix("app:"))
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	sess := &authkit.Session{
		ID: "sid-1", TenantID: "t1", Email: "a@example.com", Role: "owner",
		Permissions: []string{"invoice:issue"},
		Attrs:       map[string]string{"branch_id": "b1"},
		CreatedAt:   now, LastSeenAt: now,
	}
	if err := s.Create(ctx, sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := s.Get(ctx, "sid-1")
	if err != nil || got == nil {
		t.Fatalf("get = (%v, %v)", got, err)
	}
	if got.Email != "a@example.com" || got.Attrs["branch_id"] != "b1" || len(got.Permissions) != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Touch slides LastSeenAt.
	later := now.Add(5 * time.Minute)
	if err := s.Touch(ctx, "sid-1", later); err != nil {
		t.Fatalf("touch: %v", err)
	}
	got, _ = s.Get(ctx, "sid-1")
	if !got.LastSeenAt.Equal(later) {
		t.Fatalf("LastSeenAt = %v, want %v", got.LastSeenAt, later)
	}

	// Idle TTL expiry: fast-forward past idle.
	mr.FastForward(31 * time.Minute)
	if got, _ := s.Get(ctx, "sid-1"); got != nil {
		t.Fatal("session should have expired with the idle TTL")
	}
}

func TestSessions_RevokeAllForUser(t *testing.T) {
	rc, _ := testClient(t)
	s := NewSessions(rc, time.Hour, 2*time.Hour)
	ctx := context.Background()

	for _, id := range []string{"s1", "s2"} {
		if err := s.Create(ctx, &authkit.Session{ID: id, TenantID: "t1", Email: "a@example.com"}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	if err := s.Create(ctx, &authkit.Session{ID: "other", TenantID: "t1", Email: "b@example.com"}); err != nil {
		t.Fatalf("create other: %v", err)
	}

	if err := s.RevokeAllForUser(ctx, "t1", "a@example.com"); err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	if got, _ := s.Get(ctx, "s1"); got != nil {
		t.Fatal("s1 should be revoked")
	}
	if got, _ := s.Get(ctx, "s2"); got != nil {
		t.Fatal("s2 should be revoked")
	}
	if got, _ := s.Get(ctx, "other"); got == nil {
		t.Fatal("other user's session must survive")
	}
}

func TestThrottler_LockoutAndReset(t *testing.T) {
	rc, mr := testClient(t)
	th := NewThrottler(rc, 3, time.Minute, 10*time.Minute, time.Hour)
	ctx := context.Background()

	if _, ok := th.Allow(ctx, "a@example.com|1.2.3.4"); !ok {
		t.Fatal("fresh key must be allowed")
	}
	for range 3 {
		if err := th.RecordFailure(ctx, "a@example.com|1.2.3.4"); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	retry, ok := th.Allow(ctx, "a@example.com|1.2.3.4")
	if ok || retry <= 0 {
		t.Fatalf("expected lockout, got ok=%v retry=%v", ok, retry)
	}

	// Lockout self-expires.
	mr.FastForward(2 * time.Minute)
	if _, ok := th.Allow(ctx, "a@example.com|1.2.3.4"); !ok {
		t.Fatal("lockout should have expired")
	}

	// Reset clears everything immediately.
	for range 3 {
		_ = th.RecordFailure(ctx, "a@example.com|1.2.3.4")
	}
	if err := th.Reset(ctx, "a@example.com|1.2.3.4"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, ok := th.Allow(ctx, "a@example.com|1.2.3.4"); !ok {
		t.Fatal("reset must clear the lockout")
	}
}

func TestTrustedDevices_TrustCheckRevoke(t *testing.T) {
	rc, mr := testClient(t)
	s := NewTrustedDevices(rc)
	ctx := context.Background()

	tok, err := s.Trust(ctx, "t1", "a@example.com", time.Hour)
	if err != nil || tok == "" {
		t.Fatalf("trust = (%q, %v)", tok, err)
	}
	if ok, _ := s.IsTrusted(ctx, "t1", "a@example.com", tok); !ok {
		t.Fatal("token should be trusted")
	}
	// The token binds to (tenant, email): another identity must not pass.
	if ok, _ := s.IsTrusted(ctx, "t2", "a@example.com", tok); ok {
		t.Fatal("token must not be trusted for another tenant")
	}
	if ok, _ := s.IsTrusted(ctx, "t1", "b@example.com", tok); ok {
		t.Fatal("token must not be trusted for another user")
	}

	if err := s.RevokeAllForUser(ctx, "t1", "a@example.com"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ok, _ := s.IsTrusted(ctx, "t1", "a@example.com", tok); ok {
		t.Fatal("revoked token must not be trusted")
	}

	// TTL expiry.
	tok2, _ := s.Trust(ctx, "t1", "a@example.com", time.Minute)
	mr.FastForward(2 * time.Minute)
	if ok, _ := s.IsTrusted(ctx, "t1", "a@example.com", tok2); ok {
		t.Fatal("expired token must not be trusted")
	}
}

func TestAuthCodes_SingleUse(t *testing.T) {
	rc, _ := testClient(t)
	s := NewAuthCodes(rc, WithKeyPrefix("app:"))
	ctx := context.Background()

	exp := time.Now().Add(time.Minute)
	ok, err := s.ClaimAuthCode(ctx, "jti-1", exp)
	if err != nil || !ok {
		t.Fatalf("first claim = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = s.ClaimAuthCode(ctx, "jti-1", exp)
	if err != nil || ok {
		t.Fatalf("second claim = (%v, %v), want (false, nil)", ok, err)
	}
	// A different jti is unaffected.
	if ok, _ := s.ClaimAuthCode(ctx, "jti-2", exp); !ok {
		t.Fatal("different jti must claim fresh")
	}
}
