package redisstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	authkit "github.com/tlmanz/authkit/v2"
)

// Sessions implements authkit.SessionStore on Redis. The session key's TTL
// models the idle timeout (slid forward on Touch); the absolute timeout is
// enforced by authkit from the stored CreatedAt. A per-user set indexes a
// user's session IDs so "log out everywhere" is one fan-out delete.
//
// Redis has no tenant isolation: the opaque 256-bit session ID is the security
// boundary here. Tenant scoping for business data remains a database concern.
type Sessions struct {
	rc       redis.UniversalClient
	idle     time.Duration
	absolute time.Duration
	prefix   string
}

// NewSessions constructs a Redis-backed session store. idle and absolute must
// match the IdleTimeout/AbsoluteTimeout configured on authkit, so the Redis
// TTLs and authkit's own checks agree.
func NewSessions(rc redis.UniversalClient, idle, absolute time.Duration, opts ...Option) *Sessions {
	o := applyOptions(opts)
	return &Sessions{rc: rc, idle: idle, absolute: absolute, prefix: o.prefix}
}

var _ authkit.SessionStore = (*Sessions)(nil)

func (s *Sessions) sessionKey(id string) string { return s.prefix + "sess:" + id }
func (s *Sessions) userKey(tenantID, email string) string {
	return s.prefix + "usess:" + tenantID + "|" + email
}

// Create stores the session (TTL = idle) and indexes it under the user.
func (s *Sessions) Create(ctx context.Context, sess *authkit.Session) error {
	blob, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("redisstore: marshal session: %w", err)
	}
	uk := s.userKey(sess.TenantID, sess.Email)
	pipe := s.rc.TxPipeline()
	pipe.Set(ctx, s.sessionKey(sess.ID), blob, s.idle)
	pipe.SAdd(ctx, uk, sess.ID)
	pipe.Expire(ctx, uk, s.absolute)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redisstore: create session: %w", err)
	}
	return nil
}

// Get returns the session, or nil when absent/expired.
func (s *Sessions) Get(ctx context.Context, id string) (*authkit.Session, error) {
	blob, err := s.rc.Get(ctx, s.sessionKey(id)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redisstore: get session: %w", err)
	}
	var sess authkit.Session
	if err := json.Unmarshal(blob, &sess); err != nil {
		return nil, fmt.Errorf("redisstore: unmarshal session: %w", err)
	}
	return &sess, nil
}

// Touch advances LastSeenAt and slides the idle TTL forward.
func (s *Sessions) Touch(ctx context.Context, id string, lastSeen time.Time) error {
	sess, err := s.Get(ctx, id)
	if err != nil || sess == nil {
		return err
	}
	sess.LastSeenAt = lastSeen
	blob, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("redisstore: marshal session: %w", err)
	}
	if err := s.rc.Set(ctx, s.sessionKey(id), blob, s.idle).Err(); err != nil {
		return fmt.Errorf("redisstore: touch session: %w", err)
	}
	return nil
}

// Revoke deletes a single session. A stale ID may linger in the user index; it
// is harmless (deletes of missing keys are no-ops) and cleared on RevokeAllForUser.
func (s *Sessions) Revoke(ctx context.Context, id string) error {
	if err := s.rc.Del(ctx, s.sessionKey(id)).Err(); err != nil {
		return fmt.Errorf("redisstore: revoke session: %w", err)
	}
	return nil
}

// RevokeAllForUser deletes every session indexed for the user.
func (s *Sessions) RevokeAllForUser(ctx context.Context, tenantID, email string) error {
	uk := s.userKey(tenantID, email)
	ids, err := s.rc.SMembers(ctx, uk).Result()
	if err != nil {
		return fmt.Errorf("redisstore: list user sessions: %w", err)
	}
	pipe := s.rc.TxPipeline()
	for _, id := range ids {
		pipe.Del(ctx, s.sessionKey(id))
	}
	pipe.Del(ctx, uk)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redisstore: revoke all sessions: %w", err)
	}
	return nil
}
