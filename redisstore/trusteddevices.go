package redisstore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	authkit "github.com/tlmanz/authkit/v2"
)

// TrustedDevices implements authkit.TrustedDeviceStore on Redis. Each trusted
// device is an opaque 256-bit token mapping to "tenant|email" with the
// configured TTL; a per-user set indexes the tokens so revoking a user's
// trusted devices ("log out everywhere", password change/reset, disable 2FA)
// is one fan-out delete. The unguessable token is the security boundary, like
// the session ID.
type TrustedDevices struct {
	rc     redis.UniversalClient
	prefix string
}

// NewTrustedDevices constructs the store.
func NewTrustedDevices(rc redis.UniversalClient, opts ...Option) *TrustedDevices {
	o := applyOptions(opts)
	return &TrustedDevices{rc: rc, prefix: o.prefix}
}

var _ authkit.TrustedDeviceStore = (*TrustedDevices)(nil)

func (s *TrustedDevices) trustedKey(token string) string { return s.prefix + "td:" + token }
func (s *TrustedDevices) userKey(tenantID, email string) string {
	return s.prefix + "tdu:" + tenantID + "|" + email
}

// Trust records a trusted device for (tenant, email) and returns its token.
func (s *TrustedDevices) Trust(ctx context.Context, tenantID, email string, ttl time.Duration) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("redisstore: trusted device token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	uk := s.userKey(tenantID, email)
	pipe := s.rc.TxPipeline()
	pipe.Set(ctx, s.trustedKey(token), tenantID+"|"+email, ttl)
	pipe.SAdd(ctx, uk, token)
	pipe.Expire(ctx, uk, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("redisstore: trust device: %w", err)
	}
	return token, nil
}

// IsTrusted reports whether token is a live trusted device for (tenant, email).
func (s *TrustedDevices) IsTrusted(ctx context.Context, tenantID, email, token string) (bool, error) {
	v, err := s.rc.Get(ctx, s.trustedKey(token)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("redisstore: is trusted: %w", err)
	}
	return v == tenantID+"|"+email, nil
}

// RevokeAllForUser drops every trusted device indexed for the user.
func (s *TrustedDevices) RevokeAllForUser(ctx context.Context, tenantID, email string) error {
	uk := s.userKey(tenantID, email)
	tokens, err := s.rc.SMembers(ctx, uk).Result()
	if err != nil {
		return fmt.Errorf("redisstore: list trusted devices: %w", err)
	}
	pipe := s.rc.TxPipeline()
	for _, t := range tokens {
		pipe.Del(ctx, s.trustedKey(t))
	}
	pipe.Del(ctx, uk)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redisstore: revoke trusted devices: %w", err)
	}
	return nil
}
