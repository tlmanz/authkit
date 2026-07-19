package redisstore

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	authkit "github.com/tlmanz/authkit/v2"
)

// AuthCodes implements authkit.AuthCodeStore on Redis: it makes PKCE
// authorization codes single-use by claiming each code's jti at redemption.
// SETNX is the atomic "first use wins" primitive and the native TTL
// self-expires the record after the code's short lifetime, so nothing
// accumulates.
type AuthCodes struct {
	rc     redis.UniversalClient
	prefix string
}

// NewAuthCodes constructs the store.
func NewAuthCodes(rc redis.UniversalClient, opts ...Option) *AuthCodes {
	o := applyOptions(opts)
	return &AuthCodes{rc: rc, prefix: o.prefix}
}

var _ authkit.AuthCodeStore = (*AuthCodes)(nil)

func (s *AuthCodes) key(jti string) string { return s.prefix + "authcode:" + jti }

// ClaimAuthCode records jti as redeemed and returns ok=true only on its first
// use; a second redemption within the TTL returns ok=false (replay). expiresAt
// bounds how long the guard remembers the code (the signed code's own exp gates
// validity regardless).
func (s *AuthCodes) ClaimAuthCode(ctx context.Context, jti string, expiresAt time.Time) (bool, error) {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// The code is already past its exp; still claim briefly so a racing replay
		// of a just-expired code can't slip through before the signed-exp check.
		ttl = time.Minute
	}
	ok, err := s.rc.SetNX(ctx, s.key(jti), "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redisstore: claim auth code: %w", err)
	}
	return ok, nil
}
