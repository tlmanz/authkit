package redisstore

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	authkit "github.com/tlmanz/authkit/v2"
)

// Throttler implements authkit.LoginThrottler on Redis. A sliding failure
// counter (TTL = window) drives an exponential lockout once a threshold is
// crossed: the lockout doubles with each further failure, capped at max.
// Redis TTLs make both the window and the lockout self-expiring: no janitor.
type Throttler struct {
	rc          redis.UniversalClient
	maxFailures int
	base        time.Duration
	maxLock     time.Duration
	window      time.Duration
	prefix      string
}

// NewThrottler constructs the throttler. maxFailures is the threshold before a
// lockout of base is applied; each further failure doubles it up to maxLock.
// window is how long the failure counter slides before expiring.
func NewThrottler(rc redis.UniversalClient, maxFailures int, base, maxLock, window time.Duration, opts ...Option) *Throttler {
	o := applyOptions(opts)
	return &Throttler{rc: rc, maxFailures: maxFailures, base: base, maxLock: maxLock, window: window, prefix: o.prefix}
}

var _ authkit.LoginThrottler = (*Throttler)(nil)

func (t *Throttler) failKey(key string) string { return t.prefix + "throttle:fail:" + key }
func (t *Throttler) lockKey(key string) string { return t.prefix + "throttle:lock:" + key }

// Allow reports whether an attempt may proceed; when locked out it returns the
// remaining lockout as retryAfter.
func (t *Throttler) Allow(ctx context.Context, key string) (time.Duration, bool) {
	ttl, err := t.rc.PTTL(ctx, t.lockKey(key)).Result()
	if err != nil {
		// Fail open on infrastructure error: don't lock users out of login if
		// Redis hiccups (the session store would already be failing loudly).
		return 0, true
	}
	if ttl > 0 {
		return ttl, false
	}
	return 0, true
}

// RecordFailure advances the sliding counter and (re)applies the lockout once
// the threshold is reached.
func (t *Throttler) RecordFailure(ctx context.Context, key string) error {
	pipe := t.rc.TxPipeline()
	incr := pipe.Incr(ctx, t.failKey(key))
	pipe.Expire(ctx, t.failKey(key), t.window)
	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}
	n := int(incr.Val())
	if n >= t.maxFailures {
		if err := t.rc.Set(ctx, t.lockKey(key), "1", t.lockDuration(n)).Err(); err != nil {
			return err
		}
	}
	return nil
}

// Reset clears the failure counter and any lockout after a successful login.
func (t *Throttler) Reset(ctx context.Context, key string) error {
	return t.rc.Del(ctx, t.failKey(key), t.lockKey(key)).Err()
}

// lockDuration grows the lockout exponentially with failures beyond the
// threshold, capped at maxLock. At exactly the threshold it is base.
func (t *Throttler) lockDuration(failures int) time.Duration {
	over := failures - t.maxFailures
	d := t.base
	for i := 0; i < over && d < t.maxLock; i++ {
		d *= 2
	}
	if d > t.maxLock {
		d = t.maxLock
	}
	return d
}
