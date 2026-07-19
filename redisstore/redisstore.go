// Package redisstore provides ready-made Redis implementations of authkit's
// storage interfaces whose data is naturally self-expiring:
//
//   - Sessions        (authkit.SessionStore)       — revocable server-side sessions
//   - Throttler       (authkit.LoginThrottler)     — login rate limiting + lockout
//   - TrustedDevices  (authkit.TrustedDeviceStore) — "remember this device" tokens
//   - AuthCodes       (authkit.AuthCodeStore)      — single-use PKCE codes
//
// Redis native key TTLs map cleanly onto idle/absolute session expiry, lockout
// windows, and trust lifetimes, so none of these stores needs a cleanup job.
// Stores that hold long-lived or relational data (users, refresh-token rotation
// lineage, TOTP secrets, password-reset tokens) are deliberately NOT provided
// here — those belong in your primary database.
//
// All stores accept a go-redis UniversalClient, so they work against a single
// node, Sentinel, or Cluster. An optional key prefix namespaces multiple
// applications sharing one Redis.
package redisstore

// Option configures a store constructor.
type Option func(*options)

type options struct {
	prefix string
}

// WithKeyPrefix namespaces every key the store writes (e.g. "myapp:").
// Default: no prefix.
func WithKeyPrefix(p string) Option {
	return func(o *options) { o.prefix = p }
}

func applyOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
