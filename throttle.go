package authkit

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// LoginThrottler rate-limits authentication attempts to blunt credential
// stuffing and brute force. The host implements it (e.g. backed by Redis);
// authkit calls it around the password login flow. Keys are per account+IP.
type LoginThrottler interface {
	// Allow reports whether an attempt for key may proceed. When locked out, ok
	// is false and retryAfter is the remaining lockout duration.
	Allow(ctx context.Context, key string) (retryAfter time.Duration, ok bool)
	// RecordFailure registers a failed attempt (advancing backoff/lockout).
	RecordFailure(ctx context.Context, key string) error
	// Reset clears the failure state for key after a successful login.
	Reset(ctx context.Context, key string) error
}

// throttleKey derives the per account+IP key.
func throttleKey(email, ip string) string {
	return strings.ToLower(strings.TrimSpace(email)) + "|" + ip
}

// clientIP returns the request's source IP (host portion of RemoteAddr). It
// deliberately does NOT trust X-Forwarded-For — behind a proxy the host app
// should set RemoteAddr from a vetted header before authkit sees the request.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// throttleAllow checks the throttler (if configured) before an attempt. It
// returns false and writes a 429 + Retry-After when the caller is locked out.
func (a *Auth) throttleAllow(w http.ResponseWriter, r *http.Request, key string) bool {
	if a.throttler == nil {
		return true
	}
	retryAfter, ok := a.throttler.Allow(r.Context(), key)
	if ok {
		return true
	}
	secs := max(int(retryAfter.Seconds()), 1)
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	http.Error(w, "too many attempts — try again later", http.StatusTooManyRequests)
	return false
}

func (a *Auth) throttleFailure(ctx context.Context, key string) {
	if a.throttler != nil {
		_ = a.throttler.RecordFailure(ctx, key)
	}
}

func (a *Auth) throttleReset(ctx context.Context, key string) {
	if a.throttler != nil {
		_ = a.throttler.Reset(ctx, key)
	}
}
