package authkit

import (
	"encoding/json"
	"net/http"
)

// Machine-readable error codes. Every error response authkit writes carries one
// of these in the "error" field of the JSON envelope, so clients (SPAs, mobile
// apps) can branch and localize without parsing English prose. The set is part
// of the public API: codes are only ever added, never renamed.
const (
	ErrCodeUnauthenticated   = "unauthenticated"     // 401: no valid credential
	ErrCodeInvalidCredential = "invalid_credentials" // 401: wrong email/password
	ErrCodeInvalidCode       = "invalid_code"        // 401: wrong TOTP/recovery code
	ErrCodeInvalidChallenge  = "invalid_challenge"   // 401: missing/expired pending step
	ErrCodeForbidden         = "forbidden"           // 403: authenticated but not allowed
	ErrCodeCSRF              = "csrf_invalid"        // 403: CSRF check failed
	ErrCodeInvalidRequest    = "invalid_request"     // 400: malformed input
	ErrCodePasswordPolicy    = "password_policy"     // 400: password rejected by policy
	ErrCodeInvalidGrant      = "invalid_grant"       // 400/401: OAuth2 token-flow failures
	ErrCodeUnsupportedGrant  = "unsupported_grant_type"
	ErrCodeConflict          = "conflict"     // 409: already exists / already enrolled
	ErrCodeRateLimited       = "rate_limited" // 429: throttled; Retry-After is set
	ErrCodeNotEnabled        = "not_enabled"  // 404: feature not configured
	ErrCodeServerError       = "server_error" // 500: unexpected failure
)

// ErrorWriter lets the host replace authkit's error rendering (for example to
// emit RFC 9457 problem+json or add a trace id). status is the HTTP status,
// code one of the ErrCode* constants, desc a short human-readable default.
// When nil, authkit writes {"error": code, "error_description": desc}.
type ErrorWriter func(w http.ResponseWriter, r *http.Request, status int, code, desc string)

// writeError renders an error through the configured ErrorWriter, defaulting
// to the uniform JSON envelope. The envelope shape matches the OAuth2 token
// error format so token endpoints and web endpoints read the same way.
func (a *Auth) writeError(w http.ResponseWriter, r *http.Request, status int, code, desc string) {
	if a.cfg.ErrorWriter != nil {
		a.cfg.ErrorWriter(w, r, status, code, desc)
		return
	}
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
