package authkit

import (
	"context"
	"time"
)

// AuditEvent is a single auditable security event emitted by authkit. The host
// application wires an AuditSink to persist these to its audit log.
//
// Type is one of the well-known constants below. TenantID is empty for platform
// principals and for pre-tenant events (e.g. a failed login before the user is
// resolved). Actor is who performed the action (email or admin id); Subject is
// who/what it acted on (often the same as Actor for self-service events). Meta
// carries event-specific detail (provider, session id, role names, etc.).
type AuditEvent struct {
	Type     string
	TenantID string
	Actor    string
	Subject  string
	IP       string
	At       time.Time
	Meta     map[string]any
}

// Well-known audit event types.
const (
	AuditLogin            = "login"
	AuditLogout           = "logout"
	AuditRefresh          = "refresh"
	AuditRevoke           = "revoke"
	Audit2FAEnroll        = "2fa_enroll"
	Audit2FAVerify        = "2fa_verify"
	Audit2FADisable       = "2fa_disable"
	Audit2FARecoveryRegen = "2fa_recovery_regenerate"
	AuditPasswordChange   = "password_change"
	AuditRoleChange       = "role_change"
	AuditPermissionChange = "permission_change"
	AuditImpersonate      = "impersonate"

	// Password reset: a recovery token was requested, and (later) a password was
	// actually changed via a consumed token.
	AuditPasswordResetRequest = "password_reset_request"
	AuditPasswordReset        = "password_reset"
)

// AuditSink receives audit events. Implementations MUST NOT block the request
// path on slow I/O — buffer or hand off as needed. Emit is best-effort from
// authkit's perspective; it never returns an error to the caller.
type AuditSink interface {
	Emit(ctx context.Context, ev AuditEvent)
}

// NopAuditSink discards every event. It is the default when Config.AuditSink is
// nil, so callers can emit unconditionally without nil checks.
type NopAuditSink struct{}

// Emit implements AuditSink and does nothing.
func (NopAuditSink) Emit(context.Context, AuditEvent) {}

// emitAudit emits an event, tolerating a nil sink (Auth values constructed
// outside New, e.g. in tests, have no default sink installed).
func (a *Auth) emitAudit(ctx context.Context, ev AuditEvent) {
	if a.audit != nil {
		a.audit.Emit(ctx, ev)
	}
}
