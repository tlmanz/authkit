package authkit

import (
	"context"
	"errors"
	"net/http"
)

// Device capabilities. A device principal is a print agent (§7.12) — a headless
// service on a shop PC, not a human. Its capability set is FIXED and tiny: it can
// receive print jobs and report their status, and nothing else in the API. These
// names are the whole of what a device may ever do; there is no policy lookup.
const (
	CapPrintJobReceive   = "print:job.receive"
	CapPrintStatusReport = "print:status.report"
)

// ErrDeviceTokenInvalid is returned by AuthenticateDevice when the presented
// token is missing, unknown, or revoked.
var ErrDeviceTokenInvalid = errors.New("authkit: invalid device token")

// deviceCaps is the immutable allow-list of capabilities a device principal
// holds. It is defined in code (not data) precisely because a device must be
// unable to acquire any capability beyond print transport, regardless of what a
// tenant's role tables say.
var deviceCaps = map[string]struct{}{
	CapPrintJobReceive:   {},
	CapPrintStatusReport: {},
}

// IsDeviceCapability reports whether perm is one of the fixed device
// capabilities. Used to reject a programming error where a non-print capability
// is required on a device route.
func IsDeviceCapability(perm string) bool {
	_, ok := deviceCaps[perm]
	return ok
}

// Device is a device principal — a print agent bound to exactly one tenant and
// branch. It carries no human identity and resolves no permissions from a policy
// provider: its reach is the fixed deviceCaps set. The branch binds job routing
// (§10): the hub delivers a job only to agents whose tenant+branch match.
type Device struct {
	AgentID  string
	Name     string
	TenantID string
	BranchID string
}

// Can reports whether the device holds a capability. Only the fixed print
// capabilities ever pass — a device can never hold "*" or any tenant capability.
func (d *Device) Can(perm string) bool {
	if d == nil {
		return false
	}
	_, ok := deviceCaps[perm]
	return ok
}

const deviceContextKey contextKey = "authkit_device"

// DeviceFromCtx returns the device principal on ctx, or nil.
func DeviceFromCtx(ctx context.Context) *Device {
	d, _ := ctx.Value(deviceContextKey).(*Device)
	return d
}

// WithDevice returns a copy of ctx carrying the device principal. RequireDevice
// sets this; the WS hub (§10) sets it on the connection context after a
// successful upgrade authentication.
func WithDevice(ctx context.Context, d *Device) context.Context {
	return context.WithValue(ctx, deviceContextKey, d)
}

// DeviceRecord is what DeviceTokenValidator returns for a valid token. The store
// looks the token up by hash (pre-tenant, via a SECURITY DEFINER function) and
// returns only the binding the principal needs — never the token itself.
type DeviceRecord struct {
	AgentID  string
	Name     string
	TenantID string
	BranchID string
}

// DeviceTokenValidator validates an opaque device token and returns the bound
// agent. Implementations hash the token at rest and look it up before any tenant
// is known (a device authenticates with only the token). Return nil, nil when
// the token is unknown, revoked, or inactive; nil, err only on infrastructure
// failure.
type DeviceTokenValidator interface {
	ValidateDeviceToken(ctx context.Context, rawToken string) (*DeviceRecord, error)
}

// AuthenticateDevice validates a raw device token and builds the principal. It
// is the credential path shared by RequireDevice (HTTP) and the WS-upgrade
// authenticator (§10), so both bind tenant+branch identically. It does NOT touch
// ctx — the caller binds (RequireDevice via WithDevice + WithTenant; the hub on
// the connection context).
func (a *Auth) AuthenticateDevice(ctx context.Context, rawToken string) (*Device, error) {
	if a.deviceValidator == nil || rawToken == "" {
		return nil, ErrDeviceTokenInvalid
	}
	rec, err := a.deviceValidator.ValidateDeviceToken(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, ErrDeviceTokenInvalid
	}
	return &Device{AgentID: rec.AgentID, Name: rec.Name, TenantID: rec.TenantID, BranchID: rec.BranchID}, nil
}

// RequireDevice authenticates a device principal (opaque token via
// Authorization: Bearer / X-API-Key) and checks it holds the given print
// capability. It is a SEPARATE credential path from Require/RequireAuth — a
// device token never authenticates a human route, and a human credential never
// authenticates a device route, so a device "can do nothing else in the API"
// (§7.12).
//
// On success it sets both the device principal and the device's tenant on ctx
// (via WithTenant), so tenant-scoped DB access runs under the right RLS GUC. It
// panics if perm is not a fixed device capability — a wiring mistake caught at
// startup, not a runtime 403.
func (a *Auth) RequireDevice(perm string) func(http.Handler) http.Handler {
	if perm != "" && !IsDeviceCapability(perm) {
		panic("authkit: RequireDevice given non-device capability " + perm)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d, err := a.AuthenticateDevice(r.Context(), extractBearerToken(r))
			if err != nil || d == nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			if perm != "" && !d.Can(perm) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			ctx := WithDevice(WithTenant(r.Context(), d.TenantID), d)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
