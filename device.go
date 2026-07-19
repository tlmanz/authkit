package authkit

import (
	"context"
	"errors"
	"net/http"
)

// Device principals are headless machine clients — an on-premise agent, a
// kiosk, an IoT device — bound to a credential that is not a human login. A
// device principal is confined to the fixed capability allow-list the host
// declares in Config.Devices.Capabilities: the list lives in code (not policy
// data) precisely so a device can never acquire a capability beyond its
// transport role, regardless of what any role table says.

// ErrDeviceTokenInvalid is returned by AuthenticateDevice when the presented
// token is missing, unknown, or revoked.
var ErrDeviceTokenInvalid = errors.New("authkit: invalid device token")

// IsDeviceCapability reports whether perm is one of the configured device
// capabilities. Used to reject a programming error where a non-device
// capability is required on a device route.
func (a *Auth) IsDeviceCapability(perm string) bool {
	_, ok := a.deviceCaps[perm]
	return ok
}

// Device is a device principal bound to exactly one tenant. It carries no
// human identity and resolves no permissions from a policy provider: its
// reach is the configured capability allow-list. Attrs carries host-defined
// scoping (e.g. a site or location id) used for routing.
type Device struct {
	AgentID  string
	Name     string
	TenantID string
	Attrs    map[string]string

	// caps is the allow-list snapshot taken from the Auth configuration at
	// authentication time.
	caps map[string]struct{}
}

// Can reports whether the device holds a capability. Only the configured
// device capabilities ever pass — a device can never hold "*" or any
// policy-resolved permission.
func (d *Device) Can(perm string) bool {
	if d == nil {
		return false
	}
	_, ok := d.caps[perm]
	return ok
}

// Attr returns the named host-defined attribute, or "" when absent.
func (d *Device) Attr(key string) string {
	if d == nil {
		return ""
	}
	return d.Attrs[key]
}

const deviceContextKey contextKey = "authkit_device"

// DeviceFromCtx returns the device principal on ctx, or nil.
func DeviceFromCtx(ctx context.Context) *Device {
	d, _ := ctx.Value(deviceContextKey).(*Device)
	return d
}

// WithDevice returns a copy of ctx carrying the device principal. RequireDevice
// sets this; a host authenticating a non-HTTP channel (e.g. a WebSocket
// upgrade) sets it on the connection context after AuthenticateDevice.
func WithDevice(ctx context.Context, d *Device) context.Context {
	return context.WithValue(ctx, deviceContextKey, d)
}

// DeviceRecord is what DeviceTokenValidator returns for a valid token. The
// store looks the token up by hash and returns only the binding the principal
// needs — never the token itself.
type DeviceRecord struct {
	AgentID  string
	Name     string
	TenantID string
	Attrs    map[string]string
}

// DeviceTokenValidator validates an opaque device token and returns the bound
// device. Implementations hash the token at rest and look it up before any
// tenant is known (a device authenticates with only the token). Return
// nil, nil when the token is unknown, revoked, or inactive; nil, err only on
// infrastructure failure.
type DeviceTokenValidator interface {
	ValidateDeviceToken(ctx context.Context, rawToken string) (*DeviceRecord, error)
}

// AuthenticateDevice validates a raw device token and builds the principal. It
// is the credential path shared by RequireDevice (HTTP) and any host-driven
// channel authentication (e.g. a WebSocket upgrade), so both bind identically.
// It does NOT touch ctx — the caller binds (RequireDevice via WithDevice +
// WithTenant; a hub on its connection context).
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
	return &Device{
		AgentID:  rec.AgentID,
		Name:     rec.Name,
		TenantID: rec.TenantID,
		Attrs:    cloneAttrs(rec.Attrs),
		caps:     a.deviceCaps,
	}, nil
}

// RequireDevice authenticates a device principal (opaque token via
// Authorization: Bearer / X-API-Key) and checks it holds the given device
// capability. It is a SEPARATE credential path from Require/RequireAuth — a
// device token never authenticates a human route, and a human credential never
// authenticates a device route, so a device can do nothing else in the API.
//
// On success it sets both the device principal and the device's tenant on ctx
// (via WithTenant), so tenant-scoped data access runs under the right scope.
// It panics if perm is not a configured device capability — a wiring mistake
// caught at startup, not a runtime 403.
func (a *Auth) RequireDevice(perm string) func(http.Handler) http.Handler {
	if perm != "" && !a.IsDeviceCapability(perm) {
		panic("authkit: RequireDevice given undeclared device capability " + perm)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d, err := a.AuthenticateDevice(r.Context(), extractBearerToken(r))
			if err != nil || d == nil {
				a.writeError(w, r, http.StatusUnauthorized, ErrCodeUnauthenticated, "unauthenticated")
				return
			}
			if perm != "" && !d.Can(perm) {
				a.writeError(w, r, http.StatusForbidden, ErrCodeForbidden, "forbidden")
				return
			}
			ctx := WithDevice(WithTenant(r.Context(), d.TenantID), d)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
