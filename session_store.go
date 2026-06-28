package authkit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

// nowFn is the clock, overridable in tests.
var nowFn = time.Now

// Session is a server-side session record. The cookie holds only the opaque ID;
// all identity state lives in the SessionStore, enabling instant revocation and
// "log out everywhere" — things a stateless cookie cannot do.
type Session struct {
	ID          string
	TenantID    string
	BranchID    string
	Email       string
	Name        string
	Provider    string
	Role        string
	Permissions []string

	// Platform marks a super-admin (platform principal) session — no tenant.
	// Tenant and platform sessions use different cookies, so they never cross.
	Platform bool

	// CreatedAt anchors the absolute timeout; LastSeenAt anchors the idle
	// timeout (advanced by Touch on a sliding basis).
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// SessionStore is the revocable, server-side session backend (DB or Redis). The
// host application implements it; authkit generates the opaque IDs and enforces
// the idle/absolute timeouts.
//
// Get is called before the tenant is known (it resolves the session by its
// unguessable ID), so implementations MUST be able to read by ID without a
// tenant scope. Create/Touch/Revoke/RevokeAllForUser are always called with the
// session's tenant already on the context.
type SessionStore interface {
	// Create persists a new session. Returns an error only on infrastructure failure.
	Create(ctx context.Context, s *Session) error
	// Get returns the session for id, or nil when it does not exist.
	Get(ctx context.Context, id string) (*Session, error)
	// Touch advances LastSeenAt for sliding idle renewal.
	Touch(ctx context.Context, id string, lastSeen time.Time) error
	// Revoke deletes a single session (logout / fixation rotation).
	Revoke(ctx context.Context, id string) error
	// RevokeAllForUser deletes every session for a user ("log out everywhere").
	RevokeAllForUser(ctx context.Context, tenantID, email string) error
}

const (
	defaultIdleTimeout     = 30 * time.Minute
	defaultAbsoluteTimeout = 24 * time.Hour
	// sessionTouchInterval throttles idle-renewal writes: LastSeenAt is only
	// advanced once per interval, not on every request.
	sessionTouchInterval = time.Minute
)

func (a *Auth) idleTimeout() time.Duration {
	if a.cfg.IdleTimeout > 0 {
		return a.cfg.IdleTimeout
	}
	return defaultIdleTimeout
}

func (a *Auth) absoluteTimeout() time.Duration {
	if a.cfg.AbsoluteTimeout > 0 {
		return a.cfg.AbsoluteTimeout
	}
	return defaultAbsoluteTimeout
}

// newSessionID returns a 256-bit opaque, URL-safe session identifier.
func newSessionID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// sidCookieName uses the __Host- prefix in production (requires Secure + Path=/
// + no Domain), which browsers reject over plain HTTP, so dev uses a plain name.
func (a *Auth) sidCookieName() string {
	if a.cfg.SecureCookie {
		return "__Host-authkit_sid"
	}
	return "authkit_sid"
}

func (a *Auth) writeSIDCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.sidCookieName(),
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(a.absoluteTimeout() / time.Second),
	})
}

func (a *Auth) clearSIDCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.sidCookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (a *Auth) readSID(r *http.Request) string {
	c, err := r.Cookie(a.sidCookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

// establishServerSession rotates to a fresh session ID on login (fixation
// prevention): it revokes any pre-existing session, creates a new record, and
// sets the cookie. ctx must already carry the user's tenant (so the store's
// tenant-scoped insert passes RLS).
func (a *Auth) establishServerSession(ctx context.Context, w http.ResponseWriter, r *http.Request, u *User) error {
	if old := a.readSID(r); old != "" {
		_ = a.cfg.SessionStore.Revoke(ctx, old)
	}
	id, err := newSessionID()
	if err != nil {
		return err
	}
	now := nowFn()
	s := &Session{
		ID:          id,
		TenantID:    u.TenantID,
		BranchID:    u.BranchID,
		Email:       u.Email,
		Name:        u.Name,
		Provider:    u.Provider,
		Role:        u.Role,
		Permissions: u.permissions,
		CreatedAt:   now,
		LastSeenAt:  now,
	}
	if err := a.cfg.SessionStore.Create(ctx, s); err != nil {
		return err
	}
	a.writeSIDCookie(w, id)
	return nil
}

// serverSessionUser loads and validates the session from the cookie, enforcing
// the absolute and idle timeouts and performing throttled sliding renewal.
// Returns nil (not an error) when there is no valid session.
func (a *Auth) serverSessionUser(ctx context.Context, r *http.Request) (*User, error) {
	id := a.readSID(r)
	if id == "" {
		return nil, nil
	}
	s, err := a.cfg.SessionStore.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, nil
	}

	now := nowFn()
	if now.Sub(s.CreatedAt) > a.absoluteTimeout() || now.Sub(s.LastSeenAt) > a.idleTimeout() {
		// Expired — revoke (scoped to the session's tenant) and treat as logged out.
		_ = a.cfg.SessionStore.Revoke(WithTenant(ctx, s.TenantID), id)
		return nil, nil
	}

	if now.Sub(s.LastSeenAt) > sessionTouchInterval {
		_ = a.cfg.SessionStore.Touch(WithTenant(ctx, s.TenantID), id, now)
	}

	return &User{
		Email:       s.Email,
		Name:        s.Name,
		Provider:    s.Provider,
		Role:        s.Role,
		TenantID:    s.TenantID,
		BranchID:    s.BranchID,
		permissions: s.Permissions,
	}, nil
}

// destroyServerSession revokes the current session and clears the cookie.
func (a *Auth) destroyServerSession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if id := a.readSID(r); id != "" {
		// Resolve the tenant from the session so the scoped delete passes RLS.
		if s, _ := a.cfg.SessionStore.Get(ctx, id); s != nil {
			_ = a.cfg.SessionStore.Revoke(WithTenant(ctx, s.TenantID), id)
		}
	}
	a.clearSIDCookie(w)
}

// ── unified entry points (branch between server-side store and legacy cookie) ─

// saveSession persists the authenticated user — server-side when a SessionStore
// is configured, otherwise the legacy encrypted cookie.
func (a *Auth) saveSession(ctx context.Context, w http.ResponseWriter, r *http.Request, u *User) error {
	if a.cfg.SessionStore != nil {
		return a.establishServerSession(ctx, w, r, u)
	}
	return saveUserToSession(a.store, w, r, u)
}

// loadSession resolves the user from the request's session.
func (a *Auth) loadSession(ctx context.Context, r *http.Request) (*User, error) {
	if a.cfg.SessionStore != nil {
		return a.serverSessionUser(ctx, r)
	}
	return userFromSession(a.store, r, a.log)
}

// endSession terminates the current session.
func (a *Auth) endSession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if a.cfg.SessionStore != nil {
		a.destroyServerSession(ctx, w, r)
		return
	}
	clearSession(a.store, w, r)
}

// RevokeUserSessions revokes every server-side session for a user — the
// "log out everywhere" / fired-employee path. No-op when no SessionStore is
// configured. ctx must carry the user's tenant.
func (a *Auth) RevokeUserSessions(ctx context.Context, tenantID, email string) error {
	if a.cfg.SessionStore == nil {
		return nil
	}
	return a.cfg.SessionStore.RevokeAllForUser(ctx, tenantID, email)
}
