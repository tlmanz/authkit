package authkit

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// Sentinel errors for impersonation.
var (
	ErrImpersonationDisabled  = errors.New("authkit: impersonation is disabled")
	ErrImpersonationForbidden = errors.New("authkit: platform:impersonate capability required")
)

// PlatformAdmin is a platform principal — a super-admin operating the SaaS
// across tenants. It is a different axis from tenant RBAC and has NO TenantID
// (§6.6). Its reach comes from application logic + explicit single-tenant
// impersonation, never from the DB role (which has no BYPASSRLS).
type PlatformAdmin struct {
	Email       string
	Name        string
	Role        string
	permissions []string
}

// Can reports whether the admin holds a platform capability ("*" passes all).
func (p *PlatformAdmin) Can(perm string) bool {
	if p == nil {
		return false
	}
	for _, c := range p.permissions {
		if c == PermAll || c == perm {
			return true
		}
	}
	return false
}

const platformAdminContextKey contextKey = "authkit_platform_admin"

// PlatformAdminFromCtx returns the platform principal on ctx, or nil.
func PlatformAdminFromCtx(ctx context.Context) *PlatformAdmin {
	p, _ := ctx.Value(platformAdminContextKey).(*PlatformAdmin)
	return p
}

func withPlatformAdmin(ctx context.Context, p *PlatformAdmin) context.Context {
	return context.WithValue(ctx, platformAdminContextKey, p)
}

// PlatformAdminRecord is what PlatformAdminStore returns for login. TOTPSecret
// is the decrypted TOTP secret (the store handles encryption at rest); 2FA is
// mandatory for platform admins, so it is always present after bootstrap.
type PlatformAdminRecord struct {
	Email          string
	Name           string
	HashedPassword string
	Role           string
	TOTPSecret     string
}

// PlatformAdminStore looks up platform admins (separate from UserStore).
type PlatformAdminStore interface {
	GetPlatformAdmin(ctx context.Context, email string) (*PlatformAdminRecord, error)
}

// PlatformPolicy maps a platform role to its capabilities (a small, static
// catalog independent of the per-tenant PolicyProvider).
type PlatformPolicy interface {
	PermissionsForPlatformRole(role string) []string
}

func (a *Auth) platformCookieName() string {
	if a.cfg.SecureCookie {
		return "__Host-authkit_padmin"
	}
	return "authkit_padmin"
}

// PlatformLogin authenticates a platform admin (password + mandatory TOTP) and
// establishes a platform session. Mount on a separate route/subdomain:
// POST /platform/login. Expects form values: email, password, code.
func (a *Auth) PlatformLogin(w http.ResponseWriter, r *http.Request) {
	if a.cfg.PlatformAdminStore == nil {
		http.Error(w, "platform admin not enabled", http.StatusNotFound)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	code := strings.TrimSpace(r.FormValue("code"))

	tkey := throttleKey("platform:"+email, clientIP(r))
	if !a.throttleAllow(w, r, tkey) {
		return
	}

	rec, err := a.cfg.PlatformAdminStore.GetPlatformAdmin(r.Context(), email)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		a.throttleFailure(r.Context(), tkey)
		a.emitAudit(r.Context(), AuditEvent{Type: AuditLogin, Actor: email, IP: clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true, "result": "fail"}})
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	// Password + mandatory TOTP (no role exemption for platform admins).
	if !CheckPassword(rec.HashedPassword, password) || rec.TOTPSecret == "" || !totp.Validate(code, rec.TOTPSecret) {
		a.throttleFailure(r.Context(), tkey)
		a.emitAudit(r.Context(), AuditEvent{Type: AuditLogin, Actor: email, IP: clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true, "result": "fail"}})
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	a.throttleReset(r.Context(), tkey)

	if err := a.establishPlatformSession(r.Context(), w, r, rec); err != nil {
		a.log.Error("authkit: platform session error: %v", err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	a.emitAudit(r.Context(), AuditEvent{Type: AuditLogin, Actor: email, IP: clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true, "result": "ok"}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// establishPlatformSession mints a platform session (separate cookie, no tenant).
func (a *Auth) establishPlatformSession(ctx context.Context, w http.ResponseWriter, r *http.Request, rec *PlatformAdminRecord) error {
	if old := a.readPlatformSID(r); old != "" {
		_ = a.cfg.SessionStore.Revoke(ctx, old)
	}
	id, err := newSessionID()
	if err != nil {
		return err
	}
	now := nowFn()
	s := &Session{
		ID: id, Email: rec.Email, Name: rec.Name, Provider: "platform",
		Role: rec.Role, Platform: true, CreatedAt: now, LastSeenAt: now,
	}
	if err := a.cfg.SessionStore.Create(ctx, s); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: a.platformCookieName(), Value: id, Path: "/",
		HttpOnly: true, Secure: a.cfg.SecureCookie, SameSite: http.SameSiteLaxMode,
		MaxAge: int(a.absoluteTimeout() / time.Second),
	})
	return nil
}

func (a *Auth) readPlatformSID(r *http.Request) string {
	c, err := r.Cookie(a.platformCookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

// PlatformLogout revokes the platform session and clears the cookie.
func (a *Auth) PlatformLogout(w http.ResponseWriter, r *http.Request) {
	if id := a.readPlatformSID(r); id != "" {
		_ = a.cfg.SessionStore.Revoke(r.Context(), id)
		a.emitAudit(r.Context(), AuditEvent{Type: AuditLogout, Actor: a.platformEmail(r), IP: clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true}})
	}
	http.SetCookie(w, &http.Cookie{Name: a.platformCookieName(), Value: "", Path: "/", HttpOnly: true, Secure: a.cfg.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *Auth) platformEmail(r *http.Request) string {
	if p := PlatformAdminFromCtx(r.Context()); p != nil {
		return p.Email
	}
	return ""
}

// platformAdminFromSession loads + validates the platform session and resolves
// the admin's platform capabilities. Returns nil when absent/expired.
func (a *Auth) platformAdminFromSession(ctx context.Context, r *http.Request) *PlatformAdmin {
	id := a.readPlatformSID(r)
	if id == "" {
		return nil
	}
	s, err := a.cfg.SessionStore.Get(ctx, id)
	if err != nil || s == nil || !s.Platform {
		return nil
	}
	now := nowFn()
	if now.Sub(s.CreatedAt) > a.absoluteTimeout() || now.Sub(s.LastSeenAt) > a.idleTimeout() {
		_ = a.cfg.SessionStore.Revoke(ctx, id)
		return nil
	}
	if now.Sub(s.LastSeenAt) > sessionTouchInterval {
		_ = a.cfg.SessionStore.Touch(ctx, id, now)
	}
	var perms []string
	if a.cfg.PlatformPolicy != nil {
		perms = a.cfg.PlatformPolicy.PermissionsForPlatformRole(s.Role)
	}
	return &PlatformAdmin{Email: s.Email, Name: s.Name, Role: s.Role, permissions: perms}
}

// RequirePlatformAdmin authenticates a platform principal and checks a platform
// capability. It NEVER sets the tenant GUC (§6.6). 401 without a platform
// session, 403 without the capability.
func (a *Auth) RequirePlatformAdmin(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := a.platformAdminFromSession(r.Context(), r)
			if p == nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			if perm != "" && !p.Can(perm) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(withPlatformAdmin(r.Context(), p)))
		})
	}
}

// ImpersonationContext returns a single-tenant-scoped context for a platform
// admin to act within exactly one tenant (break-glass). It requires the
// `platform:impersonate` capability and is audited. Downstream tenant-scoped DB
// access then runs under normal RLS for that one tenant — the admin is confined,
// never able to read across tenants.
func (a *Auth) ImpersonationContext(ctx context.Context, admin *PlatformAdmin, tenantID string) (context.Context, error) {
	if !a.cfg.EnableImpersonation {
		return nil, ErrImpersonationDisabled
	}
	if admin == nil || !admin.Can("platform:impersonate") {
		return nil, ErrImpersonationForbidden
	}
	a.emitAudit(ctx, AuditEvent{Type: AuditImpersonate, Actor: admin.Email, TenantID: tenantID, At: nowFn(), Meta: map[string]any{"platform": true}})
	return WithTenant(ctx, tenantID), nil
}
