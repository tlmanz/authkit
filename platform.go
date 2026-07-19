package authkit

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// The platform axis models the operator of a multi-tenant SaaS: principals who
// onboard/suspend tenants and run the platform itself. It is a different axis
// from tenant RBAC — a platform admin has NO TenantID, authenticates on a
// separate route with its own cookie, and 2FA is mandatory with no role
// exemption. Reach into a tenant's data only ever happens through the audited,
// single-tenant impersonation flow.

func (a *Auth) platformPendingCookieName() string { return a.cookieName("padmin_pending") }

// issuePlatformPendingToken mints a short-lived signed token proving a platform
// admin passed the password step and is awaiting the TOTP step. The "padmin:"
// signing prefix namespaces it from the user 2FA pending token, so neither can
// be replayed against the other's verify endpoint.
func (a *Auth) issuePlatformPendingToken(email string) string {
	c := pendingClaims{Email: email, Exp: nowFn().Add(twofaPendingTTL).Unix()}
	j, _ := json.Marshal(c)
	payload := base64.RawURLEncoding.EncodeToString(j)
	return payload + "." + a.sign("padmin:"+payload)
}

func (a *Auth) readPlatformPending(r *http.Request) (string, bool) {
	c, err := r.Cookie(a.platformPendingCookieName())
	if err != nil {
		return "", false
	}
	payload, mac, ok := strings.Cut(c.Value, ".")
	if !ok || subtle.ConstantTimeCompare([]byte(mac), []byte(a.sign("padmin:"+payload))) != 1 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	var cl pendingClaims
	if err := json.Unmarshal(raw, &cl); err != nil || cl.Email == "" {
		return "", false
	}
	if nowFn().Unix() > cl.Exp {
		return "", false
	}
	return cl.Email, true
}

func (a *Auth) setPlatformPendingCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: a.platformPendingCookieName(), Value: token, Path: "/",
		HttpOnly: true, Secure: a.cfg.SecureCookie, SameSite: http.SameSiteLaxMode,
		MaxAge: int(twofaPendingTTL / time.Second),
	})
}

func (a *Auth) clearPlatformPendingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: a.platformPendingCookieName(), Value: "", Path: "/",
		HttpOnly: true, Secure: a.cfg.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// Sentinel errors for impersonation.
var (
	ErrImpersonationDisabled  = errors.New("authkit: impersonation is disabled")
	ErrImpersonationForbidden = errors.New("authkit: platform:impersonate capability required")
)

// PlatformAdmin is a platform principal — an operator of the SaaS across
// tenants. It is a different axis from tenant RBAC and has NO TenantID. Its
// reach comes from application logic + explicit single-tenant impersonation,
// never from a database-level bypass.
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
// is the decrypted TOTP secret (the store handles encryption at rest), and is
// empty for an admin who has not enrolled yet; TOTPConfirmed reports whether that
// secret has been activated by a first successful verification. 2FA is mandatory,
// but a newly created admin enrolls on first login (pending→confirmed), so the
// secret is not always present immediately.
type PlatformAdminRecord struct {
	Email          string
	Name           string
	HashedPassword string
	Role           string
	TOTPSecret     string
	TOTPConfirmed  bool
}

// PlatformAdminStore looks up platform admins (separate from UserStore) and backs
// their TOTP enrollment. Admin lifecycle (create/list/remove) lives in the host
// app's own store methods; this interface is only what authkit's auth flow needs.
type PlatformAdminStore interface {
	GetPlatformAdmin(ctx context.Context, email string) (*PlatformAdminRecord, error)

	// UpdatePassword sets the hashed password for the platform admin with
	// this email. Called by the platform password-reset flow; it does NOT touch
	// the TOTP secret (2FA stays mandatory). Platform admins are not
	// tenant-scoped.
	UpdatePassword(ctx context.Context, email, hashedPassword string) error

	// EnrollPlatformTOTP stores (or replaces) a PENDING secret + recovery hashes
	// for an admin who has not confirmed 2FA yet (mirrors the user TOTPStore).
	EnrollPlatformTOTP(ctx context.Context, email, secret string, recoveryCodeHashes []string) error
	// ConfirmPlatformTOTP activates a pending secret on first successful verify.
	// Idempotent: a no-op once confirmed.
	ConfirmPlatformTOTP(ctx context.Context, email string) error
	// ConsumePlatformRecovery atomically marks a recovery code used (single-use)
	// and reports whether it matched an unused code.
	ConsumePlatformRecovery(ctx context.Context, email, codeHash string) (bool, error)
}

// PlatformPolicy maps a platform role to its capabilities (a small, static
// catalog independent of the per-tenant PolicyProvider).
type PlatformPolicy interface {
	PermissionsForPlatformRole(role string) []string
}

func (a *Auth) platformCookieName() string { return a.cookieName("padmin") }

// PlatformLogin is step ONE of platform login: it verifies the email + password
// and, only on success, starts the mandatory TOTP challenge (no role exemption).
// It does NOT mint a session — the client must then call PlatformVerify2FA with
// the code. Mount on a separate route/subdomain: POST /platform/login. Expects
// fields: email, password.
func (a *Auth) PlatformLogin(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Platform.Store == nil {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "platform admin not enabled")
		return
	}
	parseBody(r)
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	tkey := throttleKey("platform:"+email, a.clientIP(r))
	if !a.throttleAllow(w, r, tkey) {
		return
	}

	rec, err := a.cfg.Platform.Store.GetPlatformAdmin(r.Context(), email)
	if err != nil {
		a.dummyVerify(password)
		a.platformLoginFail(r, tkey, email)
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidCredential, "invalid credentials")
		return
	}
	if !a.checkPassword(rec.HashedPassword, password) {
		a.platformLoginFail(r, tkey, email)
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidCredential, "invalid credentials")
		return
	}

	// A previously trusted device ("remember this device") skips the TOTP step, but
	// only once 2FA is actually enrolled — a not-yet-confirmed admin must still
	// enroll. The password was already required, and the trusted token is opaque,
	// server-side, revocable and expiring. Platform admins have no tenant, so the
	// trusted-device key uses an empty tenant.
	if rec.TOTPConfirmed && a.trustedDeviceValid(r, "", email) {
		a.throttleReset(r.Context(), tkey)
		if err := a.establishPlatformSession(r.Context(), w, r, rec); err != nil {
			a.log.Error("platform session error (trusted device)", "err", err)
			a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "session error")
			return
		}
		a.emitAudit(r.Context(), AuditEvent{Type: AuditLogin, Actor: email, IP: a.clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true, "result": "ok", "trusted_device": true}})
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	// Password correct → arm the TOTP step. A newly created admin who has not yet
	// confirmed 2FA enrolls now (pending→confirm); everyone else verifies. Throttle
	// is reset only on full success.
	a.setPlatformPendingCookie(w, a.issuePlatformPendingToken(email))
	action := "verify"
	if !rec.TOTPConfirmed {
		action = "enroll"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "2fa_required", "action": action})
}

func (a *Auth) platformLoginFail(r *http.Request, tkey, email string) {
	a.throttleFailure(r.Context(), tkey)
	a.emitAudit(r.Context(), AuditEvent{Type: AuditLogin, Actor: email, IP: a.clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true, "result": "fail"}})
}

// PlatformVerify2FA is step TWO: it validates the TOTP code for the admin in the
// platform-pending state (password already verified) and, on success, establishes
// the platform session. Mount on: POST /platform/2fa/verify. Fields: code.
func (a *Auth) PlatformVerify2FA(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Platform.Store == nil {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "platform admin not enabled")
		return
	}
	parseBody(r)
	email, ok := a.readPlatformPending(r)
	if !ok {
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidChallenge, "no pending platform challenge")
		return
	}
	tkey := throttleKey("platform:"+email, a.clientIP(r))
	if !a.throttleAllow(w, r, tkey) {
		return
	}

	rec, err := a.cfg.Platform.Store.GetPlatformAdmin(r.Context(), email)
	if err != nil {
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidChallenge, "invalid challenge")
		return
	}
	if !a.validatePlatform2FA(r.Context(), rec, r) {
		a.platformLoginFail(r, tkey, email)
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidCode, "invalid code")
		return
	}
	// First successful verification confirms a pending enrollment (idempotent once
	// confirmed), so subsequent logins go straight to verify.
	if err := a.cfg.Platform.Store.ConfirmPlatformTOTP(r.Context(), email); err != nil {
		a.log.Error("platform totp confirm failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	a.throttleReset(r.Context(), tkey)
	a.clearPlatformPendingCookie(w)

	// Honor "remember this device": mint + set a trusted-device cookie so the next
	// login on this browser skips 2FA (best-effort; empty tenant for platform).
	a.rememberDevice(r.Context(), w, r, "", email)

	if err := a.establishPlatformSession(r.Context(), w, r, rec); err != nil {
		a.log.Error("platform session error", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "session error")
		return
	}
	a.emitAudit(r.Context(), AuditEvent{Type: AuditLogin, Actor: email, IP: a.clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true, "result": "ok"}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// validatePlatform2FA checks the submitted recovery code or TOTP code against the
// admin's record. A pending (unconfirmed) secret still validates — the first valid
// code is what confirms it (PlatformVerify2FA calls ConfirmPlatformTOTP on success).
func (a *Auth) validatePlatform2FA(ctx context.Context, rec *PlatformAdminRecord, r *http.Request) bool {
	if rc := strings.TrimSpace(r.FormValue("recovery_code")); rc != "" {
		ok, err := a.cfg.Platform.Store.ConsumePlatformRecovery(ctx, rec.Email, hashRecoveryCode(rc))
		return err == nil && ok
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" || rec.TOTPSecret == "" {
		return false
	}
	ts, ok := matchTOTPTimestep(code, rec.TOTPSecret, nowFn())
	if !ok {
		return false
	}
	// Anti-replay (opt-in), same reasoning as the user path (validate2FA).
	if g, has := a.cfg.Platform.Store.(PlatformTOTPReplayGuard); has {
		claimed, cerr := g.ClaimPlatformTOTPTimestep(ctx, rec.Email, ts)
		if cerr != nil {
			a.log.Error("platform totp replay claim failed", "err", cerr)
		} else if !claimed {
			return false
		}
	}
	return true
}

// PlatformEnroll2FA provisions a PENDING TOTP secret + recovery codes for a
// platform admin who passed the password step but has not enrolled 2FA yet, and
// returns the otpauth URL + recovery codes to show once. The admin confirms by
// calling PlatformVerify2FA with a code. Mount on: POST /platform/2fa/enroll.
//
// It refuses once 2FA is confirmed: a stolen password alone must never be able to
// re-enroll (and thus reset) a platform admin's authenticator. Re-enrollment of a
// confirmed admin only happens after another admin resets their 2FA.
func (a *Auth) PlatformEnroll2FA(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Platform.Store == nil {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "platform admin not enabled")
		return
	}
	email, ok := a.readPlatformPending(r)
	if !ok {
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidChallenge, "no pending platform challenge")
		return
	}
	rec, err := a.cfg.Platform.Store.GetPlatformAdmin(r.Context(), email)
	if err != nil {
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeInvalidChallenge, "invalid challenge")
		return
	}
	if rec.TOTPConfirmed {
		a.writeError(w, r, http.StatusConflict, ErrCodeConflict, "2fa already enrolled")
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: a.appName() + " Platform", AccountName: email})
	if err != nil {
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	plain, hashes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	if err := a.cfg.Platform.Store.EnrollPlatformTOTP(r.Context(), email, key.Secret(), hashes); err != nil {
		a.log.Error("platform totp enroll failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"otpauthUrl":    key.URL(),
		"secret":        key.Secret(),
		"recoveryCodes": plain,
	})
}

// establishPlatformSession mints a platform session (separate cookie, no tenant).
func (a *Auth) establishPlatformSession(ctx context.Context, w http.ResponseWriter, r *http.Request, rec *PlatformAdminRecord) error {
	if old := a.readPlatformSID(r); old != "" {
		_ = a.cfg.Sessions.Store.Revoke(ctx, old)
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
	if err := a.cfg.Sessions.Store.Create(ctx, s); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: a.platformCookieName(), Value: id, Path: "/",
		HttpOnly: true, Secure: a.cfg.SecureCookie, SameSite: http.SameSiteLaxMode,
		MaxAge: int(a.absoluteTimeout() / time.Second),
	})
	return nil
}

// EstablishPlatformSession mints a platform session for rec exactly as a
// completed platform login would. It exists for host-controlled flows that
// authenticate a platform admin outside the built-in password+TOTP handlers —
// a development bypass, a test harness, or a future SSO bridge.
//
// SECURITY: the built-in flow requires password AND TOTP before ever reaching
// this point; a caller takes on that responsibility. Never expose a code path
// that reaches this from unauthenticated input in production.
func (a *Auth) EstablishPlatformSession(ctx context.Context, w http.ResponseWriter, r *http.Request, rec *PlatformAdminRecord) error {
	return a.establishPlatformSession(ctx, w, r, rec)
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
		_ = a.cfg.Sessions.Store.Revoke(r.Context(), id)
		a.emitAudit(r.Context(), AuditEvent{Type: AuditLogout, Actor: a.platformEmail(r), IP: a.clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true}})
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

// PlatformMe returns the currently signed-in platform admin (from the platform
// session cookie), or 401 when there is none. It is the platform counterpart to
// Me, letting a client confirm the platform session and show who is logged in.
// Mount on: GET /platform/me
func (a *Auth) PlatformMe(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Platform.Store == nil {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "platform admin not enabled")
		return
	}
	p := a.platformAdminFromSession(r.Context(), r)
	if p == nil {
		a.writeError(w, r, http.StatusUnauthorized, ErrCodeUnauthenticated, "unauthenticated")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"email": p.Email,
		"name":  p.Name,
		"role":  p.Role,
	})
}

// platformAdminFromSession loads + validates the platform session and resolves
// the admin's platform capabilities. Returns nil when absent/expired.
func (a *Auth) platformAdminFromSession(ctx context.Context, r *http.Request) *PlatformAdmin {
	id := a.readPlatformSID(r)
	if id == "" {
		return nil
	}
	s, err := a.cfg.Sessions.Store.Get(ctx, id)
	if err != nil || s == nil || !s.Platform {
		return nil
	}
	now := nowFn()
	if now.Sub(s.CreatedAt) > a.absoluteTimeout() || now.Sub(s.LastSeenAt) > a.idleTimeout() {
		_ = a.cfg.Sessions.Store.Revoke(ctx, id)
		return nil
	}
	if now.Sub(s.LastSeenAt) > sessionTouchInterval {
		_ = a.cfg.Sessions.Store.Touch(ctx, id, now)
	}
	var perms []string
	if a.cfg.Platform.Policy != nil {
		perms = a.cfg.Platform.Policy.PermissionsForPlatformRole(s.Role)
	}
	return &PlatformAdmin{Email: s.Email, Name: s.Name, Role: s.Role, permissions: perms}
}

// RequirePlatformAdmin authenticates a platform principal and checks a platform
// capability. It NEVER sets a tenant on the context — platform routes operate
// on platform data only. 401 without a platform session, 403 without the
// capability.
func (a *Auth) RequirePlatformAdmin(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := a.platformAdminFromSession(r.Context(), r)
			if p == nil {
				a.writeError(w, r, http.StatusUnauthorized, ErrCodeUnauthenticated, "unauthenticated")
				return
			}
			if perm != "" && !p.Can(perm) {
				a.writeError(w, r, http.StatusForbidden, ErrCodeForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r.WithContext(withPlatformAdmin(r.Context(), p)))
		})
	}
}

// ImpersonationContext returns a single-tenant-scoped context for a platform
// admin to act within exactly one tenant (break-glass support access). It
// requires the `platform:impersonate` capability and is audited. Downstream
// tenant-scoped data access then runs under that one tenant's normal scoping —
// the admin is confined, never able to read across tenants.
func (a *Auth) ImpersonationContext(ctx context.Context, admin *PlatformAdmin, tenantID string) (context.Context, error) {
	if !a.cfg.Platform.EnableImpersonation {
		return nil, ErrImpersonationDisabled
	}
	if admin == nil || !admin.Can("platform:impersonate") {
		return nil, ErrImpersonationForbidden
	}
	a.emitAudit(ctx, AuditEvent{Type: AuditImpersonate, Actor: admin.Email, TenantID: tenantID, At: nowFn(), Meta: map[string]any{"platform": true}})
	return WithTenant(ctx, tenantID), nil
}
