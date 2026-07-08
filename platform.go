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
	"golang.org/x/crypto/bcrypt"
)

const platformPendingCookieNm = "authkit_padmin_pending"

func (a *Auth) platformPendingCookieName() string {
	if a.cfg.SecureCookie {
		return "__Host-" + platformPendingCookieNm
	}
	return platformPendingCookieNm
}

// issuePlatformPendingToken mints a short-lived signed token proving a platform
// admin passed the password step and is awaiting the TOTP step. The "padmin:"
// signing prefix namespaces it from the tenant 2FA pending token, so neither can
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
// is the decrypted TOTP secret (the store handles encryption at rest), and is
// empty for an admin who has not enrolled yet; TOTPConfirmed reports whether that
// secret has been activated by a first successful verification. 2FA is mandatory,
// but a console-created admin enrolls on first login (pending→confirmed), so the
// secret is not always present immediately (only after bootstrap, or post-enroll).
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

	// UpdatePassword sets the bcrypt-hashed password for the platform admin with
	// this email. Called by the platform password-reset flow; it does NOT touch
	// the TOTP secret (2FA stays mandatory). Runs on the pool — platform_admins
	// has no RLS.
	UpdatePassword(ctx context.Context, email, hashedPassword string) error

	// EnrollPlatformTOTP stores (or replaces) a PENDING secret + recovery hashes
	// for an admin who has not confirmed 2FA yet (mirrors the tenant TOTPStore).
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

func (a *Auth) platformCookieName() string {
	if a.cfg.SecureCookie {
		return "__Host-authkit_padmin"
	}
	return "authkit_padmin"
}

// PlatformLogin is step ONE of platform login: it verifies the email + password
// and, only on success, starts the mandatory TOTP challenge (no role exemption).
// It does NOT mint a session — the client must then call PlatformVerify2FA with
// the code. Mount on a separate route/subdomain: POST /platform/login. Expects
// form values: email, password.
func (a *Auth) PlatformLogin(w http.ResponseWriter, r *http.Request) {
	if a.cfg.PlatformAdminStore == nil {
		http.Error(w, "platform admin not enabled", http.StatusNotFound)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	tkey := throttleKey("platform:"+email, clientIP(r))
	if !a.throttleAllow(w, r, tkey) {
		return
	}

	rec, err := a.cfg.PlatformAdminStore.GetPlatformAdmin(r.Context(), email)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		a.platformLoginFail(r, tkey, email)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if !CheckPassword(rec.HashedPassword, password) {
		a.platformLoginFail(r, tkey, email)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Password correct → arm the TOTP step. A console-created admin who has not yet
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
	a.emitAudit(r.Context(), AuditEvent{Type: AuditLogin, Actor: email, IP: clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true, "result": "fail"}})
}

// PlatformVerify2FA is step TWO: it validates the TOTP code for the admin in the
// platform-pending state (password already verified) and, on success, establishes
// the platform session. Mount on: POST /platform/2fa/verify. Expects form: code.
func (a *Auth) PlatformVerify2FA(w http.ResponseWriter, r *http.Request) {
	if a.cfg.PlatformAdminStore == nil {
		http.Error(w, "platform admin not enabled", http.StatusNotFound)
		return
	}
	email, ok := a.readPlatformPending(r)
	if !ok {
		http.Error(w, "no pending platform challenge", http.StatusUnauthorized)
		return
	}
	tkey := throttleKey("platform:"+email, clientIP(r))
	if !a.throttleAllow(w, r, tkey) {
		return
	}

	rec, err := a.cfg.PlatformAdminStore.GetPlatformAdmin(r.Context(), email)
	if err != nil {
		http.Error(w, "invalid challenge", http.StatusUnauthorized)
		return
	}
	if !a.validatePlatform2FA(r.Context(), rec, r) {
		a.platformLoginFail(r, tkey, email)
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	// First successful verification confirms a pending enrollment (idempotent once
	// confirmed), so subsequent logins go straight to verify.
	if err := a.cfg.PlatformAdminStore.ConfirmPlatformTOTP(r.Context(), email); err != nil {
		a.log.Error("authkit: platform totp confirm failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.throttleReset(r.Context(), tkey)
	a.clearPlatformPendingCookie(w)

	if err := a.establishPlatformSession(r.Context(), w, r, rec); err != nil {
		a.log.Error("authkit: platform session error: %v", err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	a.emitAudit(r.Context(), AuditEvent{Type: AuditLogin, Actor: email, IP: clientIP(r), At: nowFn(), Meta: map[string]any{"platform": true, "result": "ok"}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// validatePlatform2FA checks the submitted recovery code or TOTP code against the
// admin's record. A pending (unconfirmed) secret still validates — the first valid
// code is what confirms it (PlatformVerify2FA calls ConfirmPlatformTOTP on success).
func (a *Auth) validatePlatform2FA(ctx context.Context, rec *PlatformAdminRecord, r *http.Request) bool {
	if rc := strings.TrimSpace(r.FormValue("recovery_code")); rc != "" {
		ok, err := a.cfg.PlatformAdminStore.ConsumePlatformRecovery(ctx, rec.Email, hashRecoveryCode(rc))
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
	// Anti-replay (opt-in), same reasoning as the tenant path (validate2FA).
	if g, has := a.cfg.PlatformAdminStore.(PlatformTOTPReplayGuard); has {
		claimed, cerr := g.ClaimPlatformTOTPTimestep(ctx, rec.Email, ts)
		if cerr != nil {
			a.log.Error("authkit: platform totp replay claim: %v", cerr)
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
	if a.cfg.PlatformAdminStore == nil {
		http.Error(w, "platform admin not enabled", http.StatusNotFound)
		return
	}
	email, ok := a.readPlatformPending(r)
	if !ok {
		http.Error(w, "no pending platform challenge", http.StatusUnauthorized)
		return
	}
	rec, err := a.cfg.PlatformAdminStore.GetPlatformAdmin(r.Context(), email)
	if err != nil {
		http.Error(w, "invalid challenge", http.StatusUnauthorized)
		return
	}
	if rec.TOTPConfirmed {
		http.Error(w, "2fa already enrolled", http.StatusConflict)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: a.appName() + " Platform", AccountName: email})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	plain, hashes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := a.cfg.PlatformAdminStore.EnrollPlatformTOTP(r.Context(), email, key.Secret(), hashes); err != nil {
		a.log.Error("authkit: platform totp enroll failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
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

// PlatformMe returns the currently signed-in platform admin (from the platform
// session cookie), or 401 when there is none. It is the platform counterpart to
// Me, letting an SPA confirm the platform session and show who is logged in.
// Mount on: GET /platform/me
func (a *Auth) PlatformMe(w http.ResponseWriter, r *http.Request) {
	if a.cfg.PlatformAdminStore == nil {
		http.Error(w, "platform admin not enabled", http.StatusNotFound)
		return
	}
	p := a.platformAdminFromSession(r.Context(), r)
	if p == nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
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
