package authkit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// TOTPStore persists a user's TOTP secret and recovery codes. The host
// implementation is responsible for encrypting the secret at rest; authkit
// passes/receives the plaintext secret at this boundary. All methods are called
// with the user's tenant already on the context (TOTP access is tenant-scoped).
type TOTPStore interface {
	// Enroll stores (or replaces) the user's TOTP secret and the hashed recovery
	// codes as PENDING — provisioned but NOT yet confirmed. The user is not
	// considered to have working 2FA until they prove possession of the
	// authenticator with a valid code (see Confirm). This two-phase model is what
	// lets a user who abandons enrollment (got the QR, never added it) be sent
	// back to enroll on the next login instead of being locked at the verify step.
	Enroll(ctx context.Context, tenantID, email, secret string, recoveryCodeHashes []string) error
	// Confirm marks a pending secret confirmed (activated). Called once, on the
	// user's first successful verification. MUST be idempotent: a no-op when the
	// secret is already confirmed or absent.
	Confirm(ctx context.Context, tenantID, email string) error
	// Secret returns the user's TOTP secret (empty when none is stored) and whether
	// it has been CONFIRMED. A non-empty secret with confirmed=false is a pending
	// enrollment: it can be validated (to confirm it) but does not by itself mean
	// the user has set up 2FA.
	Secret(ctx context.Context, tenantID, email string) (secret string, confirmed bool, err error)
	// ConsumeRecovery atomically marks a recovery code used (single-use) and
	// reports whether it matched an unused code.
	ConsumeRecovery(ctx context.Context, tenantID, email, codeHash string) (bool, error)
}

// TOTPManager is an OPTIONAL extension of TOTPStore for self-service 2FA
// management (disable, regenerate recovery codes). authkit type-asserts the
// configured TOTPStore to this — a store that does not implement it simply
// makes those endpoints return 501, leaving the base enroll/verify flow intact.
// Kept separate from TOTPStore so adding management never breaks existing
// implementers (e.g. the platform-admin store, whose 2FA is mandatory).
type TOTPManager interface {
	// Disable removes the user's TOTP secret and all recovery codes (turning 2FA
	// off). Idempotent: a no-op when none is stored.
	Disable(ctx context.Context, tenantID, email string) error
	// ReplaceRecoveryCodes deletes the user's existing recovery codes and stores
	// the given hashed set, without touching the confirmed TOTP secret.
	ReplaceRecoveryCodes(ctx context.Context, tenantID, email string, recoveryCodeHashes []string) error
}

const (
	recoveryCodeCount   = 10
	twofaPendingTTL     = 5 * time.Minute
	totpPendingCookieNm = "authkit_2fa_pending"
)

// requires2FA reports whether the given role must complete a TOTP step.
func (a *Auth) requires2FA(role string) bool {
	return slices.Contains(a.cfg.Require2FAForRoles, role)
}

func (a *Auth) twofaCookieName() string {
	if a.cfg.SecureCookie {
		return "__Host-" + totpPendingCookieNm
	}
	return totpPendingCookieNm
}

type pendingClaims struct {
	Email string `json:"e"`
	Exp   int64  `json:"x"`
}

// issuePendingToken mints a short-lived signed token proving the user passed
// primary auth and is awaiting the 2FA step.
func (a *Auth) issuePendingToken(email string) string {
	c := pendingClaims{Email: email, Exp: nowFn().Add(twofaPendingTTL).Unix()}
	j, _ := json.Marshal(c)
	payload := base64.RawURLEncoding.EncodeToString(j)
	return payload + "." + a.sign(payload)
}

// readPendingToken validates the pending cookie and returns the email it binds.
func (a *Auth) readPendingToken(r *http.Request) (string, bool) {
	c, err := r.Cookie(a.twofaCookieName())
	if err != nil {
		return "", false
	}
	return a.parsePendingToken(c.Value)
}

// parsePendingToken validates a signed pending-2FA token value (the same token
// minted by issuePendingToken) and returns the email it binds. Shared by the
// cookie-based web flow (readPendingToken) and the mobile flow, which carries
// the token in the request body instead of a cookie.
func (a *Auth) parsePendingToken(value string) (string, bool) {
	payload, mac, ok := strings.Cut(value, ".")
	if !ok || subtle.ConstantTimeCompare([]byte(mac), []byte(a.sign(payload))) != 1 {
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

func (a *Auth) setPendingCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.twofaCookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(twofaPendingTTL / time.Second),
	})
}

func (a *Auth) clearPendingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: a.twofaCookieName(), Value: "", Path: "/",
		HttpOnly: true, Secure: a.cfg.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// beginTwoFactor is invoked after a successful primary auth when the user's role
// requires 2FA. It sets the pending cookie and tells the client whether to
// enroll or verify. It does NOT mint a full session.
func (a *Auth) beginTwoFactor(ctx context.Context, w http.ResponseWriter, email string) {
	_, confirmed, err := a.cfg.TOTPStore.Secret(ctx, tenantFromCtxOrEmpty(ctx), email)
	if err != nil {
		a.log.Error("authkit: totp secret lookup failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.setPendingCookie(w, a.issuePendingToken(email))
	// Enroll unless 2FA is fully confirmed: no secret yet, OR a pending one the
	// user provisioned but never verified (so they aren't stranded at verify).
	action := "verify"
	if !confirmed {
		action = "enroll"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "2fa_required", "action": action})
}

// Verify2FA completes a pending login by validating a TOTP code or a recovery
// code, then establishes the session. Mount on: POST /auth/2fa/verify
// Expects form values: code (6-digit TOTP) OR recovery_code.
func (a *Auth) Verify2FA(w http.ResponseWriter, r *http.Request) {
	if a.cfg.TOTPStore == nil {
		http.Error(w, "2fa not enabled", http.StatusNotFound)
		return
	}
	email, ok := a.readPendingToken(r)
	if !ok {
		http.Error(w, "no pending 2fa challenge", http.StatusUnauthorized)
		return
	}

	tkey := throttleKey(email, clientIP(r))
	if !a.throttleAllow(w, r, tkey) {
		return
	}

	// Resolve the tenant for this user so TOTP access is tenant-scoped.
	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "invalid challenge", http.StatusUnauthorized)
		return
	}
	ctx := WithTenant(r.Context(), storedUser.TenantID)

	if !a.validate2FA(ctx, storedUser.TenantID, email, r) {
		a.throttleFailure(ctx, tkey)
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	// The first successful verification confirms a pending enrollment (idempotent
	// for an already-confirmed secret), so future logins go straight to verify.
	if err := a.cfg.TOTPStore.Confirm(ctx, storedUser.TenantID, email); err != nil {
		a.log.Error("authkit: totp confirm failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.throttleReset(ctx, tkey)
	a.clearPendingCookie(w)

	if err := a.establishLoginSession(ctx, w, r, email, storedUser); err != nil {
		a.log.Error("authkit: session error after 2fa: %v", err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	// Honor "remember this device": mint a trusted-device token so future logins
	// from this browser skip the TOTP step (revocable + expiring).
	a.rememberDevice(ctx, w, r, storedUser.TenantID, email)
	// Audit the completed web login for a 2FA (owner/manager, money) role: this is
	// the highest-value login and the mobile 2FA path already audits it (§6.5#9).
	a.emitAudit(ctx, AuditEvent{Type: AuditLogin, TenantID: storedUser.TenantID, Actor: email, Subject: email, IP: clientIP(r), At: nowFn(), Meta: map[string]any{"twofa": true}})
	http.Redirect(w, r, a.cfg.AfterLoginURL, http.StatusSeeOther)
}

// validate2FA checks the submitted TOTP code or recovery code.
func (a *Auth) validate2FA(ctx context.Context, tenantID, email string, r *http.Request) bool {
	if rc := strings.TrimSpace(r.FormValue("recovery_code")); rc != "" {
		ok, err := a.cfg.TOTPStore.ConsumeRecovery(ctx, tenantID, email, hashRecoveryCode(rc))
		return err == nil && ok
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" {
		return false
	}
	// Validate against the stored secret whether or not it is confirmed yet — the
	// first valid code is exactly what confirms a pending enrollment (Verify2FA
	// calls Confirm on success). A confirmed flag here would make confirmation
	// impossible.
	secret, _, err := a.cfg.TOTPStore.Secret(ctx, tenantID, email)
	if err != nil || secret == "" {
		return false
	}
	ts, ok := matchTOTPTimestep(code, secret, nowFn())
	if !ok {
		return false
	}
	// Anti-replay (opt-in): a given time-step is usable at most once, so an
	// intercepted-and-replayed code is rejected. Fail open on a store error so a
	// transient outage doesn't lock a legitimate login out (the throttler + the
	// short window keep the residual risk low).
	if g, has := a.cfg.TOTPStore.(TOTPReplayGuard); has {
		claimed, cerr := g.ClaimTOTPTimestep(ctx, tenantID, email, ts)
		if cerr != nil {
			a.log.Error("authkit: totp replay claim: %v", cerr)
		} else if !claimed {
			return false
		}
	}
	return true
}

// Enroll2FA provisions a new TOTP secret + recovery codes for the user
// currently in the 2FA-pending state (or an authenticated session, for
// voluntary enrollment), and returns the otpauth URL + recovery codes to show
// once. Mount on: POST /auth/2fa/enroll
func (a *Auth) Enroll2FA(w http.ResponseWriter, r *http.Request) {
	if a.cfg.TOTPStore == nil {
		http.Error(w, "2fa not enabled", http.StatusNotFound)
		return
	}

	email, ok := a.readPendingToken(r)
	if !ok {
		// Fall back to an already-authenticated session (voluntary enrollment).
		if u, _ := a.loadSession(r.Context(), r); u != nil {
			email = u.Email
			ok = true
		}
	}
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "invalid user", http.StatusUnauthorized)
		return
	}
	ctx := WithTenant(r.Context(), storedUser.TenantID)

	// Refuse to overwrite an already-confirmed authenticator: a stolen password
	// alone (holding only a 2FA-pending token) must never be able to re-enroll a
	// new secret and thereby bypass 2FA. Resetting an active authenticator goes
	// through DisableTwoFactor first, which requires an authenticated session.
	// Mirrors PlatformEnroll2FA.
	if _, confirmed, err := a.cfg.TOTPStore.Secret(ctx, storedUser.TenantID, email); err == nil && confirmed {
		http.Error(w, "2fa already enrolled", http.StatusConflict)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{Issuer: a.appName(), AccountName: email})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	plain, hashes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := a.cfg.TOTPStore.Enroll(ctx, storedUser.TenantID, email, key.Secret(), hashes); err != nil {
		a.log.Error("authkit: totp enroll failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"otpauthUrl":    key.URL(),
		"secret":        key.Secret(),
		"recoveryCodes": plain,
	})
}

func (a *Auth) appName() string {
	if a.cfg.AppName != "" {
		return a.cfg.AppName
	}
	return "App"
}

// generateRecoveryCodes returns n random recovery codes (shown once) and their
// hashes (stored). Codes are formatted as two base32 groups, e.g. "AB3D-7K9P".
func generateRecoveryCodes(n int) (plain, hashes []string, err error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for range n {
		var b [5]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, nil, err
		}
		s := enc.EncodeToString(b[:]) // 8 chars
		code := s[:4] + "-" + s[4:]
		plain = append(plain, code)
		hashes = append(hashes, hashRecoveryCode(code))
	}
	return plain, hashes, nil
}

// hashRecoveryCode normalizes (uppercase, strip separators) and SHA-256-hashes a
// recovery code for storage/comparison.
func hashRecoveryCode(code string) string {
	norm := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// tenantFromCtxOrEmpty returns the tenant on ctx (or "").
func tenantFromCtxOrEmpty(ctx context.Context) string {
	id, _ := TenantIDFromCtx(ctx)
	return id
}
