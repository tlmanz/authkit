package authkit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

// RefreshToken is one opaque refresh token in a rotation chain. A successful
// refresh marks the presented token used and issues a child (same ChainID,
// ParentID = the used token). Presenting an already-used or revoked token is
// treated as theft and revokes the whole chain.
//
// ID is the raw token at the authkit boundary; the store MUST hash it at rest
// and hash lookups, so the database never holds a usable token.
type RefreshToken struct {
	ID        string
	UserEmail string
	TenantID  string
	ChainID   string
	ParentID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
}

// RefreshTokenStore persists refresh tokens with rotation lineage and reuse
// detection. Implementations hash ID at rest.
type RefreshTokenStore interface {
	// Create stores a new refresh token.
	Create(ctx context.Context, t *RefreshToken) error
	// Get returns the token for the raw value, or nil if not found.
	Get(ctx context.Context, rawToken string) (*RefreshToken, error)
	// Rotate atomically marks rawOld used and stores next (its child). It MUST
	// fail (and change nothing) if rawOld is already used or revoked.
	Rotate(ctx context.Context, rawOld string, next *RefreshToken) error
	// RevokeChain revokes every token sharing chainID (reuse response).
	RevokeChain(ctx context.Context, chainID string) error
	// RevokeAllForUser revokes every refresh token belonging to one user, so a
	// credential change or "log out everywhere" cuts off the mobile axis too, not
	// just cookie sessions. tenantID scopes the revoke; email identifies the user.
	RevokeAllForUser(ctx context.Context, tenantID, email string) error
}

func (a *Auth) refreshTTL() time.Duration {
	if a.cfg.RefreshTokenTTL > 0 {
		return a.cfg.RefreshTokenTTL
	}
	return 30 * 24 * time.Hour
}

// newOpaqueToken returns a 256-bit URL-safe random token.
func newOpaqueToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func newChainID() (string, error) { return newOpaqueToken() }

// issueTokenPair creates a fresh refresh token (new chain) and a matching access
// JWT. ctx must carry the user's tenant.
func (a *Auth) issueTokenPair(ctx context.Context, u *User) (access, refresh string, err error) {
	chain, err := newChainID()
	if err != nil {
		return "", "", err
	}
	refresh, err = newOpaqueToken()
	if err != nil {
		return "", "", err
	}
	now := nowFn()
	rt := &RefreshToken{
		ID:        refresh,
		UserEmail: u.Email,
		TenantID:  u.TenantID,
		ChainID:   chain,
		IssuedAt:  now,
		ExpiresAt: now.Add(a.refreshTTL()),
	}
	if err := a.cfg.RefreshTokenStore.Create(ctx, rt); err != nil {
		return "", "", err
	}
	access, err = a.issueAccessToken(u)
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

// RefreshAccessToken rotates a refresh token: it issues a new access + refresh
// pair and invalidates the presented token. Reuse of a spent/revoked token
// revokes the entire chain. Mount on: POST /token/refresh
// Expects form value: refresh_token.
func (a *Auth) RefreshAccessToken(w http.ResponseWriter, r *http.Request) {
	if !a.tokensEnabled() {
		http.Error(w, "tokens not enabled", http.StatusNotFound)
		return
	}
	raw := r.FormValue("refresh_token")
	if raw == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "missing refresh_token")
		return
	}

	rt, err := a.cfg.RefreshTokenStore.Get(r.Context(), raw)
	if err != nil || rt == nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant", "unknown refresh token")
		return
	}

	// Reuse detection: a token that was already rotated (used) or revoked is
	// presented again ⇒ it was copied ⇒ revoke the whole chain.
	if rt.UsedAt != nil || rt.RevokedAt != nil {
		ctx := WithTenant(r.Context(), rt.TenantID)
		_ = a.cfg.RefreshTokenStore.RevokeChain(ctx, rt.ChainID)
		a.emitAudit(ctx, AuditEvent{Type: AuditRevoke, TenantID: rt.TenantID, Actor: rt.UserEmail, At: nowFn(), Meta: map[string]any{"reason": "refresh_reuse", "chain": rt.ChainID}})
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant", "refresh token reuse detected")
		return
	}
	if nowFn().After(rt.ExpiresAt) {
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant", "refresh token expired")
		return
	}

	ctx := WithTenant(r.Context(), rt.TenantID)

	// Rebuild the user (fresh tenant + role) for the new access token.
	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), rt.UserEmail)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant", "user no longer exists")
		return
	}
	role, _ := a.rbacProvider.RoleFor(ctx, rt.UserEmail)
	u := &User{Email: rt.UserEmail, Name: storedUser.Name, TenantID: storedUser.TenantID, BranchID: storedUser.BranchID, Role: role}

	next, err := newOpaqueToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := nowFn()
	child := &RefreshToken{
		ID:        next,
		UserEmail: u.Email,
		TenantID:  u.TenantID,
		ChainID:   rt.ChainID,
		ParentID:  rt.ID,
		IssuedAt:  now,
		ExpiresAt: now.Add(a.refreshTTL()),
	}
	if err := a.cfg.RefreshTokenStore.Rotate(ctx, raw, child); err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant", "refresh token already used")
		return
	}

	access, err := a.issueAccessToken(u)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeTokenResponse(w, access, next, a.accessTTL())
}

func (a *Auth) tokensEnabled() bool {
	return a.cfg.EnableTokens && a.keyring != nil && a.cfg.RefreshTokenStore != nil
}

func writeTokenResponse(w http.ResponseWriter, access, refresh string, ttl time.Duration) {
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    int(ttl.Seconds()),
	})
}

func writeTokenError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}
