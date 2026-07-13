package authkit

import (
	"errors"
	"net/http"
	"time"
)

// IssueAccessTokenOnly mints and writes a single access-token JWT for u — no
// refresh token — with an explicit ttl instead of the configured
// AccessTokenTTL.
//
// For principals that didn't come from UserStore (the only path
// RefreshAccessToken knows how to re-resolve a principal through on rotation):
// minting a refresh token for such a principal would hand out a credential
// that could never actually be redeemed, since RefreshAccessToken
// unconditionally calls UserStore.GetUserByEmail before rotating. Issuing
// access-only instead makes that limitation explicit rather than latent — the
// caller picks ttl accordingly (e.g. bounded by how long the underlying
// principal itself remains valid, for an ephemeral tenant).
//
// u.Provider should be set to whatever distinguishes this principal type
// (e.g. "demo") — it round-trips through the token (accessClaims.Provider) so
// a principal-type guard (a tenant.IsDemo-style check) sees the same value for
// this token as it would for a session carrying the same Provider.
func (a *Auth) IssueAccessTokenOnly(w http.ResponseWriter, u *User, ttl time.Duration) error {
	if !a.tokensEnabled() {
		writeTokenError(w, http.StatusNotFound, "tokens_disabled", "tokens not enabled")
		return errors.New("authkit: tokens not enabled")
	}
	if ttl <= 0 {
		ttl = a.accessTTL()
	}
	access, err := a.issueAccessTokenWithTTL(u, ttl)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(ttl.Seconds()),
	})
	return nil
}
