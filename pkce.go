package authkit

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// PKCE Authorization Code flow for a public native client. The authorization
// code is a short-lived signed token bound to the PKCE challenge, the redirect
// URI, and the authenticated user — so only the app holding the matching
// verifier can redeem it. Login happens via the normal session before reaching
// Authorize (the system browser carries the cookie).

const authCodeTTL = 60 * time.Second

// AuthCodeStore, when configured, makes PKCE authorization codes single-use.
// ClaimAuthCode atomically records jti as redeemed and returns ok=false if it was
// already redeemed (a replay). expiresAt lets the store self-expire the record
// (the code is only valid for authCodeTTL). A short-TTL store (Redis) fits best.
type AuthCodeStore interface {
	ClaimAuthCode(ctx context.Context, jti string, expiresAt time.Time) (ok bool, err error)
}

type authCodeClaims struct {
	Email     string `json:"e"`
	Challenge string `json:"c"`
	Redirect  string `json:"r"`
	Exp       int64  `json:"x"`
	JTI       string `json:"j"`
}

func (a *Auth) issueAuthCode(email, challenge, redirect string) string {
	// jti gives each code a unique id so AuthCodeStore can enforce single-use.
	jti, _ := newOpaqueToken()
	c := authCodeClaims{Email: email, Challenge: challenge, Redirect: redirect, Exp: nowFn().Add(authCodeTTL).Unix(), JTI: jti}
	j, _ := json.Marshal(c)
	payload := base64.RawURLEncoding.EncodeToString(j)
	return payload + "." + a.sign(payload)
}

func (a *Auth) verifyAuthCode(code string) (*authCodeClaims, bool) {
	payload, mac, ok := strings.Cut(code, ".")
	if !ok || subtle.ConstantTimeCompare([]byte(mac), []byte(a.sign(payload))) != 1 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, false
	}
	var c authCodeClaims
	if err := json.Unmarshal(raw, &c); err != nil || c.Email == "" {
		return nil, false
	}
	if nowFn().Unix() > c.Exp {
		return nil, false
	}
	return &c, true
}

// Authorize is the PKCE authorization endpoint. It requires an authenticated
// session, validates the client + redirect + challenge, mints an auth code, and
// redirects back to the app. Mount on: GET /authorize
func (a *Auth) Authorize(w http.ResponseWriter, r *http.Request) {
	if !a.tokensEnabled() {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "tokens not enabled")
		return
	}
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "unsupported response_type")
		return
	}
	if q.Get("client_id") != a.cfg.Tokens.ClientID {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid client_id")
		return
	}
	redirect := q.Get("redirect_uri")
	if !slices.Contains(a.cfg.Tokens.RedirectURIs, redirect) {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid redirect_uri")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid code_challenge")
		return
	}

	// The resource owner must already be authenticated (logged in via the web
	// session in the system browser).
	u, _ := a.loadSession(r.Context(), r)
	if u == nil {
		// Bounce to the login page, preserving the authorize request.
		login := a.cfg.AfterLogoutURL
		if login == "" {
			login = "/"
		}
		http.Redirect(w, r, login+"?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}

	code := a.issueAuthCode(u.Email, challenge, redirect)
	dest, err := url.Parse(redirect)
	if err != nil {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid redirect_uri")
		return
	}
	rq := dest.Query()
	rq.Set("code", code)
	if state := q.Get("state"); state != "" {
		rq.Set("state", state)
	}
	dest.RawQuery = rq.Encode()
	http.Redirect(w, r, dest.String(), http.StatusSeeOther)
}

// IssueToken exchanges an authorization code (+ PKCE verifier) for an access +
// refresh token pair. Mount on: POST /token
// Fields: grant_type=authorization_code, code, code_verifier, redirect_uri.
func (a *Auth) IssueToken(w http.ResponseWriter, r *http.Request) {
	if !a.tokensEnabled() {
		a.writeError(w, r, http.StatusNotFound, ErrCodeNotEnabled, "tokens not enabled")
		return
	}
	parseBody(r)
	if r.FormValue("grant_type") != "authorization_code" {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeUnsupportedGrant, "expected authorization_code")
		return
	}

	claims, ok := a.verifyAuthCode(r.FormValue("code"))
	if !ok {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidGrant, "invalid or expired code")
		return
	}
	if r.FormValue("redirect_uri") != claims.Redirect {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidGrant, "redirect_uri mismatch")
		return
	}
	if !verifyPKCE(r.FormValue("code_verifier"), claims.Challenge) {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidGrant, "PKCE verification failed")
		return
	}
	// Single-use (opt-in): claim the code's jti so it cannot be redeemed twice
	// within its TTL. A failed claim (already redeemed) is treated as an invalid
	// grant. Fail closed on a store error: a redemption we can't prove is unique
	// is refused rather than risk issuing two token chains from one code.
	if a.cfg.Tokens.AuthCodes != nil {
		fresh, cerr := a.cfg.Tokens.AuthCodes.ClaimAuthCode(r.Context(), claims.JTI, time.Unix(claims.Exp, 0))
		if cerr != nil {
			a.log.Error("auth code claim failed", "err", cerr)
			a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidGrant, "code could not be validated")
			return
		}
		if !fresh {
			a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidGrant, "authorization code already used")
			return
		}
	}

	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), claims.Email)
	if err != nil {
		a.writeError(w, r, http.StatusBadRequest, ErrCodeInvalidGrant, "user no longer exists")
		return
	}
	ctx := WithTenant(r.Context(), storedUser.TenantID)
	role, _ := a.rbacProvider.RoleFor(ctx, claims.Email)
	u := &User{Email: claims.Email, Name: storedUser.Name, TenantID: storedUser.TenantID, Attrs: cloneAttrs(storedUser.Attrs), Role: role}

	access, refresh, err := a.issueTokenPair(ctx, u)
	if err != nil {
		a.log.Error("token pair issue failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, ErrCodeServerError, "internal error")
		return
	}
	writeTokenResponse(w, access, refresh, a.accessTTL())
}

// verifyPKCE checks that base64url(SHA256(verifier)) == challenge (S256).
func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}
