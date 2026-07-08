package authkit

import (
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

// PKCE Authorization Code flow for the public mobile client. The authorization
// code is a short-lived signed token bound to the PKCE challenge, the redirect
// URI, and the authenticated user — so only the app holding the matching
// verifier can redeem it. Login happens via the normal session before reaching
// Authorize (the system browser carries the cookie).

const authCodeTTL = 60 * time.Second

type authCodeClaims struct {
	Email     string `json:"e"`
	Challenge string `json:"c"`
	Redirect  string `json:"r"`
	Exp       int64  `json:"x"`
}

func (a *Auth) issueAuthCode(email, challenge, redirect string) string {
	c := authCodeClaims{Email: email, Challenge: challenge, Redirect: redirect, Exp: nowFn().Add(authCodeTTL).Unix()}
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
		http.Error(w, "tokens not enabled", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		http.Error(w, "unsupported_response_type", http.StatusBadRequest)
		return
	}
	if q.Get("client_id") != a.cfg.TokenClientID {
		http.Error(w, "invalid_client", http.StatusBadRequest)
		return
	}
	redirect := q.Get("redirect_uri")
	if !slices.Contains(a.cfg.TokenRedirectURIs, redirect) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "invalid code_challenge", http.StatusBadRequest)
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
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
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
// Expects form values: grant_type=authorization_code, code, code_verifier,
// redirect_uri.
func (a *Auth) IssueToken(w http.ResponseWriter, r *http.Request) {
	if !a.tokensEnabled() {
		http.Error(w, "tokens not enabled", http.StatusNotFound)
		return
	}
	if r.FormValue("grant_type") != "authorization_code" {
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "expected authorization_code")
		return
	}

	claims, ok := a.verifyAuthCode(r.FormValue("code"))
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired code")
		return
	}
	if r.FormValue("redirect_uri") != claims.Redirect {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if !verifyPKCE(r.FormValue("code_verifier"), claims.Challenge) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	storedUser, err := a.cfg.UserStore.GetUserByEmail(r.Context(), claims.Email)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "user no longer exists")
		return
	}
	ctx := WithTenant(r.Context(), storedUser.TenantID)
	role, _ := a.rbacProvider.RoleFor(ctx, claims.Email)
	u := &User{Email: claims.Email, Name: storedUser.Name, TenantID: storedUser.TenantID, BranchID: storedUser.BranchID, Role: role}

	access, refresh, err := a.issueTokenPair(ctx, u)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
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
