package authkit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// CSRF protects cookie-authenticated, state-changing requests using the signed
// double-submit pattern: a token is delivered in a JS-readable cookie and must
// be echoed back in the X-CSRF-Token header. The server verifies (a) the header
// matches the cookie and (b) the token carries a valid HMAC, so an attacker who
// can neither read the cookie (same-origin policy) nor mint a signed token
// (no secret) cannot forge a request — even from a subdomain that can set cookies.
//
// Token-authenticated requests (Authorization: Bearer / X-API-Key) carry no
// ambient cookie credential and are therefore not CSRF-prone; they are skipped.

const (
	csrfHeader = "X-CSRF-Token"
)

func (a *Auth) csrfCookieName() string {
	if a.cfg.SecureCookie {
		return "__Host-csrf_token"
	}
	return "csrf_token"
}

// issueCSRFToken returns a fresh token of the form base64(rand).base64(hmac).
func (a *Auth) issueCSRFToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	msg := base64.RawURLEncoding.EncodeToString(raw[:])
	return msg + "." + a.sign(msg), nil
}

// sign returns the URL-safe base64 HMAC-SHA256 of msg under SessionSecret. Used
// for CSRF tokens and the short-lived 2FA-pending token.
func (a *Auth) sign(msg string) string {
	m := hmac.New(sha256.New, []byte(a.cfg.SessionSecret))
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// verifyCSRFToken reports whether tok is well-formed and correctly signed.
func (a *Auth) verifyCSRFToken(tok string) bool {
	msg, mac, ok := strings.Cut(tok, ".")
	if !ok || msg == "" || mac == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(mac), []byte(a.sign(msg))) == 1
}

func (a *Auth) setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.csrfCookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: false, // the SPA must read it to echo in the header
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) readCSRFCookie(r *http.Request) string {
	c, err := r.Cookie(a.csrfCookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// CSRF is middleware enforcing the double-submit check on unsafe methods. On
// safe methods it ensures a valid token cookie is present (bootstrapping the
// SPA). It is a pass-through when EnableCSRF is false or the request is
// token-authenticated.
func (a *Auth) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.cfg.EnableCSRF || extractBearerToken(r) != "" {
			next.ServeHTTP(w, r)
			return
		}

		cookieTok := a.readCSRFCookie(r)
		if cookieTok == "" || !a.verifyCSRFToken(cookieTok) {
			if t, err := a.issueCSRFToken(); err == nil {
				a.setCSRFCookie(w, t)
				cookieTok = t
			}
		}

		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}

		hdr := r.Header.Get(csrfHeader)
		if hdr == "" || cookieTok == "" ||
			subtle.ConstantTimeCompare([]byte(hdr), []byte(cookieTok)) != 1 ||
			!a.verifyCSRFToken(hdr) {
			http.Error(w, "csrf token invalid", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CSRFToken issues (or returns the existing) CSRF token and writes it as JSON,
// for SPAs that fetch it explicitly. Mount on: GET /auth/csrf
func (a *Auth) CSRFToken(w http.ResponseWriter, r *http.Request) {
	tok := a.readCSRFCookie(r)
	if tok == "" || !a.verifyCSRFToken(tok) {
		var err error
		tok, err = a.issueCSRFToken()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		a.setCSRFCookie(w, tok)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"csrfToken": tok})
}
