package authkit

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SigningKey is one Ed25519 key in the rotation ring. The current key (the first
// in Config.SigningKeys) signs new access tokens; all keys verify, so a key can
// be retired without invalidating tokens it already signed.
type SigningKey struct {
	KID     string
	Private ed25519.PrivateKey
}

// NewSigningKey builds a SigningKey from a 32-byte Ed25519 seed.
func NewSigningKey(kid string, seed []byte) (SigningKey, error) {
	if len(seed) != ed25519.SeedSize {
		return SigningKey{}, fmt.Errorf("authkit: signing key seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return SigningKey{KID: kid, Private: ed25519.NewKeyFromSeed(seed)}, nil
}

// keyring holds the active signer plus all public keys for verification/JWKS.
type keyring struct {
	signer SigningKey
	public map[string]ed25519.PublicKey
	order  []string // kid order for stable JWKS output
}

func newKeyring(keys []SigningKey) (*keyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("authkit: EnableTokens requires at least one SigningKey")
	}
	kr := &keyring{signer: keys[0], public: make(map[string]ed25519.PublicKey, len(keys))}
	for _, k := range keys {
		pub, ok := k.Private.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("authkit: signing key %q is not Ed25519", k.KID)
		}
		kr.public[k.KID] = pub
		kr.order = append(kr.order, k.KID)
	}
	return kr, nil
}

// accessClaims are the JWT claims for an access token. Permissions are NOT in
// the token — they are resolved server-side per request (so changes take effect
// within one access-token TTL).
//
// Provider mirrors User.Provider (e.g. "password", "demo") so principal-type
// checks that key off it (like a "demo tenant" guard) see the same value for a
// bearer-token request as they would for a cookie session — see
// verifyAccessToken. Omitted from older tokens minted before this field
// existed; those simply verify with Provider == "", identical to today.
type accessClaims struct {
	Name     string `json:"name,omitempty"`
	Provider string `json:"provider,omitempty"`
	TenantID string `json:"tenant_id"`
	BranchID string `json:"branch_id,omitempty"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func (a *Auth) accessTTL() time.Duration {
	if a.cfg.AccessTokenTTL > 0 {
		return a.cfg.AccessTokenTTL
	}
	return 15 * time.Minute
}

// issueAccessToken signs a short-lived JWT for u with the current key, using
// the configured AccessTokenTTL.
func (a *Auth) issueAccessToken(u *User) (string, error) {
	return a.issueAccessTokenWithTTL(u, a.accessTTL())
}

// issueAccessTokenWithTTL signs a JWT for u with an explicit lifetime instead
// of the configured AccessTokenTTL — see IssueAccessTokenOnly, whose callers
// need a token bound to something shorter-lived than the principal itself
// (e.g. an ephemeral tenant's own remaining lifetime).
func (a *Auth) issueAccessTokenWithTTL(u *User, ttl time.Duration) (string, error) {
	now := nowFn()
	claims := accessClaims{
		Name:     u.Name,
		Provider: u.Provider,
		TenantID: u.TenantID,
		BranchID: u.BranchID,
		Role:     u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.cfg.TokenIssuer,
			Subject:   u.Email,
			Audience:  jwt.ClaimStrings{a.cfg.TokenClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = a.keyring.signer.KID
	return tok.SignedString(a.keyring.signer.Private)
}

// verifyAccessToken validates a JWT against the keyring and returns the bearer's
// identity (without permissions — the caller resolves those). Returns an error
// for expired/invalid tokens.
func (a *Auth) verifyAccessToken(raw string) (*User, error) {
	claims := &accessClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		pub, ok := a.keyring.public[kid]
		if !ok {
			return nil, fmt.Errorf("authkit: unknown kid %q", kid)
		}
		return pub, nil
	},
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(a.cfg.TokenIssuer),
		jwt.WithAudience(a.cfg.TokenClientID),
		jwt.WithTimeFunc(nowFn),
	)
	if err != nil {
		return nil, err
	}
	return &User{
		Email:    claims.Subject,
		Name:     claims.Name,
		Provider: claims.Provider,
		Role:     claims.Role,
		TenantID: claims.TenantID,
		BranchID: claims.BranchID,
	}, nil
}

// tryTokenAuth verifies a bearer JWT (when token auth is enabled) and returns
// the identity. Returns nil when tokens are disabled, no bearer is present, or
// the token is invalid — callers then fall through to other credentials.
func (a *Auth) tryTokenAuth(r *http.Request) *User {
	if !a.cfg.EnableTokens || a.keyring == nil {
		return nil
	}
	raw := extractBearerToken(r)
	if raw == "" {
		return nil
	}
	u, err := a.verifyAccessToken(raw)
	if err != nil {
		return nil
	}
	return u
}

// JWKS serves the public verification keys. Mount on:
// GET /.well-known/jwks.json
func (a *Auth) JWKS(w http.ResponseWriter, _ *http.Request) {
	if a.keyring == nil {
		http.Error(w, "tokens not enabled", http.StatusNotFound)
		return
	}
	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		X   string `json:"x"`
	}
	keys := make([]jwk, 0, len(a.keyring.order))
	for _, kid := range a.keyring.order {
		keys = append(keys, jwk{
			Kty: "OKP", Crv: "Ed25519", Kid: kid, Use: "sig", Alg: "EdDSA",
			X: base64.RawURLEncoding.EncodeToString(a.keyring.public[kid]),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}
