// Package signer mints short-lived identity assertions.
//
// A signer sits at the trust boundary. It is the only component that turns a
// network-verified identity into a bearer token, so it is the only component
// that has to be trusted not to lie about who a caller is.
package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/jwt"
	"github.com/bitcomplete/tsjwt/keys"
)

// MaxTTL is the longest token lifetime this package will mint. A short
// lifetime is the only revocation this design has, so the ceiling is
// enforced rather than advised.
const MaxTTL = 15 * time.Minute

// DefaultTTL is the lifetime used when none is configured.
const DefaultTTL = 5 * time.Minute

// Config configures a [Signer].
type Config struct {
	// Issuer is the "iss" claim. It should be the signer's own stable
	// URL. Required.
	Issuer string

	// Keys is the key source to sign with. Required.
	//
	// Both *keys.Set and *keys.Published satisfy this. The difference is
	// what JWKS returns: one replica's keys, or every live replica's. The
	// signer does not care, because signing only ever uses the local
	// private key.
	Keys KeySource

	// Identities establishes who a caller is. Required.
	Identities tsjwt.IdentitySource

	// Tenants maps an identity to its authorized tenants. Required.
	Tenants tsjwt.TenantResolver

	// TTL is the token lifetime. It is clamped to MaxTTL. Zero means
	// DefaultTTL.
	TTL time.Duration

	// Leeway is how far before now the "nbf" claim is set, to tolerate
	// clock skew between the signer and a backend. Default 30s.
	Leeway time.Duration

	// Now replaces the time source. For tests.
	Now func() time.Time
}

// KeySource provides the key to sign with and the set to publish.
type KeySource interface {
	// Current returns the private key to sign with, and its id.
	Current() (*ecdsa.PrivateKey, string, error)
	// JWKS returns the verification keys to publish.
	JWKS() keys.JWKS
}

// Signer mints assertions.
type Signer struct {
	cfg Config
}

// New validates cfg and returns a signer.
func New(cfg Config) (*Signer, error) {
	switch {
	case strings.TrimSpace(cfg.Issuer) == "":
		return nil, fmt.Errorf("signer: Issuer is required")
	case cfg.Keys == nil:
		return nil, fmt.Errorf("signer: Keys is required")
	case cfg.Identities == nil:
		return nil, fmt.Errorf("signer: Identities is required")
	case cfg.Tenants == nil:
		return nil, fmt.Errorf("signer: Tenants is required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.TTL > MaxTTL {
		cfg.TTL = MaxTTL
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Signer{cfg: cfg}, nil
}

// TTL reports the lifetime this signer mints with, after clamping.
func (s *Signer) TTL() time.Duration { return s.cfg.TTL }

// Mint issues a token for the identity behind remoteAddr, scoped to
// audience, acting for tenant.
//
// An empty tenant selects the grant's default tenant. A tenant the identity
// does not hold is refused with [tsjwt.ErrNoTenant]; that check is the whole
// of tenant isolation, so it fails closed.
func (s *Signer) Mint(remoteAddr, audience, tenant string) (string, tsjwt.Claims, error) {
	var zero tsjwt.Claims
	if strings.TrimSpace(audience) == "" {
		return "", zero, fmt.Errorf("signer: audience is required")
	}
	id, err := s.cfg.Identities.Identify(remoteAddr)
	if err != nil {
		return "", zero, err
	}
	if err := id.Valid(); err != nil {
		return "", zero, err
	}
	grant, err := s.cfg.Tenants.Resolve(id)
	if err != nil {
		return "", zero, err
	}
	if err := grant.Valid(); err != nil {
		return "", zero, err
	}
	if len(grant.Tenants) == 0 {
		return "", zero, fmt.Errorf("%w: %s is authorized for no tenant", tsjwt.ErrNoTenant, id.Subject)
	}
	if tenant == "" {
		tenant = grant.Default
		if tenant == "" {
			return "", zero, fmt.Errorf("%w: no tenant requested and no default", tsjwt.ErrNoTenant)
		}
	}
	t, ok := grant.Tenant(tenant)
	if !ok {
		// Do not echo the requested tenant back to the caller in a
		// user-facing error; it confirms existence. The full detail
		// stays in the error for the server log.
		return "", zero, fmt.Errorf("%w: %s may not act for %q", tsjwt.ErrNoTenant, id.Subject, tenant)
	}

	now := s.cfg.Now()
	jti, err := newID()
	if err != nil {
		return "", zero, err
	}
	claims := tsjwt.Claims{
		Issuer:    s.cfg.Issuer,
		Subject:   id.Subject,
		Audience:  audience,
		IssuedAt:  now.Unix(),
		NotBefore: now.Add(-s.cfg.Leeway).Unix(),
		Expiry:    now.Add(s.cfg.TTL).Unix(),
		ID:        jti,
		Name:      id.DisplayName,
		Node:      id.Node,
		Tenant:    t.ID,
		Tenants:   grant.IDs(),
		Roles:     t.Roles,
		Groups:    id.Groups,
	}
	if strings.Contains(id.Login, "@") {
		claims.Email = id.Login
	}
	tok, err := signClaims(s.cfg.Keys, claims)
	if err != nil {
		return "", zero, err
	}
	return tok, claims, nil
}

// signClaims signs with the source's current key.
func signClaims(set KeySource, c tsjwt.Claims) (string, error) {
	priv, kid, err := set.Current()
	if err != nil {
		return "", err
	}
	return jwt.Sign(priv, kid, c)
}

// newID returns a unique, unguessable token id for replay detection.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("signer: token id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// JWKSHandler serves the signer's public keys at /.well-known/jwks.json.
//
// The response is cacheable, but for less than the key overlap window, or a
// verifier can still hold a stale set when a key is retired.
func JWKSHandler(set KeySource, cacheFor time.Duration) http.Handler {
	if cacheFor <= 0 {
		cacheFor = 5 * time.Minute
	}
	secs := int(cacheFor.Seconds())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", secs))
		_ = json.NewEncoder(w).Encode(set.JWKS())
	})
}
