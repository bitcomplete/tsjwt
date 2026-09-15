// Package keys manages the signing key set: generation, rotation with an
// overlap window, and publication as a JWKS.
//
// Rotation is the reason this package exists. A signer holds exactly one
// current private key and mints with it. A verifier must accept tokens
// signed by the previous key until every one of them has expired. The
// overlap window is what makes a rotation invisible to callers.
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrNoCurrent means the set holds no key to sign with.
var ErrNoCurrent = errors.New("keys: no current signing key")

// JWK is a public key in JSON Web Key form. Only the fields needed for an
// EC P-256 verification key are present.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKS is a JSON Web Key Set, the document published at
// /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// key is one generation of signing key.
type key struct {
	kid     string
	priv    *ecdsa.PrivateKey
	retires time.Time // zero while current
}

// Set is a rotating set of signing keys. It is safe for concurrent use.
//
// At any moment the set holds one current key, used for signing, and zero or
// more retired keys still inside their overlap window, used only for
// verification. Keys past the window are dropped and their tokens stop
// verifying.
type Set struct {
	// Overlap is how long a retired key stays valid for verification. It
	// must exceed the maximum token lifetime, or a token minted just
	// before a rotation will fail before it expires.
	overlap time.Duration
	now     func() time.Time

	mu      sync.RWMutex
	current *key
	retired []*key
}

// Option configures a [Set].
type Option func(*Set)

// WithOverlap sets how long a retired key remains valid for verification.
// It must be longer than the longest token lifetime. The default is one
// hour.
func WithOverlap(d time.Duration) Option {
	return func(s *Set) { s.overlap = d }
}

// WithClock replaces the time source. It exists for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Set) { s.now = now }
}

// NewSet returns a set holding one freshly generated key.
func NewSet(opts ...Option) (*Set, error) {
	s := &Set{overlap: time.Hour, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	if err := s.Rotate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Rotate generates a new key, makes it current, and moves the previous
// current key into the overlap window. Keys whose window has passed are
// dropped.
func (s *Set) Rotate() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("keys: generate: %w", err)
	}
	kid, err := thumbprint(&priv.PublicKey)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.current != nil {
		s.current.retires = now.Add(s.overlap)
		s.retired = append(s.retired, s.current)
	}
	s.current = &key{kid: kid, priv: priv}
	s.pruneLocked(now)
	return nil
}

// pruneLocked drops retired keys whose overlap window has passed.
func (s *Set) pruneLocked(now time.Time) {
	live := s.retired[:0]
	for _, k := range s.retired {
		if k.retires.After(now) {
			live = append(live, k)
		}
	}
	for i := len(live); i < len(s.retired); i++ {
		s.retired[i] = nil
	}
	s.retired = live
}

// Current returns the key to sign with, and its id.
func (s *Set) Current() (*ecdsa.PrivateKey, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil, "", ErrNoCurrent
	}
	return s.current.priv, s.current.kid, nil
}

// PublicKey returns the verification key for kid, if the set still holds it.
func (s *Set) PublicKey(kid string) (*ecdsa.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	if s.current != nil && s.current.kid == kid {
		return &s.current.priv.PublicKey, true
	}
	for _, k := range s.retired {
		if k.kid == kid && k.retires.After(now) {
			return &k.priv.PublicKey, true
		}
	}
	return nil, false
}

// JWKS returns the public key set: the current key plus every retired key
// still inside its overlap window.
//
// Exactly one key type and one algorithm ever appear. A verifier that
// selects keys from this set cannot be steered onto a different algorithm.
func (s *Set) JWKS() JWKS {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	out := JWKS{Keys: make([]JWK, 0, 1+len(s.retired))}
	if s.current != nil {
		out.Keys = append(out.Keys, jwkOf(&s.current.priv.PublicKey, s.current.kid))
	}
	for _, k := range s.retired {
		if k.retires.After(now) {
			out.Keys = append(out.Keys, jwkOf(&k.priv.PublicKey, k.kid))
		}
	}
	return out
}

// jwkOf renders a public key as a JWK.
func jwkOf(pub *ecdsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "EC",
		Crv: "P-256",
		Kid: kid,
		Use: "sig",
		Alg: "ES256",
		X:   coord(pub.X.Bytes()),
		Y:   coord(pub.Y.Bytes()),
	}
}

// coord left-pads a coordinate to the 32 bytes P-256 requires and encodes it.
func coord(b []byte) string {
	buf := make([]byte, 32)
	copy(buf[32-len(b):], b)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// thumbprint derives a key id from the key itself, as RFC 7638 describes.
// Deriving rather than assigning means a key id can never be reused for a
// different key.
func thumbprint(pub *ecdsa.PublicKey) (string, error) {
	// RFC 7638 requires exactly these members, in lexicographic order,
	// with no whitespace.
	canonical := struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{"P-256", "EC", coord(pub.X.Bytes()), coord(pub.Y.Bytes())}
	b, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("keys: thumbprint: %w", err)
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
