// Package jwt implements the narrow slice of JWS this module needs: ES256
// signing and verification over a compact-serialised token.
//
// It deliberately supports exactly one algorithm. A JWT library that accepts
// many algorithms has to be configured carefully to avoid algorithm
// confusion, where a key published for verification is accepted as an HMAC
// secret. Supporting one algorithm removes that class of bug rather than
// documenting it away.
package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Alg is the only signature algorithm this package implements: ECDSA using
// P-256 and SHA-256.
const Alg = "ES256"

// Typ is the token type this package writes and requires.
const Typ = "JWT"

// coordLen is the fixed byte length of one ES256 signature coordinate. The
// signature is R and S, each left-padded to this length. Fixed-width padding
// matters: a variable-length encoding would make signatures malleable.
const coordLen = 32

// Errors reported by this package.
var (
	ErrMalformed   = errors.New("jwt: token is malformed")
	ErrAlgorithm   = errors.New("jwt: unsupported algorithm")
	ErrSignature   = errors.New("jwt: signature does not verify")
	ErrKeyMismatch = errors.New("jwt: key is not P-256")
)

// Header is the JOSE header this package writes.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

func b64(b []byte) string            { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// Sign serialises payload as a compact JWS signed with key, naming kid in
// the header so a verifier can select the matching public key.
//
// payload is marshalled as JSON. It should be a claim set.
func Sign(key *ecdsa.PrivateKey, kid string, payload any) (string, error) {
	if key == nil || key.Curve != elliptic256() {
		return "", ErrKeyMismatch
	}
	hdr, err := json.Marshal(Header{Alg: Alg, Typ: Typ, Kid: kid})
	if err != nil {
		return "", fmt.Errorf("jwt: marshal header: %w", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("jwt: marshal payload: %w", err)
	}
	signing := b64(hdr) + "." + b64(body)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", fmt.Errorf("jwt: sign: %w", err)
	}
	sig := make([]byte, 2*coordLen)
	r.FillBytes(sig[:coordLen])
	s.FillBytes(sig[coordLen:])
	return signing + "." + b64(sig), nil
}

// Parse splits a compact JWS and returns its header and raw payload. It does
// not verify the signature, and the payload must not be trusted until
// [Verify] has succeeded. Its purpose is to read the kid so a key can be
// selected.
func Parse(token string) (Header, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Header{}, nil, fmt.Errorf("%w: want 3 segments, got %d", ErrMalformed, len(parts))
	}
	rawHdr, err := unb64(parts[0])
	if err != nil {
		return Header{}, nil, fmt.Errorf("%w: header is not base64url", ErrMalformed)
	}
	var h Header
	if err := json.Unmarshal(rawHdr, &h); err != nil {
		return Header{}, nil, fmt.Errorf("%w: header is not JSON", ErrMalformed)
	}
	if h.Alg != Alg {
		return Header{}, nil, fmt.Errorf("%w: %q, want %s", ErrAlgorithm, h.Alg, Alg)
	}
	// An explicit typ is optional in JWS, but when present it must match.
	if h.Typ != "" && !strings.EqualFold(h.Typ, Typ) {
		return Header{}, nil, fmt.Errorf("%w: typ %q", ErrMalformed, h.Typ)
	}
	body, err := unb64(parts[1])
	if err != nil {
		return Header{}, nil, fmt.Errorf("%w: payload is not base64url", ErrMalformed)
	}
	return h, body, nil
}

// Verify checks the signature on a compact JWS against pub and returns the
// raw payload. The algorithm is re-checked here, so Verify is safe to call
// without Parse.
func Verify(pub *ecdsa.PublicKey, token string) ([]byte, error) {
	if pub == nil || pub.Curve != elliptic256() {
		return nil, ErrKeyMismatch
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: want 3 segments, got %d", ErrMalformed, len(parts))
	}
	if _, _, err := Parse(token); err != nil {
		return nil, err
	}
	sig, err := unb64(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64url", ErrMalformed)
	}
	if len(sig) != 2*coordLen {
		return nil, fmt.Errorf("%w: signature is %d bytes, want %d", ErrMalformed, len(sig), 2*coordLen)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:coordLen])
	s := new(big.Int).SetBytes(sig[coordLen:])
	if !ecdsa.Verify(pub, sum[:], r, s) {
		return nil, ErrSignature
	}
	body, err := unb64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url", ErrMalformed)
	}
	return body, nil
}
