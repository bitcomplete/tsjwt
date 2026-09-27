package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/bitcomplete/tsjwt/keys"
)

func xyCoords(pub *ecdsa.PublicKey) (string, string) {
	enc := func(b []byte) string {
		buf := make([]byte, 32)
		copy(buf[32-len(b):], b)
		return base64.RawURLEncoding.EncodeToString(buf)
	}
	return enc(pub.X.Bytes()), enc(pub.Y.Bytes())
}

// A JWK whose kid is not the RFC 7638 thumbprint of its key must be rejected on
// load. Otherwise a publisher (or a hostile/stale JWKS endpoint) could label an
// attacker-chosen key with a kid a token names, and this cache would then use
// that key to "verify" the token.
//
// Regression for the kid==thumbprint-on-load hardening.
func TestJwkToPublicRejectsKidMismatch(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := xyCoords(&key.PublicKey)
	kid, err := keys.Thumbprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	good := keys.JWK{Kty: "EC", Crv: "P-256", Kid: kid, Use: "sig", Alg: "ES256", X: x, Y: y}
	if _, err := jwkToPublic(good); err != nil {
		t.Fatalf("well-formed key (kid == thumbprint) rejected: %v", err)
	}

	forged := keys.JWK{Kty: "EC", Crv: "P-256", Kid: "not-the-thumbprint", Use: "sig", Alg: "ES256", X: x, Y: y}
	if _, err := jwkToPublic(forged); err == nil {
		t.Fatal("a key whose kid is not its thumbprint was accepted")
	}
}
