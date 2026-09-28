package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pad32 mirrors the on-wire coordinate encoding (left-padded to the P-256 size).
func pad32(n *big.Int) []byte {
	b := make([]byte, 32)
	n.FillBytes(b)
	return b
}

func TestPublicFromXY_roundTripsAValidKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PublicFromXY(b64(pad32(priv.X)), b64(pad32(priv.Y)))
	if err != nil {
		t.Fatalf("a valid P-256 point must parse: %v", err)
	}
	if got.X.Cmp(priv.X) != 0 || got.Y.Cmp(priv.Y) != 0 {
		t.Fatal("round-tripped key does not match the original coordinates")
	}
}

func TestPublicFromXY_toleratesMinimalCoordinateEncoding(t *testing.T) {
	// big.Int.Bytes() returns the minimal big-endian form (leading zeros
	// stripped), which a lenient producer may emit. Left-padding must accept it
	// whatever its length.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublicFromXY(b64(priv.X.Bytes()), b64(priv.Y.Bytes())); err != nil {
		t.Fatalf("the minimal (stripped) coordinate encoding of a valid point must parse: %v", err)
	}
}

func TestPublicFromXY_rejectsOffCurvePoint(t *testing.T) {
	// A valid X with Y := Y+1 is (almost surely) not on the curve.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badY := new(big.Int).Add(priv.Y, big.NewInt(1))
	if _, err := PublicFromXY(b64(pad32(priv.X)), b64(pad32(badY))); err == nil {
		t.Fatal("an off-curve point must be rejected")
	}
}

func TestPublicFromXY_rejectsPointAtInfinity(t *testing.T) {
	zero := b64(make([]byte, 32))
	if _, err := PublicFromXY(zero, zero); err == nil {
		t.Fatal("the point at infinity (0,0) must be rejected")
	}
}

func TestPublicFromXY_rejectsOverlongCoordinate(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	overlong := b64(append([]byte{0}, pad32(priv.X)...)) // 33 bytes
	if _, err := PublicFromXY(overlong, b64(pad32(priv.Y))); err == nil {
		t.Fatal("an over-long (>32 byte) coordinate must be rejected")
	}
}

func TestPublicFromXY_rejectsNonBase64(t *testing.T) {
	if _, err := PublicFromXY("!!!", "!!!"); err == nil || !strings.Contains(err.Error(), "base64url") {
		t.Fatalf("non-base64url coordinate must be rejected as such, got: %v", err)
	}
}
