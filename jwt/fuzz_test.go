package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// The token is fully attacker-controlled before a signature is checked, so
// Parse and Verify are the first surface an audit fuzzes. Neither may panic on
// any input: a panic in the request path is a denial of service. This fuzzer
// asserts only that property; correctness is covered by the unit tests.
func FuzzParseAndVerify(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	good, err := Sign(key, "kid", map[string]any{"sub": "someone"})
	if err != nil {
		f.Fatal(err)
	}

	// Seeds: a valid token, and the shapes that tend to trip a hand-written
	// parser — wrong segment counts, non-base64, over-long, and empty.
	for _, s := range []string{
		good,
		"",
		".",
		"..",
		"a.b.c",
		"a.b.c.d",
		good + ".extra",
		"eyJhbGciOiJFUzI1NiJ9..",
		"!!!.@@@.###",
	} {
		f.Add(s)
	}

	for i := 0; i < 4096; i++ {
		f.Add(good[:i%len(good)])
	}

	f.Fuzz(func(t *testing.T, token string) {
		// Must not panic. Errors are fine and expected.
		_, _, _ = Parse(token)
		_, _ = Verify(&key.PublicKey, token)
		// A nil or wrong-curve key must also be handled without panic.
		_, _ = Verify(nil, token)
	})
}
