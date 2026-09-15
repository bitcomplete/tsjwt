package keys

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestNewSetGivesCurrentKeyAndOneKeyJWKS(t *testing.T) {
	set, err := NewSet()
	if err != nil {
		t.Fatalf("NewSet failed: %v", err)
	}

	_, kid, err := set.Current()
	if err != nil {
		t.Fatalf("Current failed: %v", err)
	}

	if kid == "" {
		t.Error("kid is empty")
	}

	jwks := set.JWKS()
	if len(jwks.Keys) != 1 {
		t.Errorf("expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != kid {
		t.Errorf("JWKS kid %q does not match Current kid %q", jwks.Keys[0].Kid, kid)
	}
}

func TestRotateChangesCurrentKid(t *testing.T) {
	set, _ := NewSet()
	_, kid1, _ := set.Current()

	err := set.Rotate()
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	_, kidAfterRotate, _ := set.Current()
	if kid1 == kidAfterRotate {
		t.Error("kid did not change after rotation")
	}
}

func TestRotateOldKeyVerifiesDuringOverlapWindow(t *testing.T) {
	now := time.Now()
	set, _ := NewSet(WithClock(func() time.Time { return now }), WithOverlap(1*time.Hour))

	// Get the initial key
	priv1, kid1, _ := set.Current()

	// Manually verify the key is in the set
	pub1, ok := set.PublicKey(kid1)
	if !ok {
		t.Error("Current key not found in set after NewSet")
	}
	if pub1 == nil {
		t.Error("PublicKey returned nil for current kid")
	}

	// Verify it matches the private key
	if pub1.X.Cmp(priv1.PublicKey.X) != 0 || pub1.Y.Cmp(priv1.PublicKey.Y) != 0 {
		t.Error("public key from PublicKey does not match current private key's public key")
	}

	// Rotate the key
	set.Rotate()

	// Old key should still verify during overlap window
	pub1Again, ok := set.PublicKey(kid1)
	if !ok {
		t.Error("old kid not found immediately after rotation (still in overlap)")
	}
	if pub1Again == nil {
		t.Error("PublicKey returned nil for old kid during overlap")
	}

	// Clean test: create a fresh scenario
	testSet, _ := NewSet(WithClock(func() time.Time { return now }), WithOverlap(30*time.Minute))
	_, oldKid, _ := testSet.Current()

	testSet.Rotate()

	// Still in window
	_, stillExists := testSet.PublicKey(oldKid)
	if !stillExists {
		t.Error("old key should still exist in overlap window")
	}
}

func TestRotateOldKeyDoesNotVerifyAfterOverlap(t *testing.T) {
	now := time.Now()
	set, _ := NewSet(WithClock(func() time.Time { return now }), WithOverlap(30*time.Second))

	_, oldKid, _ := set.Current()

	// Rotate to make a new current key
	set.Rotate()

	// Verify old key exists immediately after rotation
	_, existsNow := set.PublicKey(oldKid)
	if !existsNow {
		t.Fatal("old key should exist immediately after rotation")
	}

	// Advance time past overlap window
	laterTime := now.Add(1 * time.Minute)

	// Create new set with later time to test cleanup
	set, _ = NewSet(WithClock(func() time.Time { return laterTime }), WithOverlap(30*time.Second))
	set.Rotate() // Make old key
	set.Rotate() // Make new key

	// Now manually verify that PublicKey looks at retirement times correctly
	// We need to rotate a second time to have something in retired that's past the window
	set.Rotate() // Current moves to retired, a new one becomes current

	// Go back and create a clear test case
	now = time.Now()
	set, _ = NewSet(WithClock(func() time.Time { return now }), WithOverlap(1*time.Second))
	_, kid1, _ := set.Current()
	set.Rotate()

	// Should exist during overlap
	pub, exists := set.PublicKey(kid1)
	if !exists || pub == nil {
		t.Fatal("old key should exist in overlap window")
	}

	// Move time past overlap
	set.Rotate() // Trigger a clock check with new time
	// But we need to use a new set with the later time
	laterSet := &Set{overlap: 1 * time.Second, now: func() time.Time { return now.Add(2 * time.Second) }}
	laterSet.current = set.current
	laterSet.retired = set.retired

	pub, exists = laterSet.PublicKey(kid1)
	if exists {
		t.Error("old key should not exist after overlap window expired")
	}
}

func TestJWKSContainsOnlyExpectedFields(t *testing.T) {
	set, _ := NewSet()
	jwks := set.JWKS()

	if len(jwks.Keys) == 0 {
		t.Fatal("JWKS has no keys")
	}

	for i, key := range jwks.Keys {
		if key.Kty != "EC" {
			t.Errorf("key[%d] kty=%q, want EC", i, key.Kty)
		}
		if key.Crv != "P-256" {
			t.Errorf("key[%d] crv=%q, want P-256", i, key.Crv)
		}
		if key.Alg != "ES256" {
			t.Errorf("key[%d] alg=%q, want ES256", i, key.Alg)
		}
		if key.Kid == "" {
			t.Errorf("key[%d] kid is empty", i)
		}
		if key.Use != "sig" {
			t.Errorf("key[%d] use=%q, want sig", i, key.Use)
		}
	}
}

func TestKidIsStableThumbprint(t *testing.T) {
	set1, _ := NewSet()
	_, kid1First, _ := set1.Current()

	set2, _ := NewSet()
	_, kid2First, _ := set2.Current()

	// The kids should be different because keys are generated randomly
	if kid1First == kid2First {
		t.Error("different keys should have different kids")
	}

	// Test that the same key generates the same kid
	// We'll verify this by checking that generating a key and getting its thumbprint
	// is deterministic
	set3, _ := NewSet()
	priv3, kid3First, _ := set3.Current()

	// Manually compute thumbprint of priv3's public key
	canonical := struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{
		Crv: "P-256",
		Kty: "EC",
		X:   coordHelper(priv3.PublicKey.X.Bytes()),
		Y:   coordHelper(priv3.PublicKey.Y.Bytes()),
	}
	b, _ := json.Marshal(canonical)

	// Compute SHA256 and base64url encode
	sum := sha256.Sum256(b)
	expectedKid := base64.RawURLEncoding.EncodeToString(sum[:])

	if kid3First != expectedKid {
		t.Errorf("computed kid %q does not match expected %q", kid3First, expectedKid)
	}
}

func TestKidDiffersForDifferentKeys(t *testing.T) {
	set1, _ := NewSet()
	_, kid1, _ := set1.Current()

	set2, _ := NewSet()
	_, kid2, _ := set2.Current()

	if kid1 == kid2 {
		t.Error("different keys should generate different kids")
	}
}

func TestJWKSWithOverlapWindow(t *testing.T) {
	now := time.Now()
	set, _ := NewSet(WithClock(func() time.Time { return now }), WithOverlap(1*time.Hour))

	// Initially 1 key
	jwks := set.JWKS()
	if len(jwks.Keys) != 1 {
		t.Errorf("initial JWKS should have 1 key, got %d", len(jwks.Keys))
	}

	// Rotate to add a retired key
	set.Rotate()
	jwks = set.JWKS()
	if len(jwks.Keys) != 2 {
		t.Errorf("after 1 rotation, JWKS should have 2 keys, got %d", len(jwks.Keys))
	}

	// Rotate again
	set.Rotate()
	jwks = set.JWKS()
	if len(jwks.Keys) != 3 {
		t.Errorf("after 2 rotations, JWKS should have 3 keys, got %d", len(jwks.Keys))
	}

	// Advance time past overlap
	laterSet := &Set{
		overlap: 1 * time.Hour,
		now:     func() time.Time { return now.Add(2 * time.Hour) },
		current: set.current,
		retired: set.retired,
	}
	jwks = laterSet.JWKS()
	if len(jwks.Keys) != 1 {
		t.Errorf("after time advances past overlap, JWKS should have 1 key, got %d", len(jwks.Keys))
	}
}

// Helper to compute coordinate padding like the real code does
func coordHelper(b []byte) string {
	buf := make([]byte, 32)
	copy(buf[32-len(b):], b)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func TestCurrentReturnsErrorWhenNoKey(t *testing.T) {
	set := &Set{overlap: 1 * time.Hour, now: time.Now}
	// Don't call NewSet or Rotate, so current is nil

	_, _, err := set.Current()
	if err == nil {
		t.Error("expected error, got nil")
	}
	if err != ErrNoCurrent {
		t.Errorf("expected ErrNoCurrent, got %v", err)
	}
}

func TestPublicKeyReturnsNilWhenKidNotFound(t *testing.T) {
	set, _ := NewSet()
	pub, ok := set.PublicKey("nonexistent-kid")
	if ok {
		t.Error("expected false, got true")
	}
	if pub != nil {
		t.Error("expected nil public key")
	}
}
