package verifier_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/jwt"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/signer"
	"github.com/bitcomplete/tsjwt/verifier"
)

// FakeIdentitySource for testing
type FakeIdentitySource struct {
	identity tsjwt.Identity
}

func (f *FakeIdentitySource) Identify(remoteAddr string) (tsjwt.Identity, error) {
	return f.identity, nil
}

// Helper to mint a token for testing
func mintToken(keySet *keys.Set, audience string) (string, error) {
	tenant := tsjwt.Tenant{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}}
	grant := tsjwt.Grant{
		Tenants: []tsjwt.Tenant{tenant},
		Default: "tenant1",
	}

	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{
			Subject:     "user123",
			Login:       "user@example.com",
			DisplayName: "Test User",
			Groups:      []string{"group1"},
		},
	}

	resolver := tsjwt.StaticGrant(grant)

	cfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    resolver,
		TTL:        5 * time.Minute,
	}

	s, _ := signer.New(cfg)
	token, _, err := s.Mint("127.0.0.1:8080", audience, "tenant1")
	return token, err
}

func TestVerifyRoundTrip(t *testing.T) {
	keySet, _ := keys.NewSet()
	token, err := mintToken(keySet, "myapp")
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	cfg := verifier.Config{
		Issuer:   "https://example.com",
		Audience: "myapp",
		Keys:     verifier.LocalKeys{Set: keySet},
	}

	v, _ := verifier.New(cfg)
	claims, err := v.Verify(context.Background(), token)

	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if claims.Subject != "user123" {
		t.Errorf("claims.Subject = %q, want user123", claims.Subject)
	}
	if claims.Tenant != "tenant1" {
		t.Errorf("claims.Tenant = %q, want tenant1", claims.Tenant)
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	keySet, _ := keys.NewSet()
	token, _ := mintToken(keySet, "myapp")

	cfg := verifier.Config{
		Issuer:   "https://example.com",
		Audience: "wrongapp", // Different audience
		Keys:     verifier.LocalKeys{Set: keySet},
	}

	v, _ := verifier.New(cfg)
	_, err := v.Verify(context.Background(), token)

	if err == nil {
		t.Error("expected error for wrong audience, got nil")
	}
	if !errors.Is(err, tsjwt.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	keySet, _ := keys.NewSet()
	token, _ := mintToken(keySet, "myapp")

	cfg := verifier.Config{
		Issuer:   "https://wrong.com", // Different issuer
		Audience: "myapp",
		Keys:     verifier.LocalKeys{Set: keySet},
	}

	v, _ := verifier.New(cfg)
	_, err := v.Verify(context.Background(), token)

	if err == nil {
		t.Error("expected error for wrong issuer, got nil")
	}
	if !errors.Is(err, tsjwt.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	keySet, _ := keys.NewSet()
	tenant := tsjwt.Tenant{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}}
	grant := tsjwt.Grant{
		Tenants: []tsjwt.Tenant{tenant},
		Default: "tenant1",
	}

	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{
			Subject: "user123",
		},
	}

	resolver := tsjwt.StaticGrant(grant)

	// Create signer with very short TTL
	baseTime := time.Unix(1000000, 0)
	cfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    resolver,
		TTL:        1 * time.Second,
		Now:        func() time.Time { return baseTime },
	}

	s, _ := signer.New(cfg)
	token, _, _ := s.Mint("127.0.0.1:8080", "myapp", "tenant1")

	// Advance time well past expiry (expiry is baseTime + 1 second, verifier leeway is 1 minute by default)
	laterTime := baseTime.Add(2 * time.Minute)

	vCfg := verifier.Config{
		Issuer:   "https://example.com",
		Audience: "myapp",
		Keys:     verifier.LocalKeys{Set: keySet},
		Now:      func() time.Time { return laterTime },
	}

	v, _ := verifier.New(vCfg)
	_, err := v.Verify(context.Background(), token)

	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
	if !errors.Is(err, tsjwt.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyRejectsNotYetValid(t *testing.T) {
	keySet, _ := keys.NewSet()
	tenant := tsjwt.Tenant{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}}
	grant := tsjwt.Grant{
		Tenants: []tsjwt.Tenant{tenant},
		Default: "tenant1",
	}

	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{
			Subject: "user123",
		},
	}

	resolver := tsjwt.StaticGrant(grant)

	baseTime := time.Unix(2000000, 0)
	cfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    resolver,
		TTL:        5 * time.Minute,
		Leeway:     30 * time.Second, // Default leeway
		Now:        func() time.Time { return baseTime },
	}

	s, _ := signer.New(cfg)
	token, _, _ := s.Mint("127.0.0.1:8080", "myapp", "tenant1")

	// nbf is baseTime - 30 seconds (from signer leeway)
	// verifier checks: now.Add(leeway).Before(nbf)
	// with verifier leeway 60s default: earlyTime.Add(60s).Before(baseTime - 30s)
	// we need: earlyTime + 60s < baseTime - 30s
	// so: earlyTime < baseTime - 90s
	// Try to verify 2 minutes before baseTime
	earlyTime := baseTime.Add(-2 * time.Minute)

	vCfg := verifier.Config{
		Issuer:   "https://example.com",
		Audience: "myapp",
		Keys:     verifier.LocalKeys{Set: keySet},
		Now:      func() time.Time { return earlyTime },
	}

	v, _ := verifier.New(vCfg)
	_, err := v.Verify(context.Background(), token)

	if err == nil {
		t.Error("expected error for not-yet-valid token, got nil")
	}
	if !errors.Is(err, tsjwt.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyRejectsUnknownKid(t *testing.T) {
	keySet, _ := keys.NewSet()
	token, _ := mintToken(keySet, "myapp")

	// Get the kid from the token
	hdr, _, _ := jwt.Parse(token)
	originalKid := hdr.Kid

	// Create a new key set with a different key
	newKeySet, _ := keys.NewSet()

	// Verify the new key set doesn't have the original kid
	_, ok := newKeySet.PublicKey(originalKid)
	if ok {
		t.Fatal("new key set should not have the original kid")
	}

	cfg := verifier.Config{
		Issuer:   "https://example.com",
		Audience: "myapp",
		Keys:     verifier.LocalKeys{Set: newKeySet},
	}

	v, _ := verifier.New(cfg)
	_, err := v.Verify(context.Background(), token)

	if err == nil {
		t.Error("expected error for unknown kid, got nil")
	}
	if !errors.Is(err, tsjwt.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyRejectsExceededMaxLifetime(t *testing.T) {
	// Create a token with a very long lifetime
	// We'll use a signer with custom time and then verify with strict MaxLifetime
	keySet, _ := keys.NewSet()

	baseTime := time.Unix(3000000, 0)
	tenant := tsjwt.Tenant{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}}
	grant := tsjwt.Grant{
		Tenants: []tsjwt.Tenant{tenant},
		Default: "tenant1",
	}

	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{Subject: "user123"},
	}

	cfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    tsjwt.StaticGrant(grant),
		TTL:        20 * time.Minute, // Token lifetime will be clamped to 15 min (MaxTTL)
		Now:        func() time.Time { return baseTime },
	}

	s, _ := signer.New(cfg)
	token, _, _ := s.Mint("127.0.0.1:8080", "myapp", "tenant1")

	// Verify with a strict MaxLifetime smaller than actual token lifetime
	vCfg := verifier.Config{
		Issuer:      "https://example.com",
		Audience:    "myapp",
		Keys:        verifier.LocalKeys{Set: keySet},
		MaxLifetime: 5 * time.Minute, // Smaller than signer.MaxTTL
		Now:         func() time.Time { return baseTime },
	}

	v, _ := verifier.New(vCfg)
	_, err := v.Verify(context.Background(), token)

	if err == nil {
		t.Error("expected error for lifetime exceeding MaxLifetime, got nil")
	}
	if !errors.Is(err, tsjwt.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyRejectsReplayedToken(t *testing.T) {
	keySet, _ := keys.NewSet()
	token, _ := mintToken(keySet, "myapp")

	guard := verifier.NewMemoryReplayGuard()

	cfg := verifier.Config{
		Issuer:   "https://example.com",
		Audience: "myapp",
		Keys:     verifier.LocalKeys{Set: keySet},
		Replay:   guard,
	}

	v, _ := verifier.New(cfg)

	// First verification should succeed
	_, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("first verify failed: %v", err)
	}

	// Second verification of same token should fail (replay)
	_, err = v.Verify(context.Background(), token)
	if err == nil {
		t.Error("expected error for replayed token, got nil")
	}
	if !errors.Is(err, tsjwt.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestMemoryReplayGuard(t *testing.T) {
	guard := verifier.NewMemoryReplayGuard()

	jti := "token-123"
	expiry := time.Now().Add(5 * time.Minute)

	// First call should return false (not seen)
	if guard.Seen(jti, expiry) {
		t.Error("expected false for first Seen call, got true")
	}

	// Second call should return true (already seen)
	if !guard.Seen(jti, expiry) {
		t.Error("expected true for second Seen call, got false")
	}
}

func TestMemoryReplayGuardCleansExpiredTokens(t *testing.T) {
	guard := verifier.NewMemoryReplayGuard()

	jti := "token-123"
	expiry := time.Now().Add(1 * time.Millisecond)

	// Record the token
	if guard.Seen(jti, expiry) {
		t.Error("expected false for first Seen call")
	}

	// Wait for expiry to pass
	time.Sleep(2 * time.Millisecond)

	// Same token should not be considered replayed anymore (expired)
	if guard.Seen(jti, expiry) {
		t.Error("expected false for expired token, got true")
	}
}

func TestVerifyWithWrongKeyStillRejects(t *testing.T) {
	keySet1, _ := keys.NewSet()
	keySet2, _ := keys.NewSet()

	token, _ := mintToken(keySet1, "myapp")

	// Try to verify with a different key set
	cfg := verifier.Config{
		Issuer:   "https://example.com",
		Audience: "myapp",
		Keys:     verifier.LocalKeys{Set: keySet2},
	}

	v, _ := verifier.New(cfg)
	_, err := v.Verify(context.Background(), token)

	if err == nil {
		t.Error("expected error when verifying with wrong key, got nil")
	}
	if !errors.Is(err, tsjwt.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}
