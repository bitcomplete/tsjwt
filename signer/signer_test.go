package signer_test

import (
	"errors"
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/signer"
)

// FakeIdentitySource for testing
type FakeIdentitySource struct {
	identity tsjwt.Identity
	err      error
}

func (f *FakeIdentitySource) Identify(remoteAddr string) (tsjwt.Identity, error) {
	if f.err != nil {
		return tsjwt.Identity{}, f.err
	}
	return f.identity, nil
}

func TestMintAndVerify(t *testing.T) {
	// Setup
	keySet, _ := keys.NewSet()
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
			Node:        "node1",
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

	s, err := signer.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Mint a token
	token, claims, err := s.Mint("127.0.0.1:8080", "myapp", "tenant1")
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	if token == "" {
		t.Error("token is empty")
	}
	if claims.Subject != "user123" {
		t.Errorf("claims.Subject = %q, want user123", claims.Subject)
	}
	if claims.Tenant != "tenant1" {
		t.Errorf("claims.Tenant = %q, want tenant1", claims.Tenant)
	}
	if claims.Audience != "myapp" {
		t.Errorf("claims.Audience = %q, want myapp", claims.Audience)
	}
}

func TestMintRefusesIdentityWithNoTenant(t *testing.T) {
	keySet, _ := keys.NewSet()

	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{
			Subject:     "user123",
			DisplayName: "Test User",
		},
	}

	// Empty grant with no tenants
	resolver := tsjwt.StaticGrant(tsjwt.Grant{})

	cfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    resolver,
	}

	s, _ := signer.New(cfg)
	_, _, err := s.Mint("127.0.0.1:8080", "myapp", "")

	if err == nil {
		t.Error("expected error for no tenant, got nil")
	}
	if !errors.Is(err, tsjwt.ErrNoTenant) {
		t.Errorf("expected ErrNoTenant, got %v", err)
	}
}

func TestMintRefusesTenantNotHeld(t *testing.T) {
	// Test tenant isolation
	keySet, _ := keys.NewSet()
	tenant1 := tsjwt.Tenant{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}}
	grant := tsjwt.Grant{
		Tenants: []tsjwt.Tenant{tenant1},
		Default: "tenant1",
	}

	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{
			Subject: "user123",
		},
	}

	resolver := tsjwt.StaticGrant(grant)

	cfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    resolver,
	}

	s, _ := signer.New(cfg)
	// Try to mint for a tenant the identity does not hold
	_, _, err := s.Mint("127.0.0.1:8080", "myapp", "tenant2")

	if err == nil {
		t.Error("expected error for unauthorized tenant, got nil")
	}
	if !errors.Is(err, tsjwt.ErrNoTenant) {
		t.Errorf("expected ErrNoTenant, got %v", err)
	}
}

func TestMintWithEmptyTenantSelectsDefault(t *testing.T) {
	keySet, _ := keys.NewSet()
	tenant1 := tsjwt.Tenant{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}}
	tenant2 := tsjwt.Tenant{ID: "tenant2", Name: "Tenant 2", Roles: []string{"user"}}
	grant := tsjwt.Grant{
		Tenants: []tsjwt.Tenant{tenant1, tenant2},
		Default: "tenant2",
	}

	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{
			Subject: "user123",
		},
	}

	resolver := tsjwt.StaticGrant(grant)

	cfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    resolver,
	}

	s, _ := signer.New(cfg)
	_, claims, err := s.Mint("127.0.0.1:8080", "myapp", "")

	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}
	if claims.Tenant != "tenant2" {
		t.Errorf("expected tenant2, got %q", claims.Tenant)
	}
}

func TestMintClampsTTL(t *testing.T) {
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

	// Try to set TTL higher than MaxTTL
	cfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    resolver,
		TTL:        30 * time.Minute, // Exceeds MaxTTL (15 min)
	}

	s, _ := signer.New(cfg)

	if s.TTL() != signer.MaxTTL {
		t.Errorf("TTL not clamped: got %v, want %v", s.TTL(), signer.MaxTTL)
	}

	_, claims, _ := s.Mint("127.0.0.1:8080", "myapp", "tenant1")

	expiry := time.Unix(claims.Expiry, 0)
	issuedAt := time.Unix(claims.IssuedAt, 0)
	actualTTL := expiry.Sub(issuedAt)

	if actualTTL > signer.MaxTTL {
		t.Errorf("token TTL exceeds MaxTTL: %v > %v", actualTTL, signer.MaxTTL)
	}
}
