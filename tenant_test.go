package tsjwt

import (
	"errors"
	"testing"
)

func TestTenantValidRejectsBadIDs(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		shouldErr bool
	}{
		{
			name:      "uppercase",
			id:        "UPPERCASE",
			shouldErr: true,
		},
		{
			name:      "empty",
			id:        "",
			shouldErr: true,
		},
		{
			name:      "leading dash",
			id:        "-invalid",
			shouldErr: true,
		},
		{
			name:      "trailing dash",
			id:        "invalid-",
			shouldErr: true,
		},
		{
			name:      "too long",
			id:        "a" + string(make([]byte, 63)), // 64 chars
			shouldErr: true,
		},
		{
			name:      "special chars",
			id:        "tenant@invalid",
			shouldErr: true,
		},
		{
			name:      "valid single char",
			id:        "a",
			shouldErr: false,
		},
		{
			name:      "valid multi char",
			id:        "my-tenant",
			shouldErr: false,
		},
		{
			name:      "valid with dots and underscores",
			id:        "my_tenant.prod",
			shouldErr: false,
		},
		{
			name:      "max length valid",
			id:        "a" + string(make([]byte, 61)) + "z", // 63 chars, all 'a' except last
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant := Tenant{ID: tt.id, Name: "Test"}
			err := tenant.Valid()
			if (err != nil) != tt.shouldErr {
				t.Errorf("expected error=%v, got error=%v (%v)", tt.shouldErr, err != nil, err)
			}
			if err != nil && !errors.Is(err, ErrNoTenant) {
				t.Errorf("expected error wrapping ErrNoTenant, got %v", err)
			}
		})
	}
}

func TestTenantValidRejectsEmptyRoles(t *testing.T) {
	tenant := Tenant{
		ID:    "tenant1",
		Name:  "Test",
		Roles: []string{"admin", "", "user"},
	}
	err := tenant.Valid()
	if err == nil {
		t.Error("expected error for empty role, got nil")
	}
	if !errors.Is(err, ErrNoTenant) {
		t.Errorf("expected error wrapping ErrNoTenant, got %v", err)
	}
}

func TestTenantAcceptsValidIDs(t *testing.T) {
	tests := []struct {
		id string
	}{
		{"a"},
		{"tenant1"},
		{"my-tenant"},
		{"my_tenant"},
		{"my.tenant"},
		{"a1b2c3"},
		{"tenant-123"},
		{"a" + string(make([]byte, 61)) + "z"}, // 63 chars
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			tenant := Tenant{ID: tt.id, Name: "Test", Roles: []string{"user"}}
			err := tenant.Valid()
			if err != nil {
				t.Errorf("expected no error for valid id, got %v", err)
			}
		})
	}
}

func TestGrantValidRejectsDuplicateTenant(t *testing.T) {
	grant := Grant{
		Tenants: []Tenant{
			{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}},
			{ID: "tenant1", Name: "Tenant 1 Duplicate", Roles: []string{"user"}},
		},
	}
	err := grant.Valid()
	if err == nil {
		t.Error("expected error for duplicate tenant, got nil")
	}
	if !errors.Is(err, ErrNoTenant) {
		t.Errorf("expected error wrapping ErrNoTenant, got %v", err)
	}
}

func TestGrantValidRejectsDefaultNotInTenants(t *testing.T) {
	grant := Grant{
		Tenants: []Tenant{
			{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}},
		},
		Default: "tenant2", // Not in Tenants
	}
	err := grant.Valid()
	if err == nil {
		t.Error("expected error for default not in tenants, got nil")
	}
	if !errors.Is(err, ErrNoTenant) {
		t.Errorf("expected error wrapping ErrNoTenant, got %v", err)
	}
}

func TestGrantValidAcceptsValidGrant(t *testing.T) {
	grant := Grant{
		Tenants: []Tenant{
			{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}},
			{ID: "tenant2", Name: "Tenant 2", Roles: []string{"user"}},
		},
		Default: "tenant1",
	}
	err := grant.Valid()
	if err != nil {
		t.Errorf("expected no error for valid grant, got %v", err)
	}
}

func TestGrantValidAcceptsEmptyDefault(t *testing.T) {
	grant := Grant{
		Tenants: []Tenant{
			{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}},
		},
		Default: "",
	}
	err := grant.Valid()
	if err != nil {
		t.Errorf("expected no error with empty default, got %v", err)
	}
}

func TestGroupTenantResolverAccumulatesRoles(t *testing.T) {
	resolver := GroupTenantResolver{
		Tenant: Tenant{ID: "tenant1", Name: "Tenant"},
		Roles: map[string]string{
			"group1": "admin",
			"group2": "editor",
			"group3": "viewer",
		},
	}

	identity := Identity{
		Subject: "user1",
		Groups:  []string{"group1", "group2"},
	}

	grant, err := resolver.Resolve(identity)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(grant.Tenants) != 1 {
		t.Errorf("expected 1 tenant, got %d", len(grant.Tenants))
	}

	tenant := grant.Tenants[0]
	if len(tenant.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(tenant.Roles))
	}

	// Roles should be sorted
	if tenant.Roles[0] != "admin" || tenant.Roles[1] != "editor" {
		t.Errorf("expected sorted roles [admin, editor], got %v", tenant.Roles)
	}
}

func TestGroupTenantResolverSortsRoles(t *testing.T) {
	resolver := GroupTenantResolver{
		Tenant: Tenant{ID: "tenant1", Name: "Tenant"},
		Roles: map[string]string{
			"group1": "zebra",
			"group2": "apple",
			"group3": "middle",
		},
	}

	identity := Identity{
		Subject: "user1",
		Groups:  []string{"group3", "group1", "group2"},
	}

	grant, err := resolver.Resolve(identity)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	tenant := grant.Tenants[0]
	// Check that roles are sorted
	if tenant.Roles[0] != "apple" || tenant.Roles[1] != "middle" || tenant.Roles[2] != "zebra" {
		t.Errorf("expected sorted roles [apple, middle, zebra], got %v", tenant.Roles)
	}
}

func TestGroupTenantResolverDeduplicatesRoles(t *testing.T) {
	resolver := GroupTenantResolver{
		Tenant: Tenant{ID: "tenant1", Name: "Tenant"},
		Roles: map[string]string{
			"group1": "admin",
			"group2": "admin", // Same role
		},
	}

	identity := Identity{
		Subject: "user1",
		Groups:  []string{"group1", "group2"},
	}

	grant, err := resolver.Resolve(identity)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	tenant := grant.Tenants[0]
	if len(tenant.Roles) != 1 {
		t.Errorf("expected 1 role after deduplication, got %d", len(tenant.Roles))
	}
	if tenant.Roles[0] != "admin" {
		t.Errorf("expected admin role, got %v", tenant.Roles)
	}
}

func TestGroupTenantResolverAppliesDefaultRole(t *testing.T) {
	resolver := GroupTenantResolver{
		Tenant:      Tenant{ID: "tenant1", Name: "Tenant"},
		Roles:       map[string]string{"group1": "admin"},
		DefaultRole: "viewer",
	}

	identity := Identity{
		Subject: "user1",
		Groups:  []string{"group2"}, // Not in Roles map
	}

	grant, err := resolver.Resolve(identity)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(grant.Tenants) != 1 {
		t.Errorf("expected 1 tenant, got %d", len(grant.Tenants))
	}

	tenant := grant.Tenants[0]
	if len(tenant.Roles) != 1 || tenant.Roles[0] != "viewer" {
		t.Errorf("expected default role [viewer], got %v", tenant.Roles)
	}
}

func TestGroupTenantResolverEmptyGrantWhenNoMatchAndNoDefault(t *testing.T) {
	resolver := GroupTenantResolver{
		Tenant: Tenant{ID: "tenant1", Name: "Tenant"},
		Roles:  map[string]string{"group1": "admin"},
		// DefaultRole is empty
	}

	identity := Identity{
		Subject: "user1",
		Groups:  []string{"group2"}, // Not in Roles map
	}

	grant, err := resolver.Resolve(identity)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(grant.Tenants) != 0 {
		t.Errorf("expected empty grant (0 tenants), got %d", len(grant.Tenants))
	}
}

func TestGroupTenantResolverDefaultTenantIsSet(t *testing.T) {
	resolver := GroupTenantResolver{
		Tenant: Tenant{ID: "tenant1", Name: "Tenant"},
		Roles:  map[string]string{"group1": "admin"},
	}

	identity := Identity{
		Subject: "user1",
		Groups:  []string{"group1"},
	}

	grant, err := resolver.Resolve(identity)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if grant.Default != "tenant1" {
		t.Errorf("expected default tenant 'tenant1', got %q", grant.Default)
	}
}
