package tsjwt

import "testing"

// A non-empty top-level defaultRole in a MULTI-tenant policy must never grant a
// tenant to an identity that matches none of that tenant's group rules. Before
// the fix the resolver appended every tenant with defaultRole, so any
// authenticated identity (even one in zero mapped groups) obtained a role in
// every tenant, collapsing tenant isolation.
//
// Regression for audit finding
// policy-defaultrole-grants-every-tenant-to-every-identity.
func TestPolicyFileDefaultRoleDoesNotGrantForeignTenant(t *testing.T) {
	pf := PolicyFile{
		Tenants: []PolicyTenant{
			{ID: "acme", Default: true, Groups: map[string]string{"group:acme-admin": "admin"}},
			{ID: "globex", Groups: map[string]string{"group:globex-admin": "admin"}},
		},
		DefaultRole: "viewer",
	}
	r, err := pf.Resolver()
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}

	// An identity in an acme group only must not reach globex.
	g, err := r.Resolve(Identity{Subject: "u1", Groups: []string{"group:acme-admin"}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := g.Tenant("globex"); ok {
		t.Error("acme-only identity was granted tenant globex via defaultRole (cross-tenant leak)")
	}
	if _, ok := g.Tenant("acme"); !ok {
		t.Error("acme identity lost its legitimate acme grant")
	}

	// An identity in no mapped group at all must receive no tenant.
	g2, err := r.Resolve(Identity{Subject: "u2", Groups: []string{"group:unrelated"}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(g2.Tenants) != 0 {
		t.Errorf("ungrouped identity got %d tenants via defaultRole, want 0", len(g2.Tenants))
	}
}

// In a SINGLE-tenant policy the defaultRole fallback stays useful and safe: an
// authenticated identity with no mapped group still gets the one tenant at
// defaultRole, matching GroupTenantResolver's single-tenant behaviour.
func TestPolicyFileDefaultRoleAppliesToSingleTenant(t *testing.T) {
	pf := PolicyFile{
		Tenants: []PolicyTenant{
			{ID: "solo", Default: true, Groups: map[string]string{"group:eng": "editor"}},
		},
		DefaultRole: "viewer",
	}
	r, err := pf.Resolver()
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	g, err := r.Resolve(Identity{Subject: "u3", Groups: []string{"group:unrelated"}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	tn, ok := g.Tenant("solo")
	if !ok {
		t.Fatal("single-tenant defaultRole did not grant the tenant to an ungrouped identity")
	}
	if !tn.HasRole("viewer") {
		t.Errorf("expected viewer role from defaultRole, got %v", tn.Roles)
	}
}
