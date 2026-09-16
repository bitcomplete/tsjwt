package tsjwt

import (
	"encoding/json"
	"fmt"
	"os"
)

// PolicyFile is the on-disk tenant policy.
//
// Tenancy lives in a file rather than in code so that changing who may act
// for what is a configuration change. The format is deliberately small: the
// library has no opinion about tenant or role names, so there is nothing here
// but the mapping.
type PolicyFile struct {
	// Tenants are every tenant known to this deployment.
	Tenants []PolicyTenant `json:"tenants"`

	// DefaultRole is granted inside a tenant to an identity that matches
	// the tenant but no role rule. Empty means no access, which is the
	// safer default and so the one that applies when the field is absent.
	DefaultRole string `json:"defaultRole,omitempty"`
}

// PolicyTenant is one tenant and the groups that grant roles in it.
type PolicyTenant struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`

	// Groups maps a group reported by the identity source to a role
	// inside this tenant.
	Groups map[string]string `json:"groups"`

	// Default marks this tenant as the one used when a caller names none.
	Default bool `json:"default,omitempty"`
}

// LoadPolicyFile reads a policy file and returns it as a [TenantResolver].
//
// Unknown fields are refused. A policy that silently ignores a mistyped key
// would grant less access than its author believed, and the failure would
// show up as a confusing refusal rather than as a parse error.
func LoadPolicyFile(path string) (TenantResolver, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("tsjwt: read tenant policy: %w", err)
	}
	defer f.Close()

	var p PolicyFile
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("tsjwt: parse tenant policy %s: %w", path, err)
	}
	return p.Resolver()
}

// Resolver validates the policy and returns it as a [TenantResolver].
func (p PolicyFile) Resolver() (TenantResolver, error) {
	if len(p.Tenants) == 0 {
		return nil, fmt.Errorf("tsjwt: tenant policy names no tenants")
	}
	var defaultID string
	for _, t := range p.Tenants {
		if err := (Tenant{ID: t.ID}).Valid(); err != nil {
			return nil, fmt.Errorf("tsjwt: tenant policy: %w", err)
		}
		if t.Default {
			if defaultID != "" {
				return nil, fmt.Errorf("tsjwt: tenant policy: %q and %q are both default",
					defaultID, t.ID)
			}
			defaultID = t.ID
		}
	}

	tenants := append([]PolicyTenant(nil), p.Tenants...)
	defaultRole := p.DefaultRole

	return TenantResolverFunc(func(id Identity) (Grant, error) {
		var g Grant
		for _, t := range tenants {
			var roles []string
			seen := map[string]struct{}{}
			for _, grp := range id.Groups {
				role, ok := t.Groups[grp]
				if !ok {
					continue
				}
				if _, dup := seen[role]; dup {
					continue
				}
				seen[role] = struct{}{}
				roles = append(roles, role)
			}
			if len(roles) == 0 {
				if defaultRole == "" {
					continue // no access to this tenant
				}
				roles = []string{defaultRole}
			}
			g.Tenants = append(g.Tenants, Tenant{ID: t.ID, Name: t.Name, Roles: roles})
			if t.Default {
				g.Default = t.ID
			}
		}
		// Reaching exactly one tenant makes that the default, whatever
		// the file says, so a single-tenant deployment needs no flag.
		if g.Default == "" && len(g.Tenants) == 1 {
			g.Default = g.Tenants[0].ID
		}
		return g, nil
	}), nil
}
