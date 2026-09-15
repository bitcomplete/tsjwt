package tsjwt

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// tenantIDPattern constrains tenant ids to a conservative, URL- and
// claim-safe shape. It is deliberately narrow: a tenant id travels in a
// token and is often used to select a database, a namespace or a prefix.
var tenantIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$|^[a-z0-9]$`)

// Tenant is an organisation, workspace, project or customer that a request
// acts on behalf of. It is the unit of isolation.
//
// The shape is deliberately general. A deployment with exactly one tenant
// uses one Tenant; a deployment with many uses many. Nothing here assumes
// how tenants are named or where they come from.
type Tenant struct {
	// ID is the stable machine identifier, unique across the deployment.
	// It is what a backend keys isolation on.
	ID string

	// Name is a human label. Never authorize on it.
	Name string

	// Roles are the roles the identity holds within this tenant. Role
	// naming is entirely the operator's; this package assigns no meaning
	// to any particular value.
	Roles []string
}

// Valid reports whether the tenant is well formed.
func (t Tenant) Valid() error {
	if !tenantIDPattern.MatchString(t.ID) {
		return fmt.Errorf("%w: tenant id %q is not a valid id", ErrNoTenant, t.ID)
	}
	for _, r := range t.Roles {
		if strings.TrimSpace(r) == "" {
			return fmt.Errorf("%w: tenant %q has an empty role", ErrNoTenant, t.ID)
		}
	}
	return nil
}

// HasRole reports whether the identity holds the named role in this tenant.
func (t Tenant) HasRole(name string) bool {
	for _, r := range t.Roles {
		if r == name {
			return true
		}
	}
	return false
}

// Grant is the full authorization decision for one identity: the tenants it
// may act for, and the role it holds in each.
type Grant struct {
	// Tenants are every tenant the identity may act for. An empty slice
	// means the identity is authenticated but authorized for nothing.
	Tenants []Tenant

	// Default is the tenant id to use when a request names none. It must
	// appear in Tenants. Empty means the caller must always name one.
	Default string
}

// Tenant returns the tenant with the given id.
func (g Grant) Tenant(id string) (Tenant, bool) {
	for _, t := range g.Tenants {
		if t.ID == id {
			return t, true
		}
	}
	return Tenant{}, false
}

// IDs returns every tenant id in the grant, sorted, so that token claims are
// deterministic.
func (g Grant) IDs() []string {
	ids := make([]string, 0, len(g.Tenants))
	for _, t := range g.Tenants {
		ids = append(ids, t.ID)
	}
	sort.Strings(ids)
	return ids
}

// Valid reports whether the grant is well formed and internally consistent.
func (g Grant) Valid() error {
	seen := make(map[string]struct{}, len(g.Tenants))
	for _, t := range g.Tenants {
		if err := t.Valid(); err != nil {
			return err
		}
		if _, dup := seen[t.ID]; dup {
			return fmt.Errorf("%w: tenant %q appears twice", ErrNoTenant, t.ID)
		}
		seen[t.ID] = struct{}{}
	}
	if g.Default != "" {
		if _, ok := seen[g.Default]; !ok {
			return fmt.Errorf("%w: default tenant %q is not in the grant", ErrNoTenant, g.Default)
		}
	}
	return nil
}

// TenantResolver maps a verified identity to the tenants it may act for.
//
// This is the extension point for an operator's own org model. It is called
// on every mint, so an implementation that consults a database should cache.
//
// A resolver must fail closed: on any doubt, return an error or an empty
// grant, never a broader one.
type TenantResolver interface {
	Resolve(Identity) (Grant, error)
}

// TenantResolverFunc adapts a function to [TenantResolver].
type TenantResolverFunc func(Identity) (Grant, error)

// Resolve implements [TenantResolver].
func (f TenantResolverFunc) Resolve(i Identity) (Grant, error) { return f(i) }

// StaticGrant returns a resolver that gives every authenticated identity the
// same grant. It suits a single-tenant deployment and tests. It does not
// suit anything with more than one tenant.
func StaticGrant(g Grant) TenantResolver {
	return TenantResolverFunc(func(Identity) (Grant, error) { return g, nil })
}

// GroupRoleMap maps a group name reported by the identity source to a role
// name inside a tenant. It expresses the common rule that group membership
// is the single source of truth for authorization.
type GroupRoleMap map[string]string

// GroupTenantResolver grants one tenant to any identity holding a mapped
// group, with the roles those groups confer.
//
// Roles accumulate: an identity in two mapped groups holds both roles. An
// identity in no mapped group receives DefaultRole, and receives no tenant
// at all when DefaultRole is empty.
type GroupTenantResolver struct {
	// Tenant is the tenant granted. Required.
	Tenant Tenant

	// Roles maps group name to role name.
	Roles GroupRoleMap

	// DefaultRole is granted to an identity in no mapped group. Empty
	// means such an identity gets no access.
	DefaultRole string
}

// Resolve implements [TenantResolver].
func (r GroupTenantResolver) Resolve(id Identity) (Grant, error) {
	if err := r.Tenant.Valid(); err != nil {
		return Grant{}, err
	}
	seen := make(map[string]struct{})
	var roles []string
	for _, g := range id.Groups {
		role, ok := r.Roles[g]
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
		if r.DefaultRole == "" {
			return Grant{}, nil
		}
		roles = []string{r.DefaultRole}
	}
	sort.Strings(roles)
	t := r.Tenant
	t.Roles = roles
	return Grant{Tenants: []Tenant{t}, Default: t.ID}, nil
}
