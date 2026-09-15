package tsjwt

import (
	"encoding/json"
	"fmt"
	"time"
)

// ClaimTenant is the claim naming the tenant a token acts for. A backend
// that enforces isolation reads this claim and nothing else.
const ClaimTenant = "tenant"

// ClaimTenants is the claim listing every tenant the identity may act for.
// It lets a backend offer a tenant switch without a new token.
const ClaimTenants = "tenants"

// ClaimRoles is the claim listing the roles held within the tenant named by
// ClaimTenant.
const ClaimRoles = "roles"

// ClaimGroups is the claim listing the raw groups the identity source
// reported. It is informational: authorize on roles, which are scoped to a
// tenant, not on groups, which are not.
const ClaimGroups = "groups"

// Claims is the token payload. The registered claims follow RFC 7519; the
// rest are this module's.
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expiry    int64  `json:"exp"`
	ID        string `json:"jti"`

	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
	Node  string `json:"node,omitempty"`

	// Tenant is the tenant this token acts for.
	Tenant string `json:"tenant,omitempty"`
	// Tenants is every tenant the identity may act for.
	Tenants []string `json:"tenants,omitempty"`
	// Roles are the roles held within Tenant.
	Roles []string `json:"roles,omitempty"`
	// Groups are the raw identity-source groups. Informational.
	Groups []string `json:"groups,omitempty"`

	// Extra carries deployment-specific claims. Keys that collide with a
	// registered or module claim are rejected at mint time.
	Extra map[string]any `json:"-"`
}

// reserved is every claim name this package owns. A deployment may not
// overwrite one through Claims.Extra, because a backend trusts their
// meaning.
var reserved = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "iat": {}, "nbf": {}, "exp": {}, "jti": {},
	"email": {}, "name": {}, "node": {},
	ClaimTenant: {}, ClaimTenants: {}, ClaimRoles: {}, ClaimGroups: {},
}

// MarshalJSON merges Extra into the claim object, refusing to shadow a
// reserved name.
func (c Claims) MarshalJSON() ([]byte, error) {
	type alias Claims // avoid recursing into this method
	base, err := json.Marshal(alias(c))
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return base, nil
	}
	var merged map[string]any
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	for k, v := range c.Extra {
		if _, bad := reserved[k]; bad {
			return nil, fmt.Errorf("tsjwt: extra claim %q shadows a reserved claim", k)
		}
		merged[k] = v
	}
	return json.Marshal(merged)
}

// UnmarshalJSON reads the known claims and collects every other member into
// Extra.
func (c *Claims) UnmarshalJSON(b []byte) error {
	type alias Claims
	var base alias
	if err := json.Unmarshal(b, &base); err != nil {
		return err
	}
	*c = Claims(base)
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return err
	}
	for k, raw := range all {
		if _, known := reserved[k]; known {
			continue
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		if c.Extra == nil {
			c.Extra = make(map[string]any)
		}
		c.Extra[k] = v
	}
	return nil
}

// ExpiresAt returns the expiry as a time.
func (c Claims) ExpiresAt() time.Time { return time.Unix(c.Expiry, 0) }

// HasRole reports whether the token holds the named role in its tenant.
func (c Claims) HasRole(name string) bool {
	for _, r := range c.Roles {
		if r == name {
			return true
		}
	}
	return false
}
