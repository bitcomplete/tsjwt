// Package tsnetid establishes caller identity from a Tailscale tailnet.
//
// This is the trust anchor of the whole design, and it is worth being
// precise about why it can be trusted. tailscaled delivers a packet to this
// process only from a WireGuard peer whose node key it has already
// authenticated. The map from tailnet address to identity comes from the
// control plane, not from the peer. So a caller cannot choose what WhoIs
// reports about it: it can only choose whether to connect at all.
//
// This package is a separate Go module so that the core of tsjwt, and in
// particular a backend that only verifies tokens, does not take a dependency
// on Tailscale.
package tsnetid

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bitcomplete/tsjwt"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// CapGroups is the default capability name read from a peer's grants to
// discover its groups. An operator declares it in the tailnet policy file.
//
// It must actually be declared. Measured on 2026-09-15: WhoIs returns an
// empty CapMap for both a user node and a tagged node when no grant names a
// capability. A deployment that forgets the grant therefore sees every
// caller in no group, which resolves to no tenant, which is a refusal. That
// fails closed, but it fails silently, and it looks like a bug in the
// resolver rather than a missing line in the policy file.
const CapGroups = tailcfg.PeerCapability("tsjwt.dev/cap/groups")

// capRule is the shape this package expects inside the capability grant.
// Anything else in the grant is ignored.
type capRule struct {
	// Groups are the group names to carry into the token.
	Groups []string `json:"groups,omitempty"`
	// Tenants optionally names tenants directly, for a deployment that
	// prefers to express tenancy in the policy file rather than in code.
	Tenants []string `json:"tenants,omitempty"`
}

// AttrTenants is the [tsjwt.Identity] attribute key under which tenants
// named by a capability grant are placed, for a TenantResolver to read.
const AttrTenants = "tsnetid.tenants"

// Source implements [tsjwt.IdentitySource] against a running tailnet node.
type Source struct {
	// Local is the tailnet node's local client, from
	// tsnet.Server.LocalClient. Required.
	Local *local.Client

	// Cap is the capability read for group membership. Zero means
	// [CapGroups].
	Cap tailcfg.PeerCapability

	// AllowTagged permits a tagged node, such as a CI runner, to obtain a
	// token. It is false by default: a tagged node is a machine, not a
	// person, and it has no user identity to assert. Turn it on only for
	// a deployment that deliberately issues machine identities.
	AllowTagged bool

	// Timeout bounds the WhoIs call. Default 5s.
	Timeout time.Duration
}

// Identify implements [tsjwt.IdentitySource].
func (s *Source) Identify(remoteAddr string) (tsjwt.Identity, error) {
	var zero tsjwt.Identity
	if s.Local == nil {
		return zero, fmt.Errorf("%w: no tailnet local client", tsjwt.ErrNoIdentity)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	who, err := s.Local.WhoIs(ctx, remoteAddr)
	if err != nil {
		return zero, fmt.Errorf("%w: whois %s: %v", tsjwt.ErrNoIdentity, remoteAddr, err)
	}
	if who == nil || who.Node == nil {
		return zero, fmt.Errorf("%w: whois returned no node", tsjwt.ErrNoIdentity)
	}
	return s.identity(who)
}

// identity turns a WhoIs answer into an identity. It is separated from
// [Source.Identify] so that the trust decision can be tested against
// recorded WhoIs answers, including hostile ones. It must not consult
// anything but its argument: every field it reads is asserted by the
// control plane, never by the peer.
func (s *Source) identity(who *apitype.WhoIsResponse) (tsjwt.Identity, error) {
	var zero tsjwt.Identity
	// The tag check must come first, and it must be a tag check.
	//
	// Measured against a live tailnet on 2026-09-15: WhoIs on a tagged
	// node does NOT return an empty user. It returns a complete,
	// real-looking profile:
	//
	//	{"ID":<a stable numeric id>,
	//	 "LoginName":"tagged-devices",
	//	 "DisplayName":"Tagged Devices"}
	//
	// That ID is shared by every tagged node in the tailnet. So an
	// implementation that guards only on an empty UserProfile admits
	// every tagged node, and collapses them all into one identity that
	// looks like a person. Any workload holding any tag would then act
	// as the same principal. Guard on the tag itself.
	if who.Node.IsTagged() && !s.AllowTagged {
		return zero, fmt.Errorf("%w: %s is a tagged node, not a person",
			tsjwt.ErrNoIdentity, who.Node.Name)
	}
	if who.UserProfile == nil || who.UserProfile.LoginName == "" {
		return zero, fmt.Errorf("%w: node %s has no user profile", tsjwt.ErrNoIdentity, who.Node.Name)
	}

	id := tsjwt.Identity{
		// The numeric user id is the stable subject. LoginName can be
		// reassigned if an account is renamed; the id cannot.
		Subject:     fmt.Sprintf("tailnet:%d", who.UserProfile.ID),
		Login:       who.UserProfile.LoginName,
		DisplayName: who.UserProfile.DisplayName,
		Node:        strings.TrimSuffix(who.Node.Name, "."),
	}

	capName := s.Cap
	if capName == "" {
		capName = CapGroups
	}
	rules, err := tailcfg.UnmarshalCapJSON[capRule](who.CapMap, capName)
	if err != nil {
		return zero, fmt.Errorf("%w: capability %s is malformed: %v", tsjwt.ErrNoIdentity, capName, err)
	}
	groups := make(map[string]struct{})
	tenants := make(map[string]struct{})
	for _, r := range rules {
		for _, g := range r.Groups {
			groups[g] = struct{}{}
		}
		for _, t := range r.Tenants {
			tenants[t] = struct{}{}
		}
	}
	id.Groups = sortedKeys(groups)
	if len(tenants) > 0 {
		id.Attributes = map[string]any{AttrTenants: sortedKeys(tenants)}
	}
	return id, nil
}

// sortedKeys returns a set's members in a stable order, so that token claims
// do not vary between two calls for the same caller.
func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
