// Package tsjwt turns a network-verified caller identity into a short-lived,
// asymmetrically signed JWT.
//
// The model has three parts, and they are deliberately separate:
//
//   - An [IdentitySource] establishes who the caller is. It is the trust
//     anchor. The only implementation shipped here reads a Tailscale tailnet
//     (see package tsnetid), but the core does not depend on Tailscale.
//   - A [TenantResolver] decides which tenants that identity may act for, and
//     with which roles. This is where an operator's own org model plugs in.
//   - A signer mints a token; a verifier checks one (packages signer and
//     verifier).
//
// Nothing in this package is specific to any one deployment. Tenancy,
// role naming and group naming are all supplied by the caller.
package tsjwt

import (
	"errors"
	"fmt"
	"strings"
)

// Errors returned across the module. Callers should test with [errors.Is].
var (
	// ErrNoIdentity means the caller could not be identified at all. It is
	// distinct from an identity that is known but unauthorized.
	ErrNoIdentity = errors.New("tsjwt: caller identity could not be established")

	// ErrNoTenant means the identity is known but may not act for the
	// requested tenant, or for any tenant.
	ErrNoTenant = errors.New("tsjwt: identity has no authorized tenant")

	// ErrInvalidToken covers every rejection of a presented token:
	// malformed, bad signature, wrong algorithm, expired, wrong audience.
	// The reason is in the wrapped error; do not surface it to the caller.
	ErrInvalidToken = errors.New("tsjwt: token is not valid")

	// ErrNoKey means no signing or verification key was available for the
	// requested key id.
	ErrNoKey = errors.New("tsjwt: no key available")
)

// Identity is a caller whose identity has been established by the network
// layer, not asserted by the caller. It is the input to token minting.
//
// An Identity must never be constructed from data the caller controls, such
// as a request header. Build it only from an [IdentitySource].
type Identity struct {
	// Subject is the stable, unique id of the principal. It becomes the
	// "sub" claim. It must not be reassignable to a different person.
	Subject string

	// Login is the human-readable account name, typically an email
	// address. It becomes the "email" claim when it looks like one.
	Login string

	// DisplayName is a human name for logs and UI. Never authorize on it.
	DisplayName string

	// Groups are the group memberships the identity source reported. They
	// are the raw authorization input, before any tenant mapping.
	Groups []string

	// Node identifies the device the request came from, when the identity
	// source knows it. Informational.
	Node string

	// Attributes carries any extra facts the identity source produced, for
	// a TenantResolver to read. Keys are source-defined.
	Attributes map[string]any
}

// Valid reports whether the identity carries the minimum needed to mint a
// token.
func (i Identity) Valid() error {
	if strings.TrimSpace(i.Subject) == "" {
		return fmt.Errorf("%w: subject is empty", ErrNoIdentity)
	}
	return nil
}

// HasGroup reports whether the identity is in the named group. The
// comparison is exact; group naming is the operator's concern.
func (i Identity) HasGroup(name string) bool {
	for _, g := range i.Groups {
		if g == name {
			return true
		}
	}
	return false
}

// IdentitySource establishes the identity behind a network address or a
// request. Implementations must derive the identity from the transport, not
// from caller-supplied data.
type IdentitySource interface {
	// Identify returns the identity of the peer at remoteAddr, which is a
	// "host:port" string as found in http.Request.RemoteAddr.
	//
	// It returns an error wrapping ErrNoIdentity when the peer cannot be
	// identified.
	Identify(remoteAddr string) (Identity, error)
}
