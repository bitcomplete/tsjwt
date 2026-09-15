package tsjwt

import (
	"context"
	"net/http"
)

// DefaultHeader is the request header an assertion travels in. It follows
// the naming of the identity-aware proxies this design is modelled on:
// Cloudflare Access uses Cf-Access-Jwt-Assertion, Google IAP uses
// X-Goog-Iap-Jwt-Assertion.
const DefaultHeader = "X-Tailnet-Jwt-Assertion"

// contextKey is unexported so no other package can write the claims a
// handler reads.
type contextKey struct{}

// WithClaims returns a context carrying verified claims. Only a verifier
// should call it.
func WithClaims(ctx context.Context, c Claims) context.Context {
	return context.WithValue(ctx, contextKey{}, c)
}

// ClaimsFrom returns the verified claims on ctx.
//
// The second result is false when no verifier ran. A handler must treat that
// as unauthenticated, never as anonymous-but-allowed.
func ClaimsFrom(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(contextKey{}).(Claims)
	return c, ok
}

// StripAssertion removes every copy of the assertion header from a request.
//
// A signer must call this before it injects its own. Without it, a caller
// can present a header of its own and, if anything downstream reads the
// first of several, choose its own identity.
func StripAssertion(r *http.Request, header string) {
	if header == "" {
		header = DefaultHeader
	}
	r.Header.Del(header)
}
