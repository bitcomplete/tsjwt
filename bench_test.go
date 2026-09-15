package tsjwt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/signer"
	"github.com/bitcomplete/tsjwt/verifier"
)

// These benchmarks exist so that a change which makes the hot path slower
// shows up in CI rather than in production. The hot path is one mint and one
// verify per request, so those two dominate everything else here.

type benchNet struct{ id tsjwt.Identity }

func (b benchNet) Identify(string) (tsjwt.Identity, error) { return b.id, nil }

func benchSigner(b *testing.B) *signer.Signer {
	b.Helper()
	set, err := keys.NewSet()
	if err != nil {
		b.Fatal(err)
	}
	sg, err := signer.New(signer.Config{
		Issuer: "https://bench", Keys: set,
		Identities: benchNet{tsjwt.Identity{
			Subject: "tailnet:1", Login: "a@example.com",
			Groups: []string{"group:admin"},
		}},
		Tenants: tsjwt.StaticGrant(tsjwt.Grant{
			Tenants: []tsjwt.Tenant{{ID: "acme", Roles: []string{"admin"}}},
			Default: "acme",
		}),
	})
	if err != nil {
		b.Fatal(err)
	}
	return sg
}

// BenchmarkMint measures issuing one assertion: identity, tenant resolution,
// claim assembly and an ES256 signature.
func BenchmarkMint(b *testing.B) {
	sg := benchSigner(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := sg.Mint("100.0.0.1:1", "bench", ""); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerify measures the backend side: parse, key lookup, signature
// check and the registered-claim checks.
func BenchmarkVerify(b *testing.B) {
	set, err := keys.NewSet()
	if err != nil {
		b.Fatal(err)
	}
	sg, err := signer.New(signer.Config{
		Issuer: "https://bench", Keys: set,
		Identities: benchNet{tsjwt.Identity{Subject: "tailnet:1"}},
		Tenants: tsjwt.StaticGrant(tsjwt.Grant{
			Tenants: []tsjwt.Tenant{{ID: "acme", Roles: []string{"admin"}}}, Default: "acme"}),
	})
	if err != nil {
		b.Fatal(err)
	}
	tok, _, err := sg.Mint("100.0.0.1:1", "bench", "")
	if err != nil {
		b.Fatal(err)
	}
	v, err := verifier.New(verifier.Config{
		Issuer: "https://bench", Audience: "bench",
		Keys: verifier.LocalKeys{Set: set},
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.Verify(ctx, tok); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRouteMatch measures routing alone, over a table big enough that a
// linear scan would show. Routing runs before every mint, so a regression
// here is paid on every request.
func BenchmarkRouteMatch(b *testing.B) {
	up, _ := url.Parse("http://backend")
	var routes []proxy.Route
	for i := range 50 {
		routes = append(routes, proxy.Route{
			Hostnames:  []string{string(rune('a'+i%26)) + ".example.ts.net"},
			PathPrefix: "/svc",
			Upstream:   up, Audience: "svc",
		})
	}
	routes = append(routes, proxy.Route{
		Hostnames: []string{"app.example.ts.net"}, PathPrefix: "/api/v2",
		Upstream: up, Audience: "api",
	})
	r, err := proxy.NewRouter(routes...)
	if err != nil {
		b.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://x/api/v2/thing", nil)
	req.Host = "app.example.ts.net"
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := r.Match(req); !ok {
			b.Fatal("no match")
		}
	}
}

// BenchmarkEndToEnd measures a whole proxied request: route, mint, inject,
// forward, verify at the backend. This is the number that matters for
// capacity planning.
func BenchmarkEndToEnd(b *testing.B) {
	set, err := keys.NewSet()
	if err != nil {
		b.Fatal(err)
	}
	v, err := verifier.New(verifier.Config{
		Issuer: "https://bench", Audience: "bench",
		Keys: verifier.LocalKeys{Set: set},
	})
	if err != nil {
		b.Fatal(err)
	}
	backend := httptest.NewServer(v.Middleware("", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	defer backend.Close()
	up, _ := url.Parse(backend.URL)

	sg, err := signer.New(signer.Config{
		Issuer: "https://bench", Keys: set,
		Identities: benchNet{tsjwt.Identity{Subject: "tailnet:1"}},
		Tenants: tsjwt.StaticGrant(tsjwt.Grant{
			Tenants: []tsjwt.Tenant{{ID: "acme", Roles: []string{"admin"}}}, Default: "acme"}),
		TTL: 5 * time.Minute,
	})
	if err != nil {
		b.Fatal(err)
	}
	px, err := proxy.New(proxy.Config{Upstream: up, Signer: sg, Audience: "bench"})
	if err != nil {
		b.Fatal(err)
	}
	front := httptest.NewServer(px)
	defer front.Close()

	client := front.Client()
	b.ReportAllocs()
	for b.Loop() {
		resp, err := client.Get(front.URL + "/")
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("status %d", resp.StatusCode)
		}
	}
}
