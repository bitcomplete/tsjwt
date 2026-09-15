package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/signer"
)

const testRemoteAddr = "127.0.0.1:8080"

// newTestProxy builds a proxy whose identity source always succeeds, so a
// test can concentrate on header handling.
func newTestProxy(t *testing.T, upstream string) *proxy.Proxy {
	t.Helper()
	up, err := url.Parse(upstream)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	set, err := keys.NewSet()
	if err != nil {
		t.Fatalf("key set: %v", err)
	}
	sg, err := signer.New(signer.Config{
		Issuer:     "https://signer.test",
		Keys:       set,
		Identities: &FakeIdentitySource{identity: tsjwt.Identity{Subject: "user123"}},
		Tenants: tsjwt.StaticGrant(tsjwt.Grant{
			Tenants: []tsjwt.Tenant{{ID: "tenant1", Roles: []string{"admin"}}},
			Default: "tenant1",
		}),
	})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	px, err := proxy.New(proxy.Config{Upstream: up, Signer: sg, Audience: "myapp"})
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	return px
}

// TestStripAssertionRemovesEveryValue pins tsjwt.StripAssertion directly.
//
// The proxy-level test cannot pin it: the proxy sets the header after
// stripping it, and Set replaces every existing value, so a proxy test
// passes whether or not the strip happened. This test fails if the strip
// stops working, which is the point of having it.
func TestStripAssertionRemovesEveryValue(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		header string
		set    string
	}{
		{"default header", "", tsjwt.DefaultHeader},
		{"custom header", "X-Custom-Assertion", "X-Custom-Assertion"},
		{"case insensitive", "", "x-tailnet-jwt-assertion"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			// A multi-valued header is the case Set would not
			// obviously cover if the code ever used Add.
			r.Header.Add(tc.set, "forged-one")
			r.Header.Add(tc.set, "forged-two")

			tsjwt.StripAssertion(r, tc.header)

			name := tc.header
			if name == "" {
				name = tsjwt.DefaultHeader
			}
			if got := r.Header.Values(name); len(got) != 0 {
				t.Fatalf("header survived the strip: %q", got)
			}
		})
	}
}

// TestProxyForwardsExactlyOneAssertion checks that the backend sees one
// assertion and only one, so a forged value cannot ride alongside the real
// one.
func TestProxyForwardsExactlyOneAssertion(t *testing.T) {
	t.Parallel()
	var seen []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Values(tsjwt.DefaultHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	px := newTestProxy(t, backend.URL)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = testRemoteAddr
	r.Header.Add(tsjwt.DefaultHeader, "forged-one")
	r.Header.Add(tsjwt.DefaultHeader, "forged-two")

	px.ServeHTTP(httptest.NewRecorder(), r)

	if len(seen) != 1 {
		t.Fatalf("backend saw %d assertion headers, want exactly 1: %q", len(seen), seen)
	}
	if seen[0] == "forged-one" || seen[0] == "forged-two" {
		t.Fatalf("backend saw a caller-supplied assertion: %q", seen[0])
	}
}
