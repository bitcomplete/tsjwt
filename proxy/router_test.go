package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/bitcomplete/tsjwt/proxy"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

func req(method, rawurl, host string) *http.Request {
	r := httptest.NewRequest(method, rawurl, nil)
	if host != "" {
		r.Host = host
	}
	return r
}

// TestRouterPrecedence pins Gateway API's ordering: the most specific
// hostname wins, then the longest path prefix, then declaration order.
func TestRouterPrecedence(t *testing.T) {
	t.Parallel()
	routes := []proxy.Route{
		{Name: "catch-all", Upstream: mustURL(t, "http://catch"), Audience: "catch"},
		{Name: "wildcard", Hostnames: []string{"*.example.ts.net"},
			Upstream: mustURL(t, "http://wild"), Audience: "wild"},
		{Name: "exact", Hostnames: []string{"app.example.ts.net"},
			Upstream: mustURL(t, "http://exact"), Audience: "exact"},
		{Name: "exact-api", Hostnames: []string{"app.example.ts.net"}, PathPrefix: "/api",
			Upstream: mustURL(t, "http://api"), Audience: "api"},
		{Name: "exact-api-v2", Hostnames: []string{"app.example.ts.net"}, PathPrefix: "/api/v2",
			Upstream: mustURL(t, "http://apiv2"), Audience: "apiv2"},
	}
	r, err := proxy.NewRouter(routes...)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	for _, tc := range []struct{ name, host, path, want string }{
		{"exact beats wildcard", "app.example.ts.net", "/", "exact"},
		{"wildcard beats catch-all", "other.example.ts.net", "/", "wildcard"},
		{"unrelated host falls to catch-all", "elsewhere.net", "/", "catch-all"},
		{"longer path wins", "app.example.ts.net", "/api/v2/thing", "exact-api-v2"},
		{"shorter path when longer does not match", "app.example.ts.net", "/api/v1/thing", "exact-api"},
		{"path boundary is a segment", "app.example.ts.net", "/apixyz", "exact"},
		{"prefix matches the bare prefix", "app.example.ts.net", "/api", "exact-api"},
		{"port is ignored on the host", "app.example.ts.net:443", "/", "exact"},
		{"trailing dot is ignored", "app.example.ts.net.", "/", "exact"},
		{"host match is case insensitive", "APP.Example.TS.NET", "/", "exact"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := r.Match(req(http.MethodGet, "http://x"+tc.path, tc.host))
			if !ok {
				t.Fatalf("no route matched %s%s", tc.host, tc.path)
			}
			if got.Name != tc.want {
				t.Fatalf("matched %q, want %q", got.Name, tc.want)
			}
		})
	}
}

// TestRouterNoMatch covers a router with no catch-all.
func TestRouterNoMatch(t *testing.T) {
	t.Parallel()
	r, err := proxy.NewRouter(proxy.Route{
		Hostnames: []string{"only.example.ts.net"},
		Upstream:  mustURL(t, "http://only"), Audience: "only",
	})
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	if _, ok := r.Match(req(http.MethodGet, "http://x/", "other.example.ts.net")); ok {
		t.Fatal("a request with no matching route must not match one")
	}
}

// TestRouterRejectsBadRoutes checks the validation that stops a
// misconfiguration reaching production.
func TestRouterRejectsBadRoutes(t *testing.T) {
	t.Parallel()
	good := mustURL(t, "http://x")
	for _, tc := range []struct {
		name  string
		route proxy.Route
	}{
		{"no upstream", proxy.Route{Audience: "a"}},
		{"no audience", proxy.Route{Upstream: good}},
		{"blank audience", proxy.Route{Upstream: good, Audience: "  "}},
		{"interior wildcard", proxy.Route{Upstream: good, Audience: "a",
			Hostnames: []string{"a.*.example.net"}}},
		{"bare wildcard label", proxy.Route{Upstream: good, Audience: "a",
			Hostnames: []string{"*"}}},
		{"relative path prefix", proxy.Route{Upstream: good, Audience: "a", PathPrefix: "api"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := proxy.NewRouter(tc.route); err == nil {
				t.Fatal("expected this route to be refused")
			}
		})
	}
	if _, err := proxy.NewRouter(); err == nil {
		t.Fatal("a router with no routes must be refused")
	}
}

// TestAudienceFollowsTheRoute is the security property of routing here: a
// token minted for one backend must not carry another backend's audience.
func TestAudienceFollowsTheRoute(t *testing.T) {
	t.Parallel()
	r, err := proxy.NewRouter(
		proxy.Route{Name: "grafana", Hostnames: []string{"grafana.example.ts.net"},
			Upstream: mustURL(t, "http://grafana"), Audience: "grafana"},
		proxy.Route{Name: "bithub", Hostnames: []string{"bithub.example.ts.net"},
			Upstream: mustURL(t, "http://bithub"), Audience: "bithub"},
	)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	for host, want := range map[string]string{
		"grafana.example.ts.net": "grafana",
		"bithub.example.ts.net":  "bithub",
	} {
		got, ok := r.Match(req(http.MethodGet, "http://x/", host))
		if !ok {
			t.Fatalf("%s: no route", host)
		}
		if got.Audience != want {
			t.Fatalf("%s got audience %q, want %q — a token for one backend "+
				"would work at another", host, got.Audience, want)
		}
	}
}
