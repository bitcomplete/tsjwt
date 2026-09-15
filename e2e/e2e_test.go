// Package e2e drives the whole path the design describes: a caller whose
// identity the network established, a signer that mints an assertion, a
// proxy that injects it, and a backend that verifies it and enforces tenant
// isolation on the claim.
//
// It is deliberately end to end. The unit tests prove each part; this proves
// they compose, and in particular that tenant isolation actually holds
// across the seam.
package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/signer"
	"github.com/bitcomplete/tsjwt/verifier"
)

// network stands in for the identity the transport establishes. In
// production this is tsnetid.Source calling WhoIs. The point of the
// interface is that this substitution is the only difference.
type network map[string]tsjwt.Identity

func (n network) Identify(remoteAddr string) (tsjwt.Identity, error) {
	host := remoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	id, ok := n[host]
	if !ok {
		return tsjwt.Identity{}, tsjwt.ErrNoIdentity
	}
	return id, nil
}

// policy is the generic org model: two unrelated tenants, each with its own
// groups. Nothing here knows what either tenant is for.
func policy() tsjwt.TenantResolver {
	tenants := []struct {
		id     string
		groups map[string]string
	}{
		{"acme", map[string]string{"group:acme-admin": "admin", "group:acme-eng": "editor"}},
		{"globex", map[string]string{"group:globex-admin": "admin"}},
	}
	return tsjwt.TenantResolverFunc(func(id tsjwt.Identity) (tsjwt.Grant, error) {
		var g tsjwt.Grant
		for _, t := range tenants {
			var roles []string
			for _, grp := range id.Groups {
				if role, ok := t.groups[grp]; ok {
					roles = append(roles, role)
				}
			}
			if len(roles) == 0 {
				continue
			}
			g.Tenants = append(g.Tenants, tsjwt.Tenant{ID: t.id, Roles: roles})
		}
		if len(g.Tenants) == 1 {
			g.Default = g.Tenants[0].ID
		}
		return g, nil
	})
}

// record is a row owned by a tenant. The backend must never serve a row to a
// token scoped to a different tenant.
type record struct {
	Tenant string `json:"tenant"`
	Secret string `json:"secret"`
}

var store = map[string]record{
	"acme":   {"acme", "acme-only"},
	"globex": {"globex", "globex-only"},
}

// backend verifies the assertion and serves only the caller's own tenant.
func backend(t *testing.T, set *keys.Set) http.Handler {
	t.Helper()
	v, err := verifier.New(verifier.Config{
		Issuer:   "https://signer.test",
		Audience: "records",
		Keys:     verifier.LocalKeys{Set: set},
		Replay:   verifier.NewMemoryReplayGuard(),
	})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := tsjwt.ClaimsFrom(r.Context())
		if !ok {
			http.Error(w, "no claims", http.StatusInternalServerError)
			return
		}
		want := strings.TrimPrefix(r.URL.Path, "/records/")
		// Isolation is enforced on the tenant claim, and on nothing
		// else. The caller cannot influence it.
		if want != claims.Tenant {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && !claims.HasRole("admin") && !claims.HasRole("editor") {
			http.Error(w, "read only", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(store[claims.Tenant])
	})
	return v.Middleware("", app)
}

func TestEndToEnd(t *testing.T) {
	set, err := keys.NewSet()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	be := httptest.NewServer(backend(t, set))
	defer be.Close()
	up, _ := url.Parse(be.URL)

	net := network{
		"100.0.0.1": {Subject: "tailnet:1", Login: "ana@example.com", Groups: []string{"group:acme-admin"}},
		"100.0.0.2": {Subject: "tailnet:2", Login: "bo@example.com", Groups: []string{"group:globex-admin"}},
		"100.0.0.3": {Subject: "tailnet:3", Login: "cy@example.com", Groups: []string{"group:nobody"}},
	}
	sg, err := signer.New(signer.Config{
		Issuer:     "https://signer.test",
		Keys:       set,
		Identities: net,
		Tenants:    policy(),
	})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	px, err := proxy.New(proxy.Config{
		Upstream: up, Signer: sg, Audience: "records",
		TenantFrom: func(r *http.Request) string { return r.Header.Get("X-Tsjwt-Tenant") },
	})
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	front := httptest.NewServer(px)
	defer front.Close()

	call := func(from, path, tenant string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, front.URL+path, nil)
		req.Host = "records"
		if tenant != "" {
			req.Header.Set("X-Tsjwt-Tenant", tenant)
		}
		// The caller forges an assertion on every call. It must never
		// have any effect.
		req.Header.Set(tsjwt.DefaultHeader, "forged")
		req.RemoteAddr = from + ":40000"
		// httptest dials from loopback, so drive the proxy directly to
		// control the peer address the signer sees.
		rec := httptest.NewRecorder()
		inner, _ := http.NewRequest(http.MethodGet, path, nil)
		inner.RemoteAddr = from + ":40000"
		inner.Header = req.Header.Clone()
		px.ServeHTTP(rec, inner)
		return rec.Code, strings.TrimSpace(rec.Body.String())
	}

	for _, tc := range []struct {
		name   string
		from   string
		path   string
		tenant string
		status int
		body   string
	}{
		{"acme admin reads acme", "100.0.0.1", "/records/acme", "", 200, `{"tenant":"acme","secret":"acme-only"}`},
		{"globex admin reads globex", "100.0.0.2", "/records/globex", "", 200, `{"tenant":"globex","secret":"globex-only"}`},
		{"acme admin cannot reach globex data", "100.0.0.1", "/records/globex", "", 403, "forbidden"},
		{"acme admin cannot mint for globex", "100.0.0.1", "/records/globex", "globex", 403, "Forbidden"},
		{"unknown peer is refused", "100.0.0.9", "/records/acme", "", 401, "Unauthorized"},
		{"known peer in no group is refused", "100.0.0.3", "/records/acme", "", 403, "Forbidden"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := call(tc.from, tc.path, tc.tenant)
			if status != tc.status {
				t.Fatalf("status = %d, want %d (body %q)", status, tc.status, body)
			}
			if !strings.Contains(body, tc.body) {
				t.Fatalf("body = %q, want it to contain %q", body, tc.body)
			}
		})
	}
}

// TestForgedAssertionIsIgnored is the claim the whole design rests on:
// reaching the port proves nothing.
func TestForgedAssertionIsIgnored(t *testing.T) {
	set, _ := keys.NewSet()
	be := httptest.NewServer(backend(t, set))
	defer be.Close()

	// Call the backend directly, as any pod that reached the port could,
	// carrying a header that names an admin.
	req, _ := http.NewRequest(http.MethodGet, be.URL+"/records/acme", nil)
	req.Header.Set(tsjwt.DefaultHeader,
		`{"sub":"tailnet:1","tenant":"acme","roles":["admin"]}`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a forged assertion got %d, want 401", resp.StatusCode)
	}
}

// TestKeyRotationDoesNotBreakLiveTokens proves the overlap window works
// across the seam: a token minted before a rotation still verifies after it.
func TestKeyRotationDoesNotBreakLiveTokens(t *testing.T) {
	set, _ := keys.NewSet(keys.WithOverlap(time.Hour))
	sg, _ := signer.New(signer.Config{
		Issuer: "https://signer.test", Keys: set,
		Identities: network{"100.0.0.1": {Subject: "tailnet:1", Groups: []string{"group:acme-admin"}}},
		Tenants:    policy(),
	})
	tok, _, err := sg.Mint("100.0.0.1:1", "records", "")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := set.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	v, _ := verifier.New(verifier.Config{
		Issuer: "https://signer.test", Audience: "records",
		Keys: verifier.LocalKeys{Set: set},
	})
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("a token minted before rotation must still verify: %v", err)
	}
	_ = errors.Is
}
