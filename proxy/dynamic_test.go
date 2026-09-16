package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/signer"
)

func dynamicSigner(t *testing.T) *signer.Signer {
	t.Helper()
	set, err := keys.NewSet()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	sg, err := signer.New(signer.Config{
		Issuer: "https://test", Keys: set,
		Identities: &FakeIdentitySource{identity: tsjwt.Identity{Subject: "tailnet:1"}},
		Tenants: tsjwt.StaticGrant(tsjwt.Grant{
			Tenants: []tsjwt.Tenant{{ID: "acme", Roles: []string{"admin"}}}, Default: "acme"}),
	})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return sg
}

// TestDynamicKeepsOldTableOnBadUpdate is the property that matters once
// routes come from cluster resources: one bad edit to one HTTPRoute must not
// take down every other route on the same Gateway.
func TestDynamicKeepsOldTableOnBadUpdate(t *testing.T) {
	t.Parallel()
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer backend.Close()
	up, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	d, err := proxy.NewDynamic(proxy.Config{Signer: dynamicSigner(t)},
		[]proxy.Route{{Name: "good", Upstream: up, Audience: "good"}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	call := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:1"
		d.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call(); got != http.StatusOK {
		t.Fatalf("before the bad update: status %d, want 200", got)
	}

	// A route with no audience is exactly what a half-written HTTPRoute
	// produces.
	if err := d.Set([]proxy.Route{{Name: "broken", Upstream: up}}); err == nil {
		t.Fatal("an invalid table must be refused")
	}
	if got := call(); got != http.StatusOK {
		t.Fatalf("after the bad update: status %d, want 200 — the previous "+
			"table must survive a refused change", got)
	}
	if rs := d.Routes(); len(rs) != 1 || rs[0].Name != "good" {
		t.Fatalf("routes = %v, want the original table", rs)
	}
}

// TestDynamicAppliesAGoodUpdate checks the other half: a valid table replaces
// the old one, and the audience moves with it.
func TestDynamicAppliesAGoodUpdate(t *testing.T) {
	t.Parallel()
	var seen string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get(tsjwt.DefaultHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	up, _ := url.Parse(backend.URL)

	d, err := proxy.NewDynamic(proxy.Config{Signer: dynamicSigner(t)},
		[]proxy.Route{{Name: "first", Upstream: up, Audience: "first"}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := d.Set([]proxy.Route{{Name: "second", Upstream: up, Audience: "second"}}); err != nil {
		t.Fatalf("set: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	d.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if seen == "" {
		t.Fatal("no assertion reached the backend")
	}
	if rs := d.Routes(); len(rs) != 1 || rs[0].Audience != "second" {
		t.Fatalf("routes = %v, want the replacement table", rs)
	}
}

// TestDynamicSwapIsRaceFree drives Set concurrently with ServeHTTP, because
// route updates arrive while traffic is being served.
func TestDynamicSwapIsRaceFree(t *testing.T) {
	t.Parallel()
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer backend.Close()
	up, _ := url.Parse(backend.URL)

	d, err := proxy.NewDynamic(proxy.Config{Signer: dynamicSigner(t)},
		[]proxy.Route{{Name: "a", Upstream: up, Audience: "a"}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					rec := httptest.NewRecorder()
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.RemoteAddr = "127.0.0.1:1"
					d.ServeHTTP(rec, req)
				}
			}
		}()
	}
	for i := range 300 {
		name := "a"
		if i%2 == 0 {
			name = "b"
		}
		if err := d.Set([]proxy.Route{{Name: name, Upstream: up, Audience: name}}); err != nil {
			t.Errorf("set: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

// TestDynamicWithNoRoutesRefuses checks the empty case reports 503 and not
// 404: the Gateway exists and is simply unconfigured, which is worth a retry.
func TestDynamicWithNoRoutesRefuses(t *testing.T) {
	t.Parallel()
	d, err := proxy.NewDynamic(proxy.Config{Signer: dynamicSigner(t)}, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
