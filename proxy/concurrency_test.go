package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/signer"
)

// TestProxyUnderConcurrency guards a bug that only appears under load, and
// so would never be caught by a benchmark: benchmarks run one operation at a
// time.
//
// The standard library's default transport keeps two idle connections per
// host, because it is built for a program making occasional outbound calls.
// A proxy is the opposite: under concurrency it opened a new connection for
// nearly every request and eventually could not connect at all. Measured on
// 2026-09-15 with a load generator, 2764 of 8000 requests at concurrency 64
// returned 502.
//
// If this test starts failing, look at the transport before anything else.
func TestProxyUnderConcurrency(t *testing.T) {
	t.Parallel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(tsjwt.DefaultHeader) == "" {
			http.Error(w, "no assertion", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	up, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

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
	px, err := proxy.New(proxy.Config{Upstream: up, Signer: sg, Audience: "test"})
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	front := httptest.NewServer(px)
	defer front.Close()

	const (
		workers = 48
		each    = 40
	)
	var ok, bad atomic.Int64
	client := front.Client()
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				resp, err := client.Get(front.URL + "/")
				if err != nil {
					bad.Add(1)
					continue
				}
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					ok.Add(1)
				} else {
					bad.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	if bad.Load() != 0 {
		t.Fatalf("%d of %d requests failed under concurrency %d; "+
			"check Config.Transport and MaxIdleConnsPerHost",
			bad.Load(), workers*each, workers)
	}
	if got := ok.Load(); got != workers*each {
		t.Fatalf("completed %d requests, want %d", got, workers*each)
	}
}
