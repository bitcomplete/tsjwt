package proxy_test

import (
	"io"
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

// FakeIdentitySource for testing
type FakeIdentitySource struct {
	identity tsjwt.Identity
	err      error
}

func (f *FakeIdentitySource) Identify(remoteAddr string) (tsjwt.Identity, error) {
	if f.err != nil {
		return tsjwt.Identity{}, f.err
	}
	return f.identity, nil
}

// VerifyingBackend is a test backend that verifies the assertion header
func VerifyingBackend(t *testing.T, keySet *keys.Set, expectedAudience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assertion := r.Header.Get(tsjwt.DefaultHeader)
		if assertion == "" {
			http.Error(w, "no assertion header", http.StatusBadRequest)
			return
		}

		cfg := verifier.Config{
			Issuer:   "https://example.com",
			Audience: expectedAudience,
			Keys:     verifier.LocalKeys{Set: keySet},
		}

		v, _ := verifier.New(cfg)
		claims, err := v.Verify(r.Context(), assertion)
		if err != nil {
			http.Error(w, "invalid assertion", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"subject":"`+claims.Subject+`","tenant":"`+claims.Tenant+`"}`)
	}
}

func TestProxyInjectsAssertionHeader(t *testing.T) {
	// Setup backend
	keySet, _ := keys.NewSet()
	backend := httptest.NewServer(VerifyingBackend(t, keySet, "myapp"))
	defer backend.Close()

	upstreamURL, _ := url.Parse(backend.URL)

	// Setup proxy
	tenant := tsjwt.Tenant{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}}
	grant := tsjwt.Grant{
		Tenants: []tsjwt.Tenant{tenant},
		Default: "tenant1",
	}

	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{
			Subject: "user123",
		},
	}

	resolver := tsjwt.StaticGrant(grant)

	signerCfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    resolver,
		TTL:        5 * time.Minute,
	}

	s, _ := signer.New(signerCfg)

	proxyCfg := proxy.Config{
		Upstream: upstreamURL,
		Signer:   s,
		Audience: "myapp",
	}

	p, _ := proxy.New(proxyCfg)

	// Test request through proxy
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:8080"

	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify response contains expected data
	body := w.Body.String()
	if !strings.Contains(body, "user123") {
		t.Errorf("response should contain subject, got: %s", body)
	}
	if !strings.Contains(body, "tenant1") {
		t.Errorf("response should contain tenant, got: %s", body)
	}
}

func TestProxyStripsCallerSuppliedAssertionHeader(t *testing.T) {
	// This is a security test: caller-supplied assertion headers must be stripped

	// Setup backend that checks for the assertion header
	callerSuppliedHeaderSeen := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If we can see a caller-supplied value, that's a security failure
		assertion := r.Header.Get(tsjwt.DefaultHeader)
		if assertion != "" && strings.HasPrefix(assertion, "fake") {
			callerSuppliedHeaderSeen = true
		}

		// Return what we got
		if strings.HasPrefix(assertion, "fake") {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "caller-supplied header detected!")
			return
		}

		// Valid assertion should be from signer
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer backend.Close()

	upstreamURL, _ := url.Parse(backend.URL)

	// Setup signer
	keySet, _ := keys.NewSet()
	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{Subject: "user123"},
	}
	grant := tsjwt.Grant{
		Tenants: []tsjwt.Tenant{{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}}},
		Default: "tenant1",
	}

	signerCfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    tsjwt.StaticGrant(grant),
	}

	s, _ := signer.New(signerCfg)

	proxyCfg := proxy.Config{
		Upstream: upstreamURL,
		Signer:   s,
		Audience: "myapp",
	}

	p, _ := proxy.New(proxyCfg)

	// Create a request with a caller-supplied assertion header
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	req.Header.Set(tsjwt.DefaultHeader, "fake-malicious-token")

	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	// The proxy should have stripped the caller-supplied header
	// and replaced it with a valid one
	if callerSuppliedHeaderSeen {
		t.Error("security failure: caller-supplied assertion header was not stripped!")
	}

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d (caller header was not stripped)", w.Code)
	}
}

func TestProxyReturns401ForNoIdentity(t *testing.T) {
	keySet, _ := keys.NewSet()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	upstreamURL, _ := url.Parse(backend.URL)

	identities := &FakeIdentitySource{
		err: tsjwt.ErrNoIdentity,
	}

	signerCfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    tsjwt.StaticGrant(tsjwt.Grant{}),
	}

	s, _ := signer.New(signerCfg)

	proxyCfg := proxy.Config{
		Upstream: upstreamURL,
		Signer:   s,
		Audience: "myapp",
	}

	p, _ := proxy.New(proxyCfg)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:8080"

	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for ErrNoIdentity, got %d", w.Code)
	}
}

func TestProxyReturns403ForNoTenant(t *testing.T) {
	keySet, _ := keys.NewSet()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	upstreamURL, _ := url.Parse(backend.URL)

	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{Subject: "user123"},
	}

	// Empty grant means no tenants
	grant := tsjwt.Grant{}

	signerCfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    tsjwt.StaticGrant(grant),
	}

	s, _ := signer.New(signerCfg)

	proxyCfg := proxy.Config{
		Upstream: upstreamURL,
		Signer:   s,
		Audience: "myapp",
	}

	p, _ := proxy.New(proxyCfg)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:8080"

	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for ErrNoTenant, got %d", w.Code)
	}
}

func TestProxyErrorHandling(t *testing.T) {
	keySet, _ := keys.NewSet()

	// Backend that always errors
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("backend error")
	}))
	defer backend.Close()

	upstreamURL, _ := url.Parse(backend.URL)

	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{Subject: "user123"},
	}

	grant := tsjwt.Grant{
		Tenants: []tsjwt.Tenant{{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}}},
		Default: "tenant1",
	}

	signerCfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    tsjwt.StaticGrant(grant),
	}

	s, _ := signer.New(signerCfg)

	proxyCfg := proxy.Config{
		Upstream: upstreamURL,
		Signer:   s,
		Audience: "myapp",
	}

	p, _ := proxy.New(proxyCfg)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:8080"

	w := httptest.NewRecorder()
	// This should not panic
	p.ServeHTTP(w, req)

	// Should get a 502 Bad Gateway for upstream error
	if w.Code != http.StatusBadGateway {
		t.Errorf("expected status 502 for upstream error, got %d", w.Code)
	}
}

func TestProxyTenantFromFunction(t *testing.T) {
	// Test that TenantFrom function is called to select tenant
	keySet, _ := keys.NewSet()

	verifiedTenant := ""
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertion := r.Header.Get(tsjwt.DefaultHeader)

		cfg := verifier.Config{
			Issuer:   "https://example.com",
			Audience: "myapp",
			Keys:     verifier.LocalKeys{Set: keySet},
		}

		v, _ := verifier.New(cfg)
		claims, _ := v.Verify(r.Context(), assertion)
		verifiedTenant = claims.Tenant

		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	upstreamURL, _ := url.Parse(backend.URL)

	identities := &FakeIdentitySource{
		identity: tsjwt.Identity{Subject: "user123"},
	}

	grant := tsjwt.Grant{
		Tenants: []tsjwt.Tenant{
			{ID: "tenant1", Name: "Tenant 1", Roles: []string{"admin"}},
			{ID: "tenant2", Name: "Tenant 2", Roles: []string{"user"}},
		},
		Default: "tenant1",
	}

	signerCfg := signer.Config{
		Issuer:     "https://example.com",
		Keys:       keySet,
		Identities: identities,
		Tenants:    tsjwt.StaticGrant(grant),
	}

	s, _ := signer.New(signerCfg)

	proxyCfg := proxy.Config{
		Upstream: upstreamURL,
		Signer:   s,
		Audience: "myapp",
		TenantFrom: func(r *http.Request) string {
			// Select tenant2 based on query param
			return "tenant2"
		},
	}

	p, _ := proxy.New(proxyCfg)

	req := httptest.NewRequest("GET", "/test?tenant=tenant2", nil)
	req.RemoteAddr = "127.0.0.1:8080"

	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if verifiedTenant != "tenant2" {
		t.Errorf("expected tenant2, got %q", verifiedTenant)
	}
}
