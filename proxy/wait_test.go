package proxy_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/signer"
	"github.com/bitcomplete/tsjwt/verifier"
)

func waitGate(t *testing.T, ready func(context.Context, *url.URL) error, max int) *proxy.WaitGate {
	t.Helper()
	g, err := proxy.NewWaitGate(proxy.WaitConfig{Timeout: time.Second, Interval: time.Millisecond, MaxPending: max, MaxBackends: 2, Ready: ready})
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func gateMetrics(g *proxy.WaitGate) string {
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	return w.Body.String()
}
func awaitMetric(t *testing.T, g *proxy.WaitGate, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(gateMetrics(g), want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("missing metric %q: %s", want, gateMetrics(g))
}
func TestWaitGateBoundsAndCancelsPending(t *testing.T) {
	started := make(chan struct{}, 1)
	g := waitGate(t, func(ctx context.Context, _ *url.URL) error {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	}, 1)
	u, _ := url.Parse("http://app.test")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := g.Acquire(ctx, proxy.Route{Upstream: u}); done <- err }()
	<-started
	if _, err := g.Acquire(context.Background(), proxy.Route{Upstream: u}); err == nil {
		t.Fatal("pending limit not enforced")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	awaitMetric(t, g, "tsjwt_backend_pending_requests{upstream=\"http://app.test\"} 0")
}
func TestWaitGateTracksActiveUntilReleased(t *testing.T) {
	g := waitGate(t, func(context.Context, *url.URL) error { return nil }, 2)
	u, _ := url.Parse("http://app.test")
	release, err := g.Acquire(context.Background(), proxy.Route{Upstream: u})
	if err != nil {
		t.Fatal(err)
	}
	awaitMetric(t, g, "tsjwt_backend_active_requests{upstream=\"http://app.test\"} 1")
	release()
	release()
	awaitMetric(t, g, "tsjwt_backend_active_requests{upstream=\"http://app.test\"} 0")
}
func TestProxyWaitsThenDeliversPOSTOnce(t *testing.T) {
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); b, _ := io.ReadAll(r.Body); w.Write(b) }))
	defer backend.Close()
	ready := make(chan struct{})
	g := waitGate(t, func(ctx context.Context, _ *url.URL) error {
		select {
		case <-ready:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, 8)
	u, _ := url.Parse(backend.URL)
	p, err := proxy.New(proxy.Config{Upstream: u, Audience: "app", Signer: dynamicSigner(t), Gate: g})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader("one body")))
		done <- w
	}()
	awaitMetric(t, g, "tsjwt_backend_pending_requests{upstream="+`"`+backend.URL+`"} 1`)
	if calls.Load() != 0 {
		t.Fatal("request forwarded before readiness")
	}
	close(ready)
	w := <-done
	if w.Code != 200 || w.Body.String() != "one body" || calls.Load() != 1 {
		t.Fatalf("response %d %s, calls %d", w.Code, w.Body.String(), calls.Load())
	}
	awaitMetric(t, g, "tsjwt_backend_active_requests{upstream="+`"`+backend.URL+`"} 0`)
}
func TestUnauthorizedRequestNeverRegistersDemand(t *testing.T) {
	g := waitGate(t, func(context.Context, *url.URL) error { t.Error("unauthorized request probed backend"); return nil }, 1)
	u, _ := url.Parse("http://app.test")
	p, err := proxy.New(proxy.Config{Upstream: u, Audience: "app", Signer: dynamicSigner(t), Gate: g, TenantFrom: func(*http.Request) string { return "forbidden" }})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(tsjwt.DefaultHeader, "forged")
	p.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("status %d", w.Code)
	}
	if got := gateMetrics(g); got != "" {
		t.Fatalf("unauthorized demand: %s", got)
	}
	if r.Header.Get(tsjwt.DefaultHeader) != "" {
		t.Fatal("assertion not stripped")
	}
}
func TestWaitGateDeadlineReturns503WithoutForwarding(t *testing.T) {
	g := waitGate(t, func(ctx context.Context, _ *url.URL) error { <-ctx.Done(); return ctx.Err() }, 1)
	u, _ := url.Parse("http://app.test")
	p, err := proxy.New(proxy.Config{Upstream: u, Audience: "app", Signer: dynamicSigner(t), Gate: g})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("POST", "/", nil).WithContext(ctx))
	if w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("response %d %v", w.Code, w.Header())
	}
	awaitMetric(t, g, "tsjwt_backend_pending_requests{upstream=\"http://app.test\"} 0")
}

func TestWaitGateSharesReadinessCheck(t *testing.T) {
	var probes atomic.Int32
	ready := make(chan struct{})
	g := waitGate(t, func(ctx context.Context, _ *url.URL) error {
		probes.Add(1)
		select {
		case <-ready:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, 32)
	u, _ := url.Parse("http://app.test")
	results := make(chan error, 32)
	for i := 0; i < 32; i++ {
		go func() {
			release, err := g.Acquire(context.Background(), proxy.Route{Upstream: u})
			if err == nil {
				release()
			}
			results <- err
		}()
	}
	awaitMetric(t, g, "tsjwt_backend_pending_requests{upstream=\"http://app.test\"} 32")
	if probes.Load() != 1 {
		t.Fatalf("readiness probes %d, want one", probes.Load())
	}
	close(ready)
	for i := 0; i < 32; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	awaitMetric(t, g, "tsjwt_backend_active_requests{upstream=\"http://app.test\"} 0")
}

func TestWaitGateBoundsMetricCardinality(t *testing.T) {
	g := waitGate(t, func(context.Context, *url.URL) error { return nil }, 1)
	for _, host := range []string{"one.test", "two.test", "three.test"} {
		u, _ := url.Parse("http://" + host)
		release, err := g.Acquire(context.Background(), proxy.Route{Upstream: u})
		if host == "three.test" {
			if err == nil {
				release()
				t.Fatal("backend limit not enforced")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			release()
		}
	}
	if strings.Contains(gateMetrics(g), "three.test") {
		t.Fatal("unbounded metrics")
	}
}

type gateFunc func(context.Context, proxy.Route) (func(), error)

func (f gateFunc) Acquire(ctx context.Context, r proxy.Route) (func(), error) { return f(ctx, r) }

func TestProxyReauthorizesAfterWaiting(t *testing.T) {
	identity := &FakeIdentitySource{identity: tsjwt.Identity{Subject: "user"}}
	set, _ := keys.NewSet()
	sg, _ := signer.New(signer.Config{Issuer: "https://test", Keys: set, Identities: identity, Tenants: tsjwt.StaticGrant(tsjwt.Grant{Tenants: []tsjwt.Tenant{{ID: "acme", Roles: []string{"admin"}}}, Default: "acme"})})
	released := false
	u, _ := url.Parse("http://app.test")
	p, err := proxy.New(proxy.Config{Upstream: u, Audience: "app", Signer: sg, Gate: gateFunc(func(context.Context, proxy.Route) (func(), error) {
		identity.err = tsjwt.ErrNoIdentity
		return func() { released = true }, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 401 || !released {
		t.Fatalf("status %d released %v", w.Code, released)
	}
}

func TestProxyMintsFreshAssertionAfterColdStart(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	set, _ := keys.NewSet()
	sg, _ := signer.New(signer.Config{Issuer: "https://test", Keys: set, Identities: &FakeIdentitySource{identity: tsjwt.Identity{Subject: "user"}}, Tenants: tsjwt.StaticGrant(tsjwt.Grant{Tenants: []tsjwt.Tenant{{ID: "acme", Roles: []string{"admin"}}}, Default: "acme"}), Now: func() time.Time { return now }})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, _ := verifier.New(verifier.Config{Issuer: "https://test", Audience: "app", Keys: verifier.LocalKeys{Set: set}, Now: func() time.Time { return now }})
		claims, err := v.Verify(r.Context(), r.Header.Get(tsjwt.DefaultHeader))
		if err != nil || claims.IssuedAt != now.Unix() {
			t.Errorf("stale assertion: %v, issued %d", err, claims.IssuedAt)
		}
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	p, err := proxy.New(proxy.Config{Upstream: u, Audience: "app", Signer: sg, Gate: gateFunc(func(context.Context, proxy.Route) (func(), error) {
		now = now.Add(6 * time.Minute)
		return func() {}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 {
		t.Fatalf("response %d", w.Code)
	}
}

func TestProxyCountsDemandUntilStreamingResponseEnds(t *testing.T) {
	started := make(chan struct{})
	finish := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-finish
		w.Write([]byte("finished"))
	}))
	defer backend.Close()
	g := waitGate(t, func(context.Context, *url.URL) error { return nil }, 1)
	u, _ := url.Parse(backend.URL)
	p, err := proxy.New(proxy.Config{Upstream: u, Audience: "app", Signer: dynamicSigner(t), Gate: g})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)) }()
	<-started
	metrics := gateMetrics(g)
	close(finish)
	<-done
	if !strings.Contains(metrics, "tsjwt_backend_active_requests{upstream="+`"`+backend.URL+`"} 1`) {
		t.Fatalf("stream not counted: %s", metrics)
	}
	awaitMetric(t, g, "tsjwt_backend_active_requests{upstream="+`"`+backend.URL+`"} 0`)
}
