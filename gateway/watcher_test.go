package gateway_test

import (
	"context"
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt/gateway"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := gwapi.Install(s); err != nil {
		t.Fatalf("gateway scheme: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("core scheme: %v", err)
	}
	return s
}

func newWatcher(t *testing.T, objs ...client.Object) *gateway.Watcher {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
	return &gateway.Watcher{
		Client:  c,
		Gateway: types.NamespacedName{Namespace: "infra", Name: "edge"},
	}
}

// TestWatcherBuildsATable is the base case: routes in the cluster become
// routes in the proxy.
func TestWatcherBuildsATable(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra", "app.ts.net")
	r := route("app", "infra", "edge", []string{"app.ts.net"}, rule("app-svc", 80))
	s := svc("app-svc", "infra", 80)

	w := newWatcher(t, g, &r, &s)
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	got := w.Routes()
	if len(got) != 1 {
		t.Fatalf("got %d routes, want 1", len(got))
	}
	if got[0].Audience != "app-svc.infra" {
		t.Fatalf("audience = %q", got[0].Audience)
	}
	if w.Revision() != 1 {
		t.Fatalf("revision = %d, want 1", w.Revision())
	}
}

// TestWatcherOnlyBumpsRevisionOnChange keeps a re-read that found nothing new
// from churning the proxy. Rebuilding on every poll would swap the route
// table several times a minute for no reason.
func TestWatcherOnlyBumpsRevisionOnChange(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra", "app.ts.net")
	r := route("app", "infra", "edge", []string{"app.ts.net"}, rule("app-svc", 80))
	s := svc("app-svc", "infra", 80)

	w := newWatcher(t, g, &r, &s)
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	first := w.Revision()
	for range 3 {
		if err := w.Refresh(context.Background()); err != nil {
			t.Fatalf("refresh: %v", err)
		}
	}
	if w.Revision() != first {
		t.Fatalf("revision moved from %d to %d without the cluster changing",
			first, w.Revision())
	}
}

// TestWatcherKeepsTableWhenReadFails is the property that decides whether
// losing the API server takes the data plane with it. It must not: the routes
// already held are still correct.
func TestWatcherKeepsTableWhenReadFails(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra", "app.ts.net")
	r := route("app", "infra", "edge", []string{"app.ts.net"}, rule("app-svc", 80))
	s := svc("app-svc", "infra", 80)

	w := newWatcher(t, g, &r, &s)
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	before := w.Routes()

	// Point at a Gateway that does not exist, which is what a read
	// failure looks like from here.
	w.Gateway = types.NamespacedName{Namespace: "infra", Name: "gone"}
	if err := w.Refresh(context.Background()); err == nil {
		t.Fatal("reading a missing Gateway must fail")
	}
	after := w.Routes()
	if len(after) != len(before) {
		t.Fatalf("table changed on a failed read: %d routes became %d",
			len(before), len(after))
	}
}

// TestWatcherRunStops checks the loop honours cancellation.
func TestWatcherRunStops(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra", "app.ts.net")
	w := newWatcher(t, g)
	w.Interval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop when its context was cancelled")
	}
}
