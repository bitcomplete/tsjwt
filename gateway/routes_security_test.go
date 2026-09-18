package gateway_test

import (
	"testing"

	"github.com/bitcomplete/tsjwt/gateway"
	corev1 "k8s.io/api/core/v1"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

// A route in another namespace that explicitly parents this Gateway must NOT
// attach when the Gateway's listeners use the default allowedRoutes policy
// (From=Same). Before the fix, attachedTo matched on parentRef name+namespace
// alone, so any namespace could bind routes to a shared Gateway and shadow a
// co-tenant's hostname.
//
// Regression for audit finding gateway/cross-namespace-attach-no-allowedroutes.
func TestCrossNamespaceAttachRejectedByDefault(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra", "victim.ts.net") // listener has no allowedRoutes => Same
	r := route("hijack", "attacker", "edge", []string{"victim.ts.net"}, rule("attacker-svc", 80, "/"))
	r.Spec.ParentRefs[0].Namespace = ptr(gwapi.Namespace("infra")) // cross-namespace parentRef

	got, errs := gateway.Translate(g, []gwapi.HTTPRoute{r},
		[]corev1.Service{svc("attacker-svc", "attacker", 80)})
	if len(got) != 0 {
		t.Fatalf("cross-namespace route attached to a Gateway with default (Same) allowedRoutes; got %d routes, want 0", len(got))
	}
	// A route the Gateway does not admit is simply not attached (no error), per
	// Gateway API; the important property is that it does not serve.
	_ = errs
}

// A listener that opts into From=All must admit a route from another namespace,
// so the fix does not over-block a Gateway that deliberately shares.
func TestAllowedRoutesAllPermitsCrossNamespace(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra", "guest.ts.net")
	g.Spec.Listeners[0].AllowedRoutes = &gwapi.AllowedRoutes{
		Namespaces: &gwapi.RouteNamespaces{From: ptr(gwapi.NamespacesFromAll)},
	}
	r := route("guest", "other", "edge", []string{"guest.ts.net"}, rule("guest-svc", 80, "/"))
	r.Spec.ParentRefs[0].Namespace = ptr(gwapi.Namespace("infra"))

	got, errs := gateway.Translate(g, []gwapi.HTTPRoute{r},
		[]corev1.Service{svc("guest-svc", "other", 80)})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(got) != 1 {
		t.Fatalf("From=All should admit a cross-namespace route; got %d routes, want 1", len(got))
	}
}

// A same-namespace route with a backendRef pointing at a Service in another
// namespace must be refused with RefNotPermitted, because no ReferenceGrant is
// evaluated. Before the fix the reference was honored verbatim, letting a route
// author borrow any Service and mint a token with that backend's audience.
//
// Regression for audit finding
// gateway/cross-namespace-backendref-no-referencegrant.
func TestCrossNamespaceBackendRefRejected(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra", "app.ts.net")
	r := route("borrow", "infra", "edge", []string{"app.ts.net"}, rule("payments", 8080, "/"))
	r.Spec.Rules[0].BackendRefs[0].Namespace = ptr(gwapi.Namespace("victim"))

	got, errs := gateway.Translate(g, []gwapi.HTTPRoute{r},
		[]corev1.Service{svc("payments", "victim", 8080)})
	if len(got) != 0 {
		t.Fatalf("cross-namespace backendRef produced %d routes, want 0", len(got))
	}
	found := false
	for _, e := range errs {
		if e.Reason == gwapi.RouteReasonRefNotPermitted {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a RefNotPermitted route error for a cross-namespace backendRef, got %v", errs)
	}
}

// An explicit same-namespace backendRef (ref.Namespace set but equal to the
// route's namespace) must still be allowed — only a differing namespace is
// refused.
func TestSameNamespaceExplicitBackendRefAllowed(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra", "app.ts.net")
	r := route("ok", "infra", "edge", []string{"app.ts.net"}, rule("app-svc", 80, "/"))
	r.Spec.Rules[0].BackendRefs[0].Namespace = ptr(gwapi.Namespace("infra"))

	got, errs := gateway.Translate(g, []gwapi.HTTPRoute{r},
		[]corev1.Service{svc("app-svc", "infra", 80)})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors for a same-namespace explicit backendRef: %v", errs)
	}
	if len(got) != 1 {
		t.Fatalf("same-namespace explicit backendRef should be allowed; got %d routes, want 1", len(got))
	}
}
