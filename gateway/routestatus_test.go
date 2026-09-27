package gateway_test

import (
	"context"
	"testing"

	"github.com/bitcomplete/tsjwt/gateway"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

// The controller must report acceptance on each attached route's own status —
// Accepted=True for a route it serves, Accepted=False with the reason for one
// it rejects — so an author sees it without reading controller logs.
//
// Regression for the missing per-HTTPRoute status conditions.
func TestReconcileWritesRouteStatus(t *testing.T) {
	t.Parallel()
	gc := gatewayClass("tsjwt", gateway.ControllerName)
	g := gatewayWithClass("edge", "infra", "tsjwt", "app.ts.net")

	good := route("good", "infra", "edge", []string{"app.ts.net"}, rule("app-svc", 80, "/"))
	// A cross-namespace backendRef is rejected with RefNotPermitted.
	bad := route("bad", "infra", "edge", []string{"app.ts.net"}, rule("payments", 8080, "/x"))
	bad.Spec.Rules[0].BackendRefs[0].Namespace = ptr(gwapi.Namespace("other"))
	s := svc("app-svc", "infra", 80)

	r, c := newReconciler(t, gc, g, &good, &bad, &s)
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "infra", Name: "edge"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	accepted := func(name string) metav1.Condition {
		t.Helper()
		var hr gwapi.HTTPRoute
		if err := c.Get(ctx, types.NamespacedName{Namespace: "infra", Name: name}, &hr); err != nil {
			t.Fatalf("get route %s: %v", name, err)
		}
		for _, p := range hr.Status.Parents {
			if string(p.ControllerName) != gateway.ControllerName {
				continue
			}
			for _, cnd := range p.Conditions {
				if cnd.Type == string(gwapi.RouteConditionAccepted) {
					return cnd
				}
			}
		}
		t.Fatalf("route %s has no Accepted condition from this controller", name)
		return metav1.Condition{}
	}

	if g := accepted("good"); g.Status != metav1.ConditionTrue {
		t.Errorf("good route: Accepted=%s, want True", g.Status)
	}
	if b := accepted("bad"); b.Status != metav1.ConditionFalse ||
		b.Reason != string(gwapi.RouteReasonRefNotPermitted) {
		t.Errorf("bad route: Accepted=%s reason=%q, want False/RefNotPermitted", b.Status, b.Reason)
	}
}
