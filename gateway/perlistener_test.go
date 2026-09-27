package gateway_test

import (
	"strings"
	"testing"

	"github.com/bitcomplete/tsjwt/gateway"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

// allowedRoutes must be evaluated per matching listener, not per Gateway. On a
// Gateway with an open listener (From=All) and a strict one (From=Same) that own
// different hostnames, a route from another namespace is admitted only by the
// open listener and so may serve only the open listener's hostname — it must not
// borrow the strict listener's hostname.
//
// Regression for adversarial finding B (per-listener allowedRoutes).
func TestAllowedRoutesEvaluatedPerListener(t *testing.T) {
	t.Parallel()
	all := gwapi.NamespacesFromAll
	same := gwapi.NamespacesFromSame
	g := &gwapi.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "infra"}}
	g.Spec.Listeners = []gwapi.Listener{
		{
			Name: "open", Port: 443, Protocol: gwapi.HTTPSProtocolType,
			Hostname:      ptr(gwapi.Hostname("open.example")),
			AllowedRoutes: &gwapi.AllowedRoutes{Namespaces: &gwapi.RouteNamespaces{From: &all}},
		},
		{
			Name: "strict", Port: 443, Protocol: gwapi.HTTPSProtocolType,
			Hostname:      ptr(gwapi.Hostname("strict.example")),
			AllowedRoutes: &gwapi.AllowedRoutes{Namespaces: &gwapi.RouteNamespaces{From: &same}},
		},
	}

	// A foreign-namespace route may attach (the open listener is From=All), but
	// requesting the strict listener's hostname must not be served.
	foreignStrict := route("gstrict", "other", "edge", []string{"strict.example"}, rule("guest-svc", 80, "/"))
	foreignStrict.Spec.ParentRefs[0].Namespace = ptr(gwapi.Namespace("infra"))
	foreignOpen := route("gopen", "other", "edge", []string{"open.example"}, rule("guest-svc", 80, "/"))
	foreignOpen.Spec.ParentRefs[0].Namespace = ptr(gwapi.Namespace("infra"))
	localStrict := route("lstrict", "infra", "edge", []string{"strict.example"}, rule("app-svc", 80, "/"))

	svcs := []corev1.Service{svc("guest-svc", "other", 80), svc("app-svc", "infra", 80)}
	got, _ := gateway.Translate(g, []gwapi.HTTPRoute{foreignStrict, foreignOpen, localStrict}, svcs)

	var openServed, localServed bool
	for _, r := range got {
		switch {
		case strings.HasPrefix(r.Name, "other/gstrict"):
			t.Errorf("foreign-namespace route served strict.example, which only a From=Same listener owns: %s", r.Name)
		case strings.HasPrefix(r.Name, "other/gopen"):
			openServed = true
		case strings.HasPrefix(r.Name, "infra/lstrict"):
			localServed = true
		}
	}
	if !openServed {
		t.Error("foreign route on the From=All listener's hostname should be served")
	}
	if !localServed {
		t.Error("same-namespace route on the From=Same listener's hostname should be served")
	}
}
