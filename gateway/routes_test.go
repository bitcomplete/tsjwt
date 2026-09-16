package gateway_test

import (
	"strings"
	"testing"

	"github.com/bitcomplete/tsjwt/gateway"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

func ptr[T any](v T) *T { return &v }

func gw(name, ns string, hostnames ...string) *gwapi.Gateway {
	g := &gwapi.Gateway{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	if len(hostnames) == 0 {
		g.Spec.Listeners = []gwapi.Listener{{Name: "https", Port: 443, Protocol: gwapi.HTTPSProtocolType}}
		return g
	}
	for i, h := range hostnames {
		g.Spec.Listeners = append(g.Spec.Listeners, gwapi.Listener{
			Name:     gwapi.SectionName(string(rune('a' + i))),
			Port:     443,
			Protocol: gwapi.HTTPSProtocolType,
			Hostname: ptr(gwapi.Hostname(h)),
		})
	}
	return g
}

func svc(name, ns string, port int32) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: port}}},
	}
}

func route(name, ns, parent string, hostnames []string, rules ...gwapi.HTTPRouteRule) gwapi.HTTPRoute {
	r := gwapi.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	r.Spec.ParentRefs = []gwapi.ParentReference{{Name: gwapi.ObjectName(parent)}}
	for _, h := range hostnames {
		r.Spec.Hostnames = append(r.Spec.Hostnames, gwapi.Hostname(h))
	}
	r.Spec.Rules = rules
	return r
}

func rule(svcName string, port int32, prefixes ...string) gwapi.HTTPRouteRule {
	r := gwapi.HTTPRouteRule{
		BackendRefs: []gwapi.HTTPBackendRef{{BackendRef: gwapi.BackendRef{
			BackendObjectReference: gwapi.BackendObjectReference{
				Name: gwapi.ObjectName(svcName), Port: ptr(gwapi.PortNumber(port)),
			}}}},
	}
	for _, p := range prefixes {
		r.Matches = append(r.Matches, gwapi.HTTPRouteMatch{
			Path: &gwapi.HTTPPathMatch{
				Type:  ptr(gwapi.PathMatchPathPrefix),
				Value: ptr(p),
			}})
	}
	return r
}

// TestAudienceIsPerBackend is the property that makes one Gateway safe in
// front of many services: a token minted for one must not be accepted by
// another.
func TestAudienceIsPerBackend(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra", "grafana.ts.net", "bithub.ts.net")
	routes := []gwapi.HTTPRoute{
		route("grafana", "infra", "edge", []string{"grafana.ts.net"}, rule("grafana-svc", 80)),
		route("bithub", "infra", "edge", []string{"bithub.ts.net"}, rule("bithub-svc", 3000)),
	}
	services := []corev1.Service{svc("grafana-svc", "infra", 80), svc("bithub-svc", "infra", 3000)}

	got, errs := gateway.Translate(g, routes, services)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(got) != 2 {
		t.Fatalf("got %d routes, want 2", len(got))
	}
	auds := map[string]string{}
	for _, r := range got {
		auds[r.Hostnames[0]] = r.Audience
	}
	for host, want := range map[string]string{
		"grafana.ts.net": "grafana-svc.infra",
		"bithub.ts.net":  "bithub-svc.infra",
	} {
		if auds[host] != want {
			t.Fatalf("%s got audience %q, want %q", host, auds[host], want)
		}
	}
	if auds["grafana.ts.net"] == auds["bithub.ts.net"] {
		t.Fatal("two backends share an audience; a token for one would work at the other")
	}
}

// TestRejectsMultipleBackends covers the case that would otherwise mint a
// token whose audience depends on which backend a request landed on.
func TestRejectsMultipleBackends(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra")
	r := route("split", "infra", "edge", nil, rule("a-svc", 80))
	r.Spec.Rules[0].BackendRefs = append(r.Spec.Rules[0].BackendRefs,
		gwapi.HTTPBackendRef{BackendRef: gwapi.BackendRef{
			BackendObjectReference: gwapi.BackendObjectReference{
				Name: "b-svc", Port: ptr(gwapi.PortNumber(80))}}})

	got, errs := gateway.Translate(g, []gwapi.HTTPRoute{r},
		[]corev1.Service{svc("a-svc", "infra", 80), svc("b-svc", "infra", 80)})
	if len(got) != 0 {
		t.Fatalf("a split backend must produce no route, got %d", len(got))
	}
	if len(errs) != 1 || errs[0].Reason != gwapi.RouteReasonUnsupportedValue {
		t.Fatalf("want one UnsupportedValue error, got %v", errs)
	}
}

// TestOneBadRuleDoesNotBreakOthers pins Gateway API's rule that a rejected
// route is reported on its own status and does not invalidate its siblings.
func TestOneBadRuleDoesNotBreakOthers(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra")
	routes := []gwapi.HTTPRoute{
		route("good", "infra", "edge", nil, rule("good-svc", 80)),
		route("missing", "infra", "edge", nil, rule("absent-svc", 80)),
	}
	got, errs := gateway.Translate(g, routes, []corev1.Service{svc("good-svc", "infra", 80)})
	if len(got) != 1 {
		t.Fatalf("the good route must survive, got %d routes", len(got))
	}
	if len(errs) != 1 || errs[0].Reason != gwapi.RouteReasonBackendNotFound {
		t.Fatalf("want one BackendNotFound, got %v", errs)
	}
}

// TestHostnameIntersection checks that a route may only answer for names the
// Gateway actually serves.
func TestHostnameIntersection(t *testing.T) {
	t.Parallel()
	services := []corev1.Service{svc("app", "infra", 80)}
	for _, tc := range []struct {
		name     string
		listener []string
		routeHN  []string
		want     []string
		wantErr  bool
	}{
		{"wildcard listener narrows to the route", []string{"*.ts.net"},
			[]string{"app.ts.net"}, []string{"app.ts.net"}, false},
		{"route wildcard narrows to the listener", []string{"app.ts.net"},
			[]string{"*.ts.net"}, []string{"app.ts.net"}, false},
		{"exact match", []string{"app.ts.net"}, []string{"app.ts.net"}, []string{"app.ts.net"}, false},
		{"no overlap is refused", []string{"app.ts.net"}, []string{"other.example.com"}, nil, true},
		{"listener only", []string{"app.ts.net"}, nil, []string{"app.ts.net"}, false},
		{"route only", nil, []string{"app.ts.net"}, []string{"app.ts.net"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gw("edge", "infra", tc.listener...)
			r := route("r", "infra", "edge", tc.routeHN, rule("app", 80))
			got, errs := gateway.Translate(g, []gwapi.HTTPRoute{r}, services)
			if tc.wantErr {
				if len(errs) == 0 {
					t.Fatalf("expected a rejection, got routes %v", got)
				}
				return
			}
			if len(errs) != 0 {
				t.Fatalf("unexpected errors: %v", errs)
			}
			if len(got) != 1 {
				t.Fatalf("got %d routes, want 1", len(got))
			}
			if len(got[0].Hostnames) != len(tc.want) || (len(tc.want) > 0 && got[0].Hostnames[0] != tc.want[0]) {
				t.Fatalf("hostnames = %v, want %v", got[0].Hostnames, tc.want)
			}
		})
	}
}

// TestUnattachedRouteIsIgnored: a route naming a different Gateway must not
// appear in this Gateway's table.
func TestUnattachedRouteIsIgnored(t *testing.T) {
	t.Parallel()
	g := gw("mine", "infra")
	r := route("theirs", "infra", "someone-else", nil, rule("app", 80))
	got, errs := gateway.Translate(g, []gwapi.HTTPRoute{r}, []corev1.Service{svc("app", "infra", 80)})
	if len(got) != 0 || len(errs) != 0 {
		t.Fatalf("a route for another Gateway must be ignored silently, got %v / %v", got, errs)
	}
}

// TestAnnotationsOverride covers the two escape hatches.
func TestAnnotationsOverride(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra")
	r := route("app", "infra", "edge", nil, rule("app-svc", 80))
	r.Annotations = map[string]string{
		gateway.AudienceAnnotation: "legacy-audience",
		gateway.TenantAnnotation:   "acme",
	}
	got, errs := gateway.Translate(g, []gwapi.HTTPRoute{r}, []corev1.Service{svc("app-svc", "infra", 80)})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if got[0].Audience != "legacy-audience" {
		t.Fatalf("audience = %q, want the annotation's value", got[0].Audience)
	}
	if got[0].Tenant != "acme" {
		t.Fatalf("tenant = %q, want acme", got[0].Tenant)
	}
}

// TestPathPrefixes checks that path matches become router prefixes, and that
// an exact match is refused rather than silently widened.
func TestPathPrefixes(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra")
	services := []corev1.Service{svc("app", "infra", 80)}

	r := route("app", "infra", "edge", nil, rule("app", 80, "/api/v2", "/api/v1"))
	got, errs := gateway.Translate(g, []gwapi.HTTPRoute{r}, services)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(got) != 2 {
		t.Fatalf("two path matches must give two routes, got %d", len(got))
	}

	exact := route("exact", "infra", "edge", nil, gwapi.HTTPRouteRule{
		Matches: []gwapi.HTTPRouteMatch{{Path: &gwapi.HTTPPathMatch{
			Type: ptr(gwapi.PathMatchExact), Value: ptr("/only")}}},
		BackendRefs: []gwapi.HTTPBackendRef{{BackendRef: gwapi.BackendRef{
			BackendObjectReference: gwapi.BackendObjectReference{
				Name: "app", Port: ptr(gwapi.PortNumber(80))}}}},
	})
	got, errs = gateway.Translate(g, []gwapi.HTTPRoute{exact}, services)
	if len(got) != 0 || len(errs) == 0 {
		t.Fatalf("an exact path match must be refused, not widened to a prefix; got %v / %v", got, errs)
	}
}

// TestFiltersAreRefusedNotIgnored covers a route asking for behaviour this
// implementation does not have.
//
// Ignoring a filter is the worst outcome available: the route is accepted,
// the status says so, and it serves something other than what was asked for.
// Refusing it says which filter and why.
func TestFiltersAreRefusedNotIgnored(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra")
	services := []corev1.Service{svc("app", "infra", 80)}

	r := route("rewrite", "infra", "edge", nil, rule("app", 80, "/api"))
	r.Spec.Rules[0].Filters = []gwapi.HTTPRouteFilter{{
		Type: gwapi.HTTPRouteFilterURLRewrite,
		URLRewrite: &gwapi.HTTPURLRewriteFilter{
			Path: &gwapi.HTTPPathModifier{
				Type:               gwapi.PrefixMatchHTTPPathModifier,
				ReplacePrefixMatch: ptr("/"),
			}}}}

	got, errs := gateway.Translate(g, []gwapi.HTTPRoute{r}, services)
	if len(got) != 0 {
		t.Fatalf("a route with an unimplemented filter must produce no route, got %d", len(got))
	}
	if len(errs) != 1 || errs[0].Reason != gwapi.RouteReasonUnsupportedValue {
		t.Fatalf("want one UnsupportedValue error naming the filter, got %v", errs)
	}
	if !strings.Contains(errs[0].Detail, "URLRewrite") {
		t.Fatalf("the error should name the filter that was refused: %q", errs[0].Detail)
	}
}
