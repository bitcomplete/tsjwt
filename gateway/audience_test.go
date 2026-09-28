package gateway_test

import (
	"testing"

	"github.com/bitcomplete/tsjwt/gateway"
	corev1 "k8s.io/api/core/v1"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

// The audience is what stops a token minted for one backend being accepted by
// another, so a route author must not be able to set it to an arbitrary value.
// A route may name its own backend's derived audience, or a custom one the
// Gateway owner authorised via tsjwt.dev/allowed-audiences; anything else is
// refused. Before the fix, any route could set any audience.
//
// Regression for the audience-annotation forgery finding.
func TestAudienceAnnotationConstrainedToAllowlist(t *testing.T) {
	t.Parallel()
	g := gw("edge", "infra", "app.ts.net")
	s := svc("app-svc", "infra", 80)

	noAnno := route("plain", "infra", "edge", []string{"app.ts.net"}, rule("app-svc", 80, "/a"))
	ownAud := route("own", "infra", "edge", []string{"app.ts.net"}, rule("app-svc", 80, "/b"))
	ownAud.Annotations = map[string]string{gateway.AudienceAnnotation: "app-svc.infra"} // == derived
	forged := route("forged", "infra", "edge", []string{"app.ts.net"}, rule("app-svc", 80, "/c"))
	forged.Annotations = map[string]string{gateway.AudienceAnnotation: "echo.tsjwt-production"} // someone else's

	got, errs := gateway.Translate(g, []gwapi.HTTPRoute{noAnno, ownAud, forged}, []corev1.Service{s})

	if len(got) != 2 {
		t.Fatalf("got %d served routes, want 2 (forged custom audience must be refused)", len(got))
	}
	for _, r := range got {
		if r.Audience != "app-svc.infra" {
			t.Errorf("route %s has audience %q, want app-svc.infra", r.Name, r.Audience)
		}
	}
	refused := false
	for _, e := range errs {
		if e.Reason == gwapi.RouteReasonUnsupportedValue {
			refused = true
		}
	}
	if !refused {
		t.Fatalf("a route forging a custom audience was not refused; errs=%v", errs)
	}

	// Once the Gateway owner authorises a custom audience, routes may share it.
	g.Annotations = map[string]string{gateway.AllowedAudiencesAnnotation: "shared.aud, other.aud"}
	a := route("a", "infra", "edge", []string{"app.ts.net"}, rule("app-svc", 80, "/a"))
	a.Annotations = map[string]string{gateway.AudienceAnnotation: "shared.aud"}
	b := route("b", "infra", "edge", []string{"app.ts.net"}, rule("app-svc", 80, "/b"))
	b.Annotations = map[string]string{gateway.AudienceAnnotation: "shared.aud"}

	got2, errs2 := gateway.Translate(g, []gwapi.HTTPRoute{a, b}, []corev1.Service{s})
	if len(errs2) != 0 {
		t.Fatalf("allowlisted custom audience refused: %v", errs2)
	}
	if len(got2) != 2 {
		t.Fatalf("got %d served routes, want 2", len(got2))
	}
	for _, r := range got2 {
		if r.Audience != "shared.aud" {
			t.Errorf("route %s has audience %q, want shared.aud", r.Name, r.Audience)
		}
	}
}
