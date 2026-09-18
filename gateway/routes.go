package gateway

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/routetable"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

// AudienceAnnotation names the audience for tokens minted on a route. When
// absent the audience is derived from the backend Service, as
// "<service>.<namespace>".
//
// It is worth being deliberate about this. The audience is what stops a token
// minted for one backend being accepted by another, so it has to be stable
// and it has to differ per backend. Deriving it from the Service name gives
// both without anyone having to think about it; the annotation exists for a
// backend that already expects a particular value.
const AudienceAnnotation = "tsjwt.dev/audience"

// TenantAnnotation pins every request on a route to one tenant, whatever the
// caller asks for.
const TenantAnnotation = "tsjwt.dev/tenant"

// ClaimHeadersAnnotation writes verified claims into request headers, as a
// comma-separated list of header=claim pairs:
//
//	tsjwt.dev/claim-headers: Tailscale-User-Login=email,X-Roles=roles
//
// It exists so a backend that already trusts an identity header can move
// behind the gateway without being changed. The header then comes from an
// identity the gateway established itself, and the signed assertion travels
// beside it, so the backend can start verifying whenever it is ready.
//
// Read it as a migration path. A backend reading these headers is still
// trusting its network position; a backend verifying the assertion is not.
const ClaimHeadersAnnotation = "tsjwt.dev/claim-headers"

// RouteError explains why one rule of an HTTPRoute could not be used. It is
// reported back on the route's status rather than failing the whole table: a
// single bad rule must not take down every other route on the Gateway.
type RouteError struct {
	Route  string
	Reason gwapi.RouteConditionReason
	Detail string
}

func (e RouteError) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Route, e.Reason, e.Detail)
}

// Translate turns the HTTPRoutes attached to one Gateway into a route table.
//
// It returns every route it could build and every reason it could not build
// the rest. Partial success is the correct behaviour here: Gateway API is
// explicit that a rejected route is reported on its own status and does not
// invalidate its siblings.
func Translate(gw *gwapi.Gateway, routes []gwapi.HTTPRoute, services []corev1.Service) ([]proxy.Route, []RouteError) {
	svc := make(map[string]*corev1.Service, len(services))
	for i := range services {
		s := &services[i]
		svc[s.Namespace+"/"+s.Name] = s
	}

	var out []proxy.Route
	var errs []RouteError

	for i := range routes {
		r := &routes[i]
		if !attachedTo(gw, r) {
			continue
		}
		// An empty result and no overlap are different outcomes. Empty
		// means neither side constrains the name, so the route answers
		// for anything the Gateway receives. No overlap means the route
		// asked for names this Gateway does not serve, which is an
		// error the route must be told about.
		hostnames, ok := hostnamesFor(gw, r)
		if !ok {
			errs = append(errs, RouteError{
				Route:  r.Namespace + "/" + r.Name,
				Reason: gwapi.RouteReasonNoMatchingListenerHostname,
				Detail: "no hostname in this route overlaps a listener on the Gateway",
			})
			continue
		}

		for ri, rule := range r.Spec.Rules {
			built, err := translateRule(r, ri, rule, hostnames, svc)
			if err != nil {
				errs = append(errs, *err)
				continue
			}
			out = append(out, built...)
		}
	}

	// Declaration order decides ties in the router, so it must not depend
	// on the order the API server happened to list resources in.
	sort.SliceStable(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, errs
}

// translateRule turns one HTTPRouteRule into routes, one per path match.
func translateRule(r *gwapi.HTTPRoute, ri int, rule gwapi.HTTPRouteRule,
	hostnames []string, svc map[string]*corev1.Service) ([]proxy.Route, *RouteError) {

	name := fmt.Sprintf("%s/%s#%d", r.Namespace, r.Name, ri)

	if len(rule.BackendRefs) == 0 {
		return nil, &RouteError{name, gwapi.RouteReasonBackendNotFound,
			"the rule names no backend"}
	}
	if len(rule.BackendRefs) > 1 {
		// Weighted fan-out would mean minting a token whose audience
		// depends on which backend a request happened to land on.
		// Refusing is better than issuing a token for the wrong one.
		return nil, &RouteError{name, gwapi.RouteReasonUnsupportedValue,
			"more than one backendRef is not supported: the audience must be " +
				"decided by the backend, so a request cannot be split between two"}
	}
	ref := rule.BackendRefs[0]

	if ref.Kind != nil && *ref.Kind != "Service" {
		return nil, &RouteError{name, gwapi.RouteReasonInvalidKind,
			fmt.Sprintf("backend kind %q is not supported, only Service", *ref.Kind)}
	}
	ns := r.Namespace
	if ref.Namespace != nil && string(*ref.Namespace) != r.Namespace {
		// A cross-namespace backend reference is only legitimate when a
		// ReferenceGrant in the target namespace permits it (Gateway API).
		// This controller does not evaluate ReferenceGrants, so honouring the
		// reference would let any route borrow any Service in the cluster and
		// mint a token carrying that backend's audience. Refuse it rather than
		// silently cross the namespace boundary.
		return nil, &RouteError{name, gwapi.RouteReasonRefNotPermitted,
			fmt.Sprintf("cross-namespace backendRef to namespace %q is not permitted: "+
				"a ReferenceGrant is required and this controller does not evaluate one",
				string(*ref.Namespace))}
	}
	key := ns + "/" + string(ref.Name)
	s, ok := svc[key]
	if !ok {
		return nil, &RouteError{name, gwapi.RouteReasonBackendNotFound,
			fmt.Sprintf("Service %s does not exist", key)}
	}
	if ref.Port == nil {
		return nil, &RouteError{name, gwapi.RouteReasonUnsupportedValue,
			"the backendRef names no port"}
	}
	if !servicePortExists(s, int32(*ref.Port)) {
		return nil, &RouteError{name, gwapi.RouteReasonBackendNotFound,
			fmt.Sprintf("Service %s has no port %d", key, *ref.Port)}
	}

	upstream, err := url.Parse(fmt.Sprintf("http://%s.%s.svc:%d", s.Name, s.Namespace, *ref.Port))
	if err != nil {
		return nil, &RouteError{name, gwapi.RouteReasonUnsupportedValue, err.Error()}
	}

	audience := r.Annotations[AudienceAnnotation]
	if audience == "" {
		audience = fmt.Sprintf("%s.%s", s.Name, s.Namespace)
	}
	tenant := r.Annotations[TenantAnnotation]
	claimHeaders, err := parseClaimHeaders(r.Annotations[ClaimHeadersAnnotation])
	if err != nil {
		return nil, &RouteError{name, gwapi.RouteReasonUnsupportedValue, err.Error()}
	}

	// Filters are not implemented, and an unimplemented filter must be
	// refused rather than ignored. A route asking for a rewrite or a header
	// change and silently not getting it is worse than one that fails:
	// the author sees an accepted route serving the wrong thing.
	if len(rule.Filters) > 0 {
		kinds := make([]string, 0, len(rule.Filters))
		for _, f := range rule.Filters {
			kinds = append(kinds, string(f.Type))
		}
		return nil, &RouteError{name, gwapi.RouteReasonUnsupportedValue,
			fmt.Sprintf("filters are not implemented, and %v would be silently "+
				"ignored; give the service its own Gateway instead of rewriting "+
				"paths onto a shared one", kinds)}
	}
	for _, br := range rule.BackendRefs {
		if len(br.Filters) > 0 {
			return nil, &RouteError{name, gwapi.RouteReasonUnsupportedValue,
				"backendRef filters are not implemented and would be silently ignored"}
		}
	}

	prefixes := pathPrefixes(rule)
	if len(prefixes) == 0 {
		// Every match in the rule used a type this router cannot honour.
		// Dropping the rule silently would leave the route looking
		// accepted while serving nothing, so say so instead.
		return nil, &RouteError{name, gwapi.RouteReasonUnsupportedValue,
			"no usable path match: this router matches prefixes, so an exact " +
				"or regular-expression match is refused rather than widened"}
	}
	out := make([]proxy.Route, 0, len(prefixes))
	for pi, prefix := range prefixes {
		out = append(out, proxy.Route{
			Name:         fmt.Sprintf("%s.%d", name, pi),
			Hostnames:    hostnames,
			PathPrefix:   prefix,
			Upstream:     upstream,
			Audience:     audience,
			Tenant:       tenant,
			ClaimHeaders: claimHeaders,
		})
	}
	return out, nil
}

// pathPrefixes returns the path prefixes a rule matches. A rule with no
// matches answers for everything, which Gateway API expresses as a prefix of
// "/".
func pathPrefixes(rule gwapi.HTTPRouteRule) []string {
	if len(rule.Matches) == 0 {
		return []string{""}
	}
	var out []string
	for _, m := range rule.Matches {
		if m.Path == nil || m.Path.Value == nil {
			out = append(out, "")
			continue
		}
		switch {
		case m.Path.Type == nil, *m.Path.Type == gwapi.PathMatchPathPrefix:
			p := *m.Path.Value
			if p == "/" {
				p = ""
			}
			out = append(out, p)
		case *m.Path.Type == gwapi.PathMatchExact:
			// The router matches prefixes. An exact match is treated
			// as a prefix, which is wider than asked for, so it is
			// refused rather than quietly over-matching.
			continue
		default:
			continue
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// servicePortExists reports whether the Service exposes that port.
func servicePortExists(s *corev1.Service, port int32) bool {
	for _, p := range s.Spec.Ports {
		if p.Port == port {
			return true
		}
	}
	return false
}

// attachedTo reports whether the route names this Gateway in its parentRefs.
func attachedTo(gw *gwapi.Gateway, r *gwapi.HTTPRoute) bool {
	for _, p := range r.Spec.ParentRefs {
		if p.Kind != nil && *p.Kind != "Gateway" {
			continue
		}
		ns := r.Namespace
		if p.Namespace != nil {
			ns = string(*p.Namespace)
		}
		if string(p.Name) == gw.Name && ns == gw.Namespace {
			// Naming the Gateway is necessary but not sufficient: the
			// Gateway's listeners decide which namespaces may attach, via
			// allowedRoutes.namespaces (Gateway API, default From=Same).
			// Without this check a route in any namespace could bind to a
			// Gateway it does not own and shadow another tenant's routes.
			return listenerAllowsNamespace(gw, r.Namespace)
		}
	}
	return false
}

// listenerAllowsNamespace reports whether any of the Gateway's listeners admits
// a route from routeNS, per allowedRoutes.namespaces. The Gateway API default
// when unset is From=Same (only the Gateway's own namespace). From=Selector
// needs the route namespace's labels, which this controller does not read, so
// it fails closed until that lookup is wired in.
func listenerAllowsNamespace(gw *gwapi.Gateway, routeNS string) bool {
	for _, l := range gw.Spec.Listeners {
		from := gwapi.NamespacesFromSame
		if l.AllowedRoutes != nil && l.AllowedRoutes.Namespaces != nil && l.AllowedRoutes.Namespaces.From != nil {
			from = *l.AllowedRoutes.Namespaces.From
		}
		switch from {
		case gwapi.NamespacesFromAll:
			return true
		case gwapi.NamespacesFromSame:
			if routeNS == gw.Namespace {
				return true
			}
		case gwapi.NamespacesFromSelector:
			// Selector needs the route namespace's labels, which this
			// controller does not list; fail closed rather than guess.
		}
	}
	return false
}

// hostnamesFor intersects the route's hostnames with the Gateway's listeners,
// as Gateway API requires: a route may only answer for names the Gateway
// actually serves.
//
// The second result distinguishes the two ways the list can come back empty.
// False means the route named hostnames and none of them overlap a listener.
// True with an empty list means neither side named any, so the route answers
// for whatever reaches the Gateway.
func hostnamesFor(gw *gwapi.Gateway, r *gwapi.HTTPRoute) ([]string, bool) {
	var listener []string
	for _, l := range gw.Spec.Listeners {
		if l.Hostname != nil && *l.Hostname != "" {
			listener = append(listener, string(*l.Hostname))
		}
	}
	var route []string
	for _, h := range r.Spec.Hostnames {
		route = append(route, string(h))
	}

	switch {
	case len(listener) == 0 && len(route) == 0:
		// Neither constrains the name: answer for anything.
		return nil, true
	case len(listener) == 0:
		return route, true
	case len(route) == 0:
		return listener, true
	}

	var out []string
	for _, rh := range route {
		for _, lh := range listener {
			if h, ok := intersectHostname(rh, lh); ok {
				out = append(out, h)
			}
		}
	}
	out = dedupe(out)
	return out, len(out) > 0
}

// intersectHostname returns the narrower of two names when they overlap.
func intersectHostname(a, b string) (string, bool) {
	a, b = strings.ToLower(a), strings.ToLower(b)
	aw, bw := strings.HasPrefix(a, "*."), strings.HasPrefix(b, "*.")
	switch {
	case !aw && !bw:
		if a == b {
			return a, true
		}
	case aw && !bw:
		if strings.HasSuffix(b, strings.TrimPrefix(a, "*")) {
			return b, true
		}
	case !aw && bw:
		if strings.HasSuffix(a, strings.TrimPrefix(b, "*")) {
			return a, true
		}
	default:
		if a == b {
			return a, true
		}
		// One wildcard may contain the other, e.g. *.a.example and
		// *.example. The narrower one wins.
		if strings.HasSuffix(strings.TrimPrefix(a, "*"), strings.TrimPrefix(b, "*")) {
			return a, true
		}
		if strings.HasSuffix(strings.TrimPrefix(b, "*"), strings.TrimPrefix(a, "*")) {
			return b, true
		}
	}
	return "", false
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// routeStatusCondition builds the Accepted condition for a route.
func routeStatusCondition(gen int64, accepted bool, reason gwapi.RouteConditionReason, msg string) metav1.Condition {
	status := metav1.ConditionTrue
	if !accepted {
		status = metav1.ConditionFalse
	}
	return metav1.Condition{
		Type:               string(gwapi.RouteConditionAccepted),
		Status:             status,
		ObservedGeneration: gen,
		LastTransitionTime: metav1.Now(),
		Reason:             string(reason),
		Message:            msg,
	}
}

// RenderFor renders a translated table into the form the data plane reads.
// The controller writes this into a ConfigMap; nothing else crosses between
// the two.
func RenderFor(gateway string, revision int64, routes []proxy.Route) routetable.RouteFile {
	return routetable.Render(gateway, revision, routes)
}

// parseClaimHeaders reads the claim-headers annotation.
//
// An unknown claim name is refused rather than ignored: a header that
// silently never appears looks like the backend is at fault.
func parseClaimHeaders(v string) (map[string]string, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	known := map[string]bool{
		"sub": true, "subject": true, "email": true, "name": true,
		"node": true, "tenant": true, "tenants": true, "roles": true, "groups": true,
	}
	out := map[string]string{}
	for _, pair := range strings.Split(v, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		header, claim, ok := strings.Cut(pair, "=")
		header, claim = strings.TrimSpace(header), strings.TrimSpace(claim)
		if !ok || header == "" || claim == "" {
			return nil, fmt.Errorf("claim-headers: %q is not header=claim", pair)
		}
		if !known[claim] {
			return nil, fmt.Errorf("claim-headers: %q is not a claim that can be "+
				"written to a header", claim)
		}
		out[header] = claim
	}
	return out, nil
}
