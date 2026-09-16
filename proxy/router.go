package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Route sends matching requests to one backend, under one audience.
//
// The audience is per route, and that is the point of routing here rather
// than in a layer above. A token minted for one backend must not work at
// another, so the audience has to be decided by the same thing that decides
// the backend.
type Route struct {
	// Name identifies the route in logs and errors. Optional.
	Name string

	// Hostnames this route answers for. An entry may be an exact name
	// ("app.example.ts.net") or a wildcard with a leading label
	// ("*.example.ts.net"). Empty matches any hostname.
	Hostnames []string

	// PathPrefix matches the start of the request path, on segment
	// boundaries: "/api" matches "/api" and "/api/v1" but not "/apixyz".
	// Empty matches any path.
	PathPrefix string

	// Upstream is the backend for this route. Required.
	Upstream *url.URL

	// Audience is the "aud" of tokens minted for this route. Required.
	// It should name the backend.
	Audience string

	// Tenant pins every request on this route to one tenant, ignoring what
	// the caller asks for. Empty leaves the choice to the caller, bounded
	// by what their identity holds.
	Tenant string

	// ClaimHeaders writes verified claims into request headers, as
	// header name to claim name.
	//
	// This exists so a backend that already trusts an identity header can
	// move behind the gateway without being changed. The header now comes
	// from an identity the gateway established itself, and the signed
	// assertion travels beside it, so the backend can start verifying
	// whenever it is ready.
	//
	// It is a migration path and should be read as one. A backend reading
	// these headers is still trusting its network position; a backend
	// verifying the assertion is not. Any header named here is stripped
	// from the incoming request first, exactly like the assertion.
	//
	// Claim names: sub, email, name, node, tenant, roles, groups.
	ClaimHeaders map[string]string
}

// Valid reports whether the route is usable.
func (r Route) Valid() error {
	switch {
	case r.Upstream == nil:
		return fmt.Errorf("proxy: route %q has no upstream", r.Name)
	case strings.TrimSpace(r.Audience) == "":
		return fmt.Errorf("proxy: route %q has no audience", r.Name)
	}
	for _, h := range r.Hostnames {
		if strings.HasPrefix(h, "*.") && strings.Count(h, "*") == 1 {
			continue
		}
		if strings.Contains(h, "*") {
			return fmt.Errorf("proxy: route %q: %q is not an exact name or a "+
				"leading-label wildcard", r.Name, h)
		}
	}
	if r.PathPrefix != "" && !strings.HasPrefix(r.PathPrefix, "/") {
		return fmt.Errorf("proxy: route %q: path prefix %q must start with /", r.Name, r.PathPrefix)
	}
	return nil
}

// matches reports whether the route answers for this request, and how
// specifically, so that the best match can be chosen.
func (r Route) matches(req *http.Request) (hostRank, pathLen int, ok bool) {
	host := req.Host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	// Hostname. Exact beats wildcard beats "any", following Gateway API.
	hostRank = 1
	if len(r.Hostnames) > 0 {
		hostRank = 0
		for _, h := range r.Hostnames {
			h = strings.ToLower(h)
			if h == host {
				hostRank = 3
				break
			}
			if suffix, wild := strings.CutPrefix(h, "*."); wild {
				if strings.HasSuffix(host, "."+suffix) && hostRank < 2 {
					hostRank = 2
				}
			}
		}
		if hostRank == 0 {
			return 0, 0, false
		}
	}

	// Path. A prefix matches on segment boundaries only.
	if r.PathPrefix != "" {
		p := req.URL.Path
		trimmed := strings.TrimSuffix(r.PathPrefix, "/")
		if p != trimmed && !strings.HasPrefix(p, trimmed+"/") {
			return 0, 0, false
		}
		pathLen = len(trimmed)
	}
	return hostRank, pathLen, true
}

// Router picks a route for each request.
//
// The order is Gateway API's: the most specific hostname wins, then the
// longest path prefix. Ties go to the route declared first, so a
// configuration always resolves the same way.
type Router struct {
	routes []Route
}

// NewRouter validates the routes and returns a router.
func NewRouter(routes ...Route) (*Router, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("proxy: a router needs at least one route")
	}
	out := make([]Route, len(routes))
	copy(out, routes)
	for i, r := range out {
		if err := r.Valid(); err != nil {
			return nil, err
		}
		if r.Name == "" {
			out[i].Name = fmt.Sprintf("route-%d", i)
		}
	}
	return &Router{routes: out}, nil
}

// Routes returns a copy of the configured routes, in declaration order.
func (r *Router) Routes() []Route {
	out := make([]Route, len(r.routes))
	copy(out, r.routes)
	return out
}

// Match returns the best route for a request.
func (r *Router) Match(req *http.Request) (Route, bool) {
	type scored struct {
		route          Route
		host, path, ix int
	}
	var found []scored
	for i, rt := range r.routes {
		if h, p, ok := rt.matches(req); ok {
			found = append(found, scored{rt, h, p, i})
		}
	}
	if len(found) == 0 {
		return Route{}, false
	}
	sort.SliceStable(found, func(a, b int) bool {
		if found[a].host != found[b].host {
			return found[a].host > found[b].host
		}
		if found[a].path != found[b].path {
			return found[a].path > found[b].path
		}
		return found[a].ix < found[b].ix
	})
	return found[0].route, true
}
