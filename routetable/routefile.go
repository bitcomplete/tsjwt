package routetable

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/bitcomplete/tsjwt/proxy"
)

// RouteFile is the rendered route table, as the controller writes it and the
// data plane reads it.
//
// It exists so the data plane needs no access to the Kubernetes API. The
// controller resolves HTTPRoutes, Services and Gateways once and writes the
// result; the data plane reads a file. That removes an API dependency from
// the component that must keep serving when the API is unreachable, and it
// removes its RBAC entirely.
type RouteFile struct {
	// Revision increases whenever the controller writes a new table. It
	// exists for logs and for /readyz, not for correctness.
	Revision int64 `json:"revision"`

	// Gateway names the Gateway this table was rendered for, so a
	// misdirected mount is noticed rather than silently served.
	Gateway string `json:"gateway"`

	Routes []RouteEntry `json:"routes"`
}

// RouteEntry is one route in the rendered form.
type RouteEntry struct {
	Name       string   `json:"name"`
	Hostnames  []string `json:"hostnames,omitempty"`
	PathPrefix string   `json:"pathPrefix,omitempty"`
	Upstream   string   `json:"upstream"`
	Audience   string   `json:"audience"`
	Tenant     string   `json:"tenant,omitempty"`

	// ClaimHeaders writes verified claims into request headers, so a
	// backend that already reads an identity header can move behind the
	// gateway unchanged.
	ClaimHeaders map[string]string `json:"claimHeaders,omitempty"`
}

// Render turns a route table into the file form.
func Render(gateway string, revision int64, routes []proxy.Route) RouteFile {
	out := RouteFile{Revision: revision, Gateway: gateway}
	for _, r := range routes {
		out.Routes = append(out.Routes, RouteEntry{
			Name: r.Name, Hostnames: r.Hostnames, PathPrefix: r.PathPrefix,
			Upstream: r.Upstream.String(), Audience: r.Audience, Tenant: r.Tenant,
			ClaimHeaders: r.ClaimHeaders,
		})
	}
	return out
}

// Parse converts the file form back into routes.
//
// It refuses the whole file on any bad entry rather than dropping one. A
// partially applied table is worse than the previous one: a caller would get
// a confident 404 for a route that exists, which reads as a routing decision
// rather than as a failure.
func (f RouteFile) Parse() ([]proxy.Route, error) {
	out := make([]proxy.Route, 0, len(f.Routes))
	for i, e := range f.Routes {
		u, err := url.Parse(e.Upstream)
		if err != nil {
			return nil, fmt.Errorf("route %d (%s): upstream %q: %w", i, e.Name, e.Upstream, err)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("route %d (%s): upstream %q has no host", i, e.Name, e.Upstream)
		}
		r := proxy.Route{
			Name: e.Name, Hostnames: e.Hostnames, PathPrefix: e.PathPrefix,
			Upstream: u, Audience: e.Audience, Tenant: e.Tenant,
			ClaimHeaders: e.ClaimHeaders,
		}
		if err := r.Valid(); err != nil {
			return nil, fmt.Errorf("route %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// ReadRouteFile reads and parses a rendered table.
func ReadRouteFile(path string) (RouteFile, []proxy.Route, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return RouteFile{}, nil, err
	}
	var f RouteFile
	if err := json.Unmarshal(b, &f); err != nil {
		return RouteFile{}, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	routes, err := f.Parse()
	if err != nil {
		return RouteFile{}, nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, routes, nil
}

// WriteRouteFile writes a table atomically, so a reader never sees half of
// one. The controller uses this for the cache it hands to a ConfigMap, and
// the data plane uses it for its local copy.
func WriteRouteFile(path string, f RouteFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
