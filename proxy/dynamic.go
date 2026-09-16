package proxy

import (
	"net/http"
	"sync/atomic"
)

// Dynamic serves requests through a proxy whose routes can be replaced while
// it is running.
//
// Rebuilding the proxy is cheap but replacing the process is not: this one is
// a node on a private network, and restarting it drops that node. So a route
// change swaps a pointer, and requests already in flight finish against the
// table they started on.
type Dynamic struct {
	cfg     Config
	current atomic.Pointer[Proxy]
}

// NewDynamic returns a proxy that starts with routes and can be given more
// later. cfg must not set Router or Upstream; the routes come from Set.
func NewDynamic(cfg Config, routes []Route) (*Dynamic, error) {
	d := &Dynamic{cfg: cfg}
	if err := d.Set(routes); err != nil {
		return nil, err
	}
	return d, nil
}

// Set replaces the route table.
//
// An invalid table is refused and the previous one stays in place. That is
// the important half: a bad edit to an HTTPRoute must not empty the table of
// every other route on the same Gateway.
func (d *Dynamic) Set(routes []Route) error {
	cfg := d.cfg
	cfg.Router = nil
	cfg.Upstream = nil

	if len(routes) == 0 {
		// A Gateway with no usable route should refuse requests rather
		// than keep serving a table nobody can see any more.
		cfg.Router = nil
		d.current.Store(nil)
		return nil
	}
	router, err := NewRouter(routes...)
	if err != nil {
		return err
	}
	cfg.Router = router
	p, err := New(cfg)
	if err != nil {
		return err
	}
	d.current.Store(p)
	return nil
}

// Routes returns the table currently served.
func (d *Dynamic) Routes() []Route {
	p := d.current.Load()
	if p == nil {
		return nil
	}
	return p.Router().Routes()
}

// ServeHTTP implements [http.Handler].
func (d *Dynamic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := d.current.Load()
	if p == nil {
		// No routes at all. This is 503 rather than 404: the Gateway
		// exists and is simply not configured yet, and a caller should
		// retry rather than conclude the path is wrong.
		http.Error(w, "no routes configured", http.StatusServiceUnavailable)
		return
	}
	p.ServeHTTP(w, r)
}
