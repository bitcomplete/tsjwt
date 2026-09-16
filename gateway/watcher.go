package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bitcomplete/tsjwt/proxy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

// Watcher keeps a route table in step with the HTTPRoutes attached to one
// Gateway.
//
// It belongs to the data plane rather than the controller. The alternative —
// a controller that renders a config file and restarts the proxy — makes
// every route change a restart, and a restart of this component drops the
// tailnet node. Reading the routes here means a route change is a swap of a
// pointer.
type Watcher struct {
	// Client reads Gateways, HTTPRoutes and Services. Required.
	Client client.Client

	// Gateway names the Gateway whose routes this data plane serves.
	// Required.
	Gateway types.NamespacedName

	// Interval is how often to re-read. Required to be positive.
	//
	// This polls rather than watches, deliberately. A watch needs an
	// informer, a cache and a leader election story; a poll of a handful
	// of resources every few seconds costs almost nothing and cannot get
	// stuck in a way that leaves the table silently stale.
	Interval time.Duration

	// OnChange is called with each new table. Optional.
	OnChange func([]proxy.Route)

	// Logger records rejected routes. Nil means slog.Default().
	Logger *slog.Logger

	mu      sync.RWMutex
	current []proxy.Route
	rev     atomic.Uint64
	lastErr atomic.Pointer[string]
}

// Routes returns the current table.
func (w *Watcher) Routes() []proxy.Route {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]proxy.Route, len(w.current))
	copy(out, w.current)
	return out
}

// Revision counts how many times the table has changed. A caller can use it
// to tell a genuinely new table from a re-read that found nothing new.
func (w *Watcher) Revision() uint64 { return w.rev.Load() }

// LastError returns the most recent read failure, or nil.
//
// A read failure is not the same as an empty table, and the difference
// matters: if the API server is unreachable, the right thing is to keep
// serving the routes already held, not to serve none.
func (w *Watcher) LastError() *string { return w.lastErr.Load() }

// Refresh reads once and replaces the table.
func (w *Watcher) Refresh(ctx context.Context) error {
	log := w.Logger
	if log == nil {
		log = slog.Default()
	}

	var gw gwapi.Gateway
	if err := w.Client.Get(ctx, w.Gateway, &gw); err != nil {
		return fmt.Errorf("gateway %s: %w", w.Gateway, err)
	}

	var routes gwapi.HTTPRouteList
	if err := w.Client.List(ctx, &routes); err != nil {
		return fmt.Errorf("list HTTPRoutes: %w", err)
	}
	var services corev1.ServiceList
	if err := w.Client.List(ctx, &services); err != nil {
		return fmt.Errorf("list Services: %w", err)
	}

	table, errs := Translate(&gw, routes.Items, services.Items)
	for _, e := range errs {
		// Every rejection is logged. A route that is silently dropped
		// looks accepted to whoever wrote it, which is the worst way for
		// this to fail.
		log.Warn("route rejected", "route", e.Route, "reason", string(e.Reason), "detail", e.Detail)
	}

	w.mu.Lock()
	changed := !sameTable(w.current, table)
	if changed {
		w.current = table
	}
	w.mu.Unlock()

	if changed {
		w.rev.Add(1)
		log.Info("route table updated", "routes", len(table), "rejected", len(errs),
			"revision", w.rev.Load())
		if w.OnChange != nil {
			w.OnChange(table)
		}
	}
	return nil
}

// Run refreshes until ctx ends. A failed read leaves the previous table in
// place rather than emptying it, because losing the API server should not
// take the data plane down with it.
func (w *Watcher) Run(ctx context.Context) {
	log := w.Logger
	if log == nil {
		log = slog.Default()
	}
	interval := w.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}

	refresh := func() {
		if err := w.Refresh(ctx); err != nil {
			msg := err.Error()
			w.lastErr.Store(&msg)
			log.Error("reading routes failed; keeping the table already held",
				"err", err, "routes", len(w.Routes()))
			return
		}
		w.lastErr.Store(nil)
	}
	refresh()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		}
	}
}

// sameTable compares two tables by the fields that affect behaviour.
func sameTable(a, b []proxy.Route) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name ||
			a[i].PathPrefix != b[i].PathPrefix ||
			a[i].Audience != b[i].Audience ||
			a[i].Tenant != b[i].Tenant ||
			a[i].Upstream.String() != b[i].Upstream.String() ||
			len(a[i].Hostnames) != len(b[i].Hostnames) {
			return false
		}
		for j := range a[i].Hostnames {
			if a[i].Hostnames[j] != b[i].Hostnames[j] {
				return false
			}
		}
	}
	return true
}
