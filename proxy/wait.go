package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RequestGate holds an authorized request until its backend is available.
// Acquire must publish demand before waiting. The returned release function
// tracks demand through the entire response, including upgraded connections.
// On failure Acquire must clean up its own demand.
type RequestGate interface {
	Acquire(context.Context, Route) (release func(), err error)
}

// WaitConfig configures a bounded gate. It does not change replica counts.
type WaitConfig struct {
	Timeout     time.Duration
	Interval    time.Duration
	MaxPending  int
	MaxBackends int
	// Ready checks a trusted, configured upstream without sending the user's
	// request. Nil checks TCP connectivity to the upstream Service. Kubernetes
	// Services must publish only ready endpoints; custom deployments can supply
	// an application readiness check instead.
	Ready func(context.Context, *url.URL) error
}

type demand struct {
	pending, active int
	lastActivity    time.Time
	checking        bool
	changed         chan struct{}
	cancel          context.CancelFunc
}

// WaitGate shares readiness checks per upstream and exports demand in
// Prometheus text format. Share one instance across dynamic route reloads.
// Entries are retained to export explicit idle zeros; MaxBackends bounds
// cardinality and new backends fail closed once the limit is reached.
type WaitGate struct {
	cfg      WaitConfig
	mu       sync.Mutex
	backends map[string]*demand
}

func NewWaitGate(cfg WaitConfig) (*WaitGate, error) {
	if cfg.Timeout <= 0 || cfg.Interval <= 0 || cfg.MaxPending <= 0 || cfg.MaxBackends <= 0 {
		return nil, fmt.Errorf("wait gate: timeout, interval and limits must be positive")
	}
	if cfg.Ready == nil {
		cfg.Ready = tcpReady
	}
	return &WaitGate{cfg: cfg, backends: make(map[string]*demand)}, nil
}

func tcpReady(ctx context.Context, u *url.URL) error {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err == nil {
		c.Close()
	}
	return err
}

func (g *WaitGate) Acquire(ctx context.Context, r Route) (func(), error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := r.Upstream.String()
	g.mu.Lock()
	d := g.backends[key]
	if d == nil {
		if len(g.backends) >= g.cfg.MaxBackends {
			g.mu.Unlock()
			return nil, fmt.Errorf("wait gate: backend limit")
		}
		d = &demand{}
		g.backends[key] = d
	}
	if d.pending >= g.cfg.MaxPending {
		g.mu.Unlock()
		return nil, fmt.Errorf("wait gate: pending limit")
	}
	d.pending++
	d.lastActivity = time.Now()
	if !d.checking {
		probeCtx, stop := context.WithCancel(context.Background())
		d.checking, d.changed, d.cancel = true, make(chan struct{}), stop
		go g.check(probeCtx, r.Upstream, d, d.changed)
	}
	ready := d.changed
	g.mu.Unlock()
	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-ready:
		err = ctx.Err()
	}
	g.mu.Lock()
	d.pending--
	if d.pending == 0 && d.checking {
		d.cancel()
		d.checking = false
	}
	if err == nil {
		d.active++
	}
	d.lastActivity = time.Now()
	g.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			d.active--
			d.lastActivity = time.Now()
			g.mu.Unlock()
		})
	}, nil
}

func (g *WaitGate) check(ctx context.Context, u *url.URL, d *demand, ready chan struct{}) {
	for {
		probeCtx, cancel := context.WithTimeout(ctx, time.Second)
		err := g.cfg.Ready(probeCtx, u)
		cancel()
		if err == nil {
			g.mu.Lock()
			// A cancelled generation must never signal a newer batch of requests.
			if d.checking && d.changed == ready {
				close(ready)
				d.checking = false
				d.cancel()
			}
			g.mu.Unlock()
			return
		}
		timer := time.NewTimer(g.cfg.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// ServeHTTP exposes only configured upstream labels, never caller-controlled
// paths or host headers. Scrape on the internal operations listener.
func (g *WaitGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var out strings.Builder
	g.mu.Lock()
	for key, d := range g.backends {
		label := strconv.Quote(key)
		fmt.Fprintf(&out, "tsjwt_backend_pending_requests{upstream=%s} %d\n", label, d.pending)
		fmt.Fprintf(&out, "tsjwt_backend_active_requests{upstream=%s} %d\n", label, d.active)
		fmt.Fprintf(&out, "tsjwt_backend_last_activity_seconds{upstream=%s} %d\n", label, d.lastActivity.Unix())
	}
	g.mu.Unlock()
	// Never hold the demand lock while writing to a potentially slow scraper.
	fmt.Fprint(w, out.String())
}
