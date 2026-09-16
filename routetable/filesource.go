package routetable

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bitcomplete/tsjwt/proxy"
)

// FileSource serves the route table from a file the controller renders,
// normally a mounted ConfigMap.
//
// The data plane needs no access to the Kubernetes API this way. That matters
// most exactly when the API is unavailable: a component whose job is to keep
// serving should not have a hard dependency on the thing most likely to be
// down during an incident.
//
// It fails open in both directions that matter. While running, an unreadable
// or invalid file leaves the table already in use untouched. Across a
// restart, the last table that parsed is reloaded from a local cache, so a
// process that restarts during an outage serves the routes it had rather than
// refusing everything.
type FileSource struct {
	// Path is the rendered table, normally inside a mounted ConfigMap.
	// Required.
	Path string

	// CachePath is where the last table that parsed is kept, so it
	// survives a restart. It should be on persistent storage. Empty
	// disables the cache, and with it the fail-open behaviour across
	// restarts.
	CachePath string

	// Interval is how often to re-read. Default 5s.
	//
	// Polling suits a mounted ConfigMap: the kubelet updates the mount on
	// its own schedule, so there is no event to subscribe to anyway.
	Interval time.Duration

	// OnChange is called with each new table. Optional.
	OnChange func([]proxy.Route)

	// Logger is nil for slog.Default().
	Logger *slog.Logger

	mu       sync.RWMutex
	current  []proxy.Route
	rev      atomic.Int64
	loaded   atomic.Bool
	fromCach atomic.Bool
	lastErr  atomic.Pointer[string]
}

// Routes returns the table in use.
func (s *FileSource) Routes() []proxy.Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]proxy.Route, len(s.current))
	copy(out, s.current)
	return out
}

// Revision is the revision of the table in use, as the controller numbered
// it. Zero means nothing has loaded.
func (s *FileSource) Revision() int64 { return s.rev.Load() }

// Loaded reports whether any table has ever loaded, from the file or the
// cache. It is what readiness should be based on.
func (s *FileSource) Loaded() bool { return s.loaded.Load() }

// ServingFromCache reports whether the table in use came from the local cache
// rather than the file. It is worth alerting on: the routes are usable but
// they are not known to be current.
func (s *FileSource) ServingFromCache() bool { return s.fromCach.Load() }

// LastError is the most recent read failure, or nil.
func (s *FileSource) LastError() *string { return s.lastErr.Load() }

func (s *FileSource) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// LoadCache restores the last table that parsed. The data plane calls this at
// startup, before the first read, so that an unreadable mount does not mean
// an empty table.
func (s *FileSource) LoadCache() error {
	if s.CachePath == "" {
		return nil
	}
	f, routes, err := ReadRouteFile(s.CachePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // nothing cached yet, which is normal on a first start
		}
		return err
	}
	s.mu.Lock()
	s.current = routes
	s.mu.Unlock()
	s.rev.Store(f.Revision)
	s.loaded.Store(true)
	s.fromCach.Store(true)
	s.log().Warn("serving routes from the local cache until the rendered table can be read",
		"routes", len(routes), "revision", f.Revision, "cache", s.CachePath)
	return nil
}

// Refresh reads the file once.
func (s *FileSource) Refresh() error {
	f, routes, err := ReadRouteFile(s.Path)
	if err != nil {
		return err
	}

	s.mu.Lock()
	changed := !sameRoutes(s.current, routes)
	if changed {
		s.current = routes
	}
	s.mu.Unlock()

	s.rev.Store(f.Revision)
	s.loaded.Store(true)
	s.fromCach.Store(false)

	if !changed {
		return nil
	}
	s.log().Info("route table updated", "routes", len(routes), "revision", f.Revision)

	// Cache after the table is accepted, never before: caching something
	// that failed to parse would poison the next restart.
	if s.CachePath != "" {
		if err := WriteRouteFile(s.CachePath, f); err != nil {
			s.log().Error("could not cache the route table; a restart during an "+
				"outage would start with no routes", "err", err, "cache", s.CachePath)
		}
	}
	if s.OnChange != nil {
		s.OnChange(routes)
	}
	return nil
}

// Run polls until ctx ends.
func (s *FileSource) Run(ctx context.Context) {
	interval := s.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	read := func() {
		if err := s.Refresh(); err != nil {
			msg := err.Error()
			s.lastErr.Store(&msg)
			// Loud, but not fatal, and not a reason to drop routes.
			s.log().Error("could not read the rendered route table; keeping the one in use",
				"err", err, "routes", len(s.Routes()))
			return
		}
		s.lastErr.Store(nil)
	}
	read()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			read()
		}
	}
}

// sameRoutes compares tables by the fields that affect behaviour.
func sameRoutes(a, b []proxy.Route) bool {
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
