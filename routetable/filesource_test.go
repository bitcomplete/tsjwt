package routetable_test

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/routetable"
)

func writeTable(t *testing.T, path string, rev int64, names ...string) {
	t.Helper()
	up, _ := url.Parse("http://backend.ns.svc:80")
	var routes []proxy.Route
	for _, n := range names {
		routes = append(routes, proxy.Route{Name: n, Upstream: up, Audience: n})
	}
	if err := routetable.WriteRouteFile(path, routetable.Render("infra/edge", rev, routes)); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestFileSourceKeepsTableWhenFileGoesAway is the fail-open property while
// running: an unreadable mount must not empty the table.
func TestFileSourceKeepsTableWhenFileGoesAway(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	writeTable(t, path, 1, "a", "b")

	s := &routetable.FileSource{Path: path}
	if err := s.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(s.Routes()) != 2 {
		t.Fatalf("got %d routes, want 2", len(s.Routes()))
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := s.Refresh(); err == nil {
		t.Fatal("reading a missing file must report an error")
	}
	if len(s.Routes()) != 2 {
		t.Fatalf("table emptied when the file went away: %d routes", len(s.Routes()))
	}
}

// TestFileSourceRejectsAPartialTable checks a corrupt entry does not apply
// half a table. A partially applied table answers 404 for routes that exist,
// which reads as a routing decision rather than a failure.
func TestFileSourceRejectsAPartialTable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	writeTable(t, path, 1, "a", "b")

	s := &routetable.FileSource{Path: path}
	if err := s.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// One good entry, one with no audience.
	bad := `{"revision":2,"gateway":"infra/edge","routes":[
	  {"name":"ok","upstream":"http://x.y.svc:80","audience":"ok"},
	  {"name":"broken","upstream":"http://x.y.svc:80"}]}`
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.Refresh(); err == nil {
		t.Fatal("a table with a bad entry must be refused whole")
	}
	got := s.Routes()
	if len(got) != 2 || got[0].Name != "a" {
		t.Fatalf("the previous table must survive, got %v", got)
	}
}

// TestFileSourceFailsOpenAcrossRestart is the property the cache exists for:
// a process that restarts while the mount is unreadable serves the routes it
// last had, instead of refusing everything.
func TestFileSourceFailsOpenAcrossRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cache := filepath.Join(dir, "cache", "routes.json")
	writeTable(t, path, 7, "a", "b")

	first := &routetable.FileSource{Path: path, CachePath: cache}
	if err := first.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// The mount becomes unreadable, and the process restarts.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	second := &routetable.FileSource{Path: path, CachePath: cache}
	if err := second.LoadCache(); err != nil {
		t.Fatalf("load cache: %v", err)
	}
	if !second.Loaded() {
		t.Fatal("a restart with an unreadable mount must load the cache")
	}
	if got := second.Routes(); len(got) != 2 {
		t.Fatalf("got %d routes from the cache, want 2", len(got))
	}
	if second.Revision() != 7 {
		t.Fatalf("revision = %d, want the cached 7", second.Revision())
	}
	if !second.ServingFromCache() {
		t.Fatal("ServingFromCache must be true, so this is alertable")
	}

	// When the mount returns, the file wins and the cache flag clears.
	writeTable(t, path, 8, "a", "b", "c")
	if err := second.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if second.ServingFromCache() {
		t.Fatal("once the file is readable again, the table is no longer from cache")
	}
	if len(second.Routes()) != 3 || second.Revision() != 8 {
		t.Fatalf("got %d routes at revision %d, want 3 at 8",
			len(second.Routes()), second.Revision())
	}
}

// TestFileSourceDoesNotCacheABadTable: caching something that failed to parse
// would poison the next restart.
func TestFileSourceDoesNotCacheABadTable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cache := filepath.Join(dir, "cache", "routes.json")

	if err := os.WriteFile(path, []byte(`{"routes":[{"name":"bad"}]}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := &routetable.FileSource{Path: path, CachePath: cache}
	if err := s.Refresh(); err == nil {
		t.Fatal("a bad table must be refused")
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatal("a table that failed to parse must not be cached")
	}
}

// TestFileSourceNoChurnOnUnchangedFile keeps a re-read that found nothing new
// from swapping the route table for no reason.
func TestFileSourceNoChurnOnUnchangedFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	writeTable(t, path, 1, "a")

	var changes int
	s := &routetable.FileSource{Path: path, OnChange: func([]proxy.Route) { changes++ }}
	for range 5 {
		if err := s.Refresh(); err != nil {
			t.Fatalf("refresh: %v", err)
		}
	}
	if changes != 1 {
		t.Fatalf("OnChange fired %d times for one table, want 1", changes)
	}
}
