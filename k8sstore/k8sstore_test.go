package k8sstore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt/keys"
)

// fakeAPI stands in for the Kubernetes API server. It records what each
// request carried and serves one canned response.
type fakeAPI struct {
	mu     sync.Mutex
	auth   []string
	method []string
	path   []string
	status int
	body   string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.method = append(f.method, r.Method)
	f.path = append(f.path, r.URL.Path)
	code, body := f.status, f.body
	f.mu.Unlock()
	if code == 0 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}

func tokenFile(t *testing.T, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func storeAt(host, tokenPath string) *Store {
	return &Store{
		Name:      "tsjwt-keys",
		Namespace: "tsjwt-production",
		Host:      host,
		TokenPath: tokenPath,
		Client:    &http.Client{Timeout: 5 * time.Second},
	}
}

func cmJSON(t *testing.T, version string, entries []keys.Entry) string {
	t.Helper()
	payload, err := keys.MarshalEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"name": "tsjwt-keys", "resourceVersion": version},
		"data":     map[string]string{dataKey: string(payload)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The point of F1: the service account token is read on every request, so a
// token the kubelet rotates on disk is picked up without a restart. A store
// that cached the token at construction would send the stale one on the
// second call and fail this test.
func TestTokenIsReadFreshOnEveryRequest(t *testing.T) {
	api := &fakeAPI{status: http.StatusNotFound}
	srv := httptest.NewServer(api)
	defer srv.Close()

	tp := tokenFile(t, "token-one")
	s := storeAt(srv.URL, tp)

	if _, _, err := s.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tp, []byte("token-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(context.Background()); err != nil {
		t.Fatal(err)
	}

	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.auth) != 2 {
		t.Fatalf("saw %d requests, want 2", len(api.auth))
	}
	if api.auth[0] != "Bearer token-one" {
		t.Errorf("first request auth = %q, want the first token", api.auth[0])
	}
	if api.auth[1] != "Bearer token-two" {
		t.Errorf("second request auth = %q, want the rotated token", api.auth[1])
	}
}

// An explicit Token is used verbatim and the file is never consulted.
func TestExplicitTokenOverridesFile(t *testing.T) {
	api := &fakeAPI{status: http.StatusNotFound}
	srv := httptest.NewServer(api)
	defer srv.Close()

	s := storeAt(srv.URL, filepath.Join(t.TempDir(), "does-not-exist"))
	s.Token = "fixed-token"

	if _, _, err := s.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if api.auth[0] != "Bearer fixed-token" {
		t.Errorf("auth = %q, want the fixed token", api.auth[0])
	}
}

// A missing token file is an error, not a silent empty Authorization header.
func TestMissingTokenFileIsAnError(t *testing.T) {
	s := storeAt("http://127.0.0.1:1", filepath.Join(t.TempDir(), "absent"))
	if _, _, err := s.Load(context.Background()); err == nil {
		t.Fatal("want an error when the token file is absent")
	}
}

func TestLoadMissingConfigMapIsEmpty(t *testing.T) {
	api := &fakeAPI{status: http.StatusNotFound}
	srv := httptest.NewServer(api)
	defer srv.Close()

	entries, version, err := storeAt(srv.URL, tokenFile(t, "t")).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if entries != nil || version != "" {
		t.Fatalf("want empty set and version, got %v / %q", entries, version)
	}
}

func TestLoadParsesEntriesAndVersion(t *testing.T) {
	want := []keys.Entry{{Kid: "kid-1", X: "eXg", Y: "d2h5", Replica: "r1", Lease: time.Now().UTC().Truncate(time.Second)}}
	api := &fakeAPI{status: http.StatusOK, body: cmJSON(t, "42", want)}
	srv := httptest.NewServer(api)
	defer srv.Close()

	got, version, err := storeAt(srv.URL, tokenFile(t, "t")).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != "42" {
		t.Errorf("version = %q, want 42", version)
	}
	if len(got) != 1 || got[0].Kid != "kid-1" || got[0].Replica != "r1" {
		t.Fatalf("entries round-trip wrong: %+v", got)
	}
}

func TestLoadNon200IsAnError(t *testing.T) {
	api := &fakeAPI{status: http.StatusForbidden, body: `{"message":"forbidden"}`}
	srv := httptest.NewServer(api)
	defer srv.Close()

	if _, _, err := storeAt(srv.URL, tokenFile(t, "t")).Load(context.Background()); err == nil {
		t.Fatal("want an error on a 403")
	}
}

// An empty version creates (POST to the collection); a version updates (PUT to
// the named object).
func TestSaveCreateVersusUpdate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		version    string
		wantMethod string
		wantSuffix string
	}{
		{"create", "", http.MethodPost, "/configmaps"},
		{"update", "7", http.MethodPut, "/configmaps/tsjwt-keys"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeAPI{status: http.StatusOK, body: "{}"}
			srv := httptest.NewServer(api)
			defer srv.Close()

			err := storeAt(srv.URL, tokenFile(t, "t")).Save(context.Background(), nil, tc.version)
			if err != nil {
				t.Fatal(err)
			}
			api.mu.Lock()
			defer api.mu.Unlock()
			if api.method[0] != tc.wantMethod {
				t.Errorf("method = %s, want %s", api.method[0], tc.wantMethod)
			}
			if !strings.HasSuffix(api.path[0], tc.wantSuffix) {
				t.Errorf("path = %s, want suffix %s", api.path[0], tc.wantSuffix)
			}
		})
	}
}

func TestSaveConflictIsErrConflict(t *testing.T) {
	api := &fakeAPI{status: http.StatusConflict, body: `{"message":"conflict"}`}
	srv := httptest.NewServer(api)
	defer srv.Close()

	err := storeAt(srv.URL, tokenFile(t, "t")).Save(context.Background(), nil, "9")
	if !errors.Is(err, keys.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}
