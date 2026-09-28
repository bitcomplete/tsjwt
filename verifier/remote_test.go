package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/verifier"
)

// A cached remote key must stop being trusted once it exceeds the absolute
// staleness ceiling, even while the JWKS endpoint keeps erroring — otherwise a
// rotated or revoked key stays valid for as long as the signer is unreachable.
//
// Regression for the RemoteKeys indefinite-stale-serve gap.
func TestRemoteKeysStalenessCeiling(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(b []byte) string {
		buf := make([]byte, 32)
		copy(buf[32-len(b):], b)
		return base64.RawURLEncoding.EncodeToString(buf)
	}
	// The kid is the RFC 7638 thumbprint (computed inline so this test does not
	// depend on an unexported/other-branch helper, and stays valid once the
	// verifier enforces kid == thumbprint).
	canon, _ := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{"P-256", "EC", enc(key.X.Bytes()), enc(key.Y.Bytes())})
	sum := sha256.Sum256(canon)
	kid := base64.RawURLEncoding.EncodeToString(sum[:])

	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
		"x": enc(key.X.Bytes()), "y": enc(key.Y.Bytes()),
	}}})

	var up atomic.Bool
	up.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !up.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(jwks)
	}))
	defer srv.Close()

	t0 := time.Unix(1_000_000, 0)
	now := t0
	rk := &verifier.RemoteKeys{
		URL: srv.URL, TTL: time.Minute, MaxStale: time.Hour,
		Now: func() time.Time { return now },
	}
	ctx := context.Background()

	// Initial fetch succeeds and caches the key.
	if _, err := rk.Key(ctx, kid); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}

	// The endpoint goes down.
	up.Store(false)

	// Past TTL but within MaxStale: the stale key is still served.
	now = t0.Add(30 * time.Minute)
	if _, err := rk.Key(ctx, kid); err != nil {
		t.Fatalf("within the staleness ceiling the stale key should still serve: %v", err)
	}

	// Past MaxStale with the endpoint still down: the key is refused.
	now = t0.Add(2 * time.Hour)
	if _, err := rk.Key(ctx, kid); err == nil {
		t.Fatal("a cached key past MaxStale was still served while the endpoint was down")
	} else if !errors.Is(err, tsjwt.ErrNoKey) {
		t.Errorf("want ErrNoKey, got %v", err)
	}

	// The endpoint recovers: fetching works again and the ceiling resets.
	up.Store(true)
	if _, err := rk.Key(ctx, kid); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}
