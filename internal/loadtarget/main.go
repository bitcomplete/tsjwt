// Command loadtarget runs a full signer-proxy-backend stack over loopback so
// a load generator can drive it.
//
// Go benchmarks measure one operation at a time, in a loop, from one
// goroutine per iteration. That is the right tool for spotting a function
// that got slower. It is the wrong tool for what happens under many
// concurrent connections: lock contention, the key set being read while it
// rotates, replay-guard growth, latency at the tail rather than the mean.
// A load generator finds those.
//
// It listens on an ordinary address rather than a tailnet one, and takes its
// identity from a fixed stub, because the thing under test is the minting and
// verifying path, not WireGuard.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/signer"
	"github.com/bitcomplete/tsjwt/verifier"
)

type stubIdentity struct{ id tsjwt.Identity }

func (s stubIdentity) Identify(string) (tsjwt.Identity, error) { return s.id, nil }

func main() {
	var (
		addr    = flag.String("listen", "127.0.0.1:8099", "address to serve on")
		ttl     = flag.Duration("ttl", 5*time.Minute, "token lifetime")
		rotate  = flag.Duration("rotate", 0, "rotate the signing key this often; 0 disables")
		replay  = flag.Bool("replay-guard", false, "enable the replay guard on the backend")
		tenants = flag.Int("tenants", 1, "number of tenants the identity holds")
	)
	flag.Parse()

	set, err := keys.NewSet(keys.WithOverlap(2 * *ttl))
	if err != nil {
		log.Fatal(err)
	}

	vcfg := verifier.Config{
		Issuer: "https://loadtarget", Audience: "loadtarget",
		Keys: verifier.LocalKeys{Set: set},
	}
	if *replay {
		vcfg.Replay = verifier.NewMemoryReplayGuard()
	}
	v, err := verifier.New(vcfg)
	if err != nil {
		log.Fatal(err)
	}
	backend := httptest.NewServer(v.Middleware("", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			claims, ok := tsjwt.ClaimsFrom(r.Context())
			if !ok {
				http.Error(w, "no claims", http.StatusInternalServerError)
				return
			}
			fmt.Fprintln(w, claims.Subject, claims.Tenant)
		})))
	defer backend.Close()
	up, _ := url.Parse(backend.URL)

	var ts []tsjwt.Tenant
	for i := range *tenants {
		ts = append(ts, tsjwt.Tenant{ID: fmt.Sprintf("tenant-%d", i), Roles: []string{"admin"}})
	}
	sg, err := signer.New(signer.Config{
		Issuer: "https://loadtarget", Keys: set, TTL: *ttl,
		Identities: stubIdentity{tsjwt.Identity{
			Subject: "tailnet:1", Login: "load@example.com",
			Groups: []string{"group:admin"}}},
		Tenants: tsjwt.StaticGrant(tsjwt.Grant{Tenants: ts, Default: ts[0].ID}),
	})
	if err != nil {
		log.Fatal(err)
	}

	router, err := proxy.NewRouter(
		proxy.Route{Name: "root", Upstream: up, Audience: "loadtarget"},
	)
	if err != nil {
		log.Fatal(err)
	}
	px, err := proxy.New(proxy.Config{Router: router, Signer: sg})
	if err != nil {
		log.Fatal(err)
	}

	// Rotating under load is the interesting case: tokens minted before a
	// rotation must keep verifying after it, while new ones use the new key.
	if *rotate > 0 {
		go func() {
			t := time.NewTicker(*rotate)
			defer t.Stop()
			for range t.C {
				if err := set.Rotate(); err != nil {
					log.Printf("rotate: %v", err)
				}
			}
		}()
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/jwks.json", signer.JWKSHandler(set, time.Minute))
	mux.Handle("/", px)

	log.Printf("loadtarget on %s (ttl=%s rotate=%s replay=%v tenants=%d)",
		*addr, *ttl, *rotate, *replay, *tenants)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
