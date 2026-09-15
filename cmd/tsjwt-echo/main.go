// Command tsjwt-echo is a reference backend. It verifies the assertion on
// each request and echoes the claims it read.
//
// It exists to answer one question on a real deployment: did the signer,
// the network path and the verifier compose correctly? A backend that echoes
// its own view of the caller answers that directly, with no other moving
// parts to blame.
//
// It is also the smallest complete example of the verifying side, so it
// doubles as documentation.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/verifier"
)

func main() {
	var (
		listen   = flag.String("listen", ":8080", "address to listen on")
		issuer   = flag.String("issuer", "", "required iss claim (required)")
		audience = flag.String("audience", "", "required aud claim (required)")
		jwksURL  = flag.String("jwks", "", "signer's JWKS URL (required)")
		header   = flag.String("header", tsjwt.DefaultHeader, "assertion header")
		replay   = flag.Bool("replay-guard", false, "refuse a token id seen twice")
	)
	flag.Parse()

	if *issuer == "" || *audience == "" || *jwksURL == "" {
		fmt.Fprintln(os.Stderr, "-issuer, -audience and -jwks are all required")
		os.Exit(2)
	}

	cfg := verifier.Config{
		Issuer:   *issuer,
		Audience: *audience,
		Keys:     &verifier.RemoteKeys{URL: *jwksURL},
	}
	if *replay {
		// Off by default: this process is one replica, so the guard
		// would give a false sense of protection behind a Service that
		// fans out.
		cfg.Replay = verifier.NewMemoryReplayGuard()
	}
	v, err := verifier.New(cfg)
	if err != nil {
		slog.Error("verifier", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	// /whoami is deliberately behind the verifier: an unauthenticated
	// caller must not learn anything from it.
	mux.Handle("/whoami", v.Middleware(*header, http.HandlerFunc(whoami)))
	mux.Handle("/", v.Middleware(*header, http.HandlerFunc(whoami)))

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("serving", "listen", *listen, "issuer", *issuer, "audience", *audience, "jwks", *jwksURL)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}

// whoami reports what the verified token said about the caller. It reads
// only from the context, never from a header, so it cannot be spoofed.
func whoami(w http.ResponseWriter, r *http.Request) {
	claims, ok := tsjwt.ClaimsFrom(r.Context())
	if !ok {
		// Unreachable behind the middleware, but a handler that
		// assumes its middleware ran is a handler waiting to be
		// mounted somewhere else.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject":   claims.Subject,
		"email":     claims.Email,
		"name":      claims.Name,
		"node":      claims.Node,
		"tenant":    claims.Tenant,
		"tenants":   claims.Tenants,
		"roles":     claims.Roles,
		"groups":    claims.Groups,
		"issuer":    claims.Issuer,
		"audience":  claims.Audience,
		"expiresAt": claims.ExpiresAt().UTC().Format(time.RFC3339),
		"tokenId":   claims.ID,
	})
}
