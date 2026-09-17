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
	"strings"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/jwt"
	"github.com/bitcomplete/tsjwt/verifier"
)

// assertionHeader is where the proxy put the token, so the handler can show
// the JOSE header from it.
var assertionHeader = tsjwt.DefaultHeader

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
	assertionHeader = *header
	mux.Handle("/whoami", v.Middleware(*header, http.HandlerFunc(whoami)))
	mux.Handle("/", v.Middleware(*header, http.HandlerFunc(whoami)))

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	slog.Info("serving", "listen", *listen, "issuer", *issuer, "audience", *audience, "jwks", *jwksURL)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}

// whoami reports everything the verified token said, and how the request
// reached here.
//
// It exists to be looked at. Someone putting a service behind this for the
// first time wants to see the assertion, not be told it worked, so this shows
// the JOSE header, every claim including any the deployment added, and the
// routing that produced this audience.
func whoami(w http.ResponseWriter, r *http.Request) {
	claims, ok := tsjwt.ClaimsFrom(r.Context())
	if !ok {
		// Unreachable behind the middleware, but a handler that assumes
		// its middleware ran is a handler waiting to be mounted
		// somewhere else.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	out := map[string]any{
		"identity": map[string]any{
			"subject": claims.Subject,
			"email":   claims.Email,
			"name":    claims.Name,
			"node":    claims.Node,
		},
		"authorization": map[string]any{
			"tenant":  claims.Tenant,
			"tenants": claims.Tenants,
			"roles":   claims.Roles,
			"groups":  claims.Groups,
		},
		"token": map[string]any{
			"issuer":    claims.Issuer,
			"audience":  claims.Audience,
			"id":        claims.ID,
			"issuedAt":  time.Unix(claims.IssuedAt, 0).UTC().Format(time.RFC3339),
			"notBefore": time.Unix(claims.NotBefore, 0).UTC().Format(time.RFC3339),
			"expiresAt": claims.ExpiresAt().UTC().Format(time.RFC3339),
			"validFor":  time.Until(claims.ExpiresAt()).Round(time.Second).String(),
		},
		"request": map[string]any{
			"host":   r.Host,
			"path":   r.URL.Path,
			"method": r.Method,
			"proto":  r.Proto,
		},
	}

	// The JOSE header says which key signed this and with what. Showing it
	// makes key rotation visible: the kid changes and nothing else does.
	if raw := bearerToken(r.Header.Get(assertionHeader)); raw != "" {
		if hdr, _, err := jwt.Parse(raw); err == nil {
			out["signature"] = map[string]any{
				"alg": hdr.Alg, "typ": hdr.Typ, "kid": hdr.Kid,
			}
		}
	}
	if len(claims.Extra) > 0 {
		out["extra"] = claims.Extra
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

// bearerToken accepts either a bare token or one behind a Bearer prefix, so
// this works behind a proxy that writes either.
func bearerToken(v string) string {
	if rest, ok := strings.CutPrefix(v, "Bearer "); ok {
		return rest
	}
	return v
}
