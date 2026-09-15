// Command tsjwtd is the identity-aware proxy: a tailnet node that
// authenticates callers with WhoIs, mints a short-lived JWT for each
// request, and forwards to a backend.
//
// It is the reference deployment of this module. A deployment with a
// different tenant model should import the packages rather than fork this
// file.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/signer"
	"github.com/bitcomplete/tsjwt/tsnetid"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		hostname  = flag.String("hostname", "tsjwt", "tailnet hostname for this node")
		stateDir  = flag.String("state-dir", "/var/lib/tsjwt", "directory for tailnet node state")
		upstream  = flag.String("upstream", "", "backend URL to forward to (required)")
		audience  = flag.String("audience", "", "aud claim for minted tokens (required)")
		issuer    = flag.String("issuer", "", "iss claim; defaults to https://<hostname>")
		header    = flag.String("header", tsjwt.DefaultHeader, "header the assertion is injected into")
		ttl       = flag.Duration("ttl", signer.DefaultTTL, "token lifetime")
		rotate    = flag.Duration("rotate", 24*time.Hour, "signing key rotation interval")
		overlap   = flag.Duration("overlap", time.Hour, "how long a retired key still verifies")
		tenantCfg = flag.String("tenants", "", "path to the tenant policy JSON file (required)")
		listen    = flag.String("listen", ":443", "tailnet address to listen on")
		allowTags = flag.Bool("allow-tagged", false, "issue tokens to tagged nodes as well as people")
		jwksLocal = flag.String("jwks-listen", "", "also serve ONLY the key set on this ordinary address, for in-cluster verifiers")
		capName   = flag.String("cap", string(tsnetid.CapGroups), "tailnet capability that carries the caller's groups")
		plaintext = flag.Bool("plaintext", false, "serve HTTP instead of HTTPS on -listen; for a tailnet with no certificates")
		redirect  = flag.String("redirect-listen", "", "serve permanent redirects to HTTPS on this address, conventionally :80")
	)
	flag.Parse()

	switch {
	case *upstream == "":
		return errors.New("-upstream is required")
	case *audience == "":
		return errors.New("-audience is required")
	case *tenantCfg == "":
		return errors.New("-tenants is required")
	}
	if *issuer == "" {
		*issuer = "https://" + *hostname
	}
	if *overlap <= *ttl {
		return fmt.Errorf("-overlap (%s) must exceed -ttl (%s), or a token minted "+
			"just before a rotation stops verifying before it expires", *overlap, *ttl)
	}

	up, err := url.Parse(*upstream)
	if err != nil {
		return fmt.Errorf("parse -upstream: %w", err)
	}

	policy, err := loadPolicy(*tenantCfg)
	if err != nil {
		return err
	}

	keySet, err := keys.NewSet(keys.WithOverlap(*overlap))
	if err != nil {
		return fmt.Errorf("key set: %w", err)
	}

	// The auth key is read from the environment, never a flag, so it does
	// not appear in the process table.
	ts := &tsnet.Server{
		Hostname: *hostname,
		Dir:      *stateDir,
		AuthKey:  os.Getenv("TS_AUTHKEY"),
		Logf:     func(string, ...any) {}, // quiet; errors surface on Up
	}
	defer ts.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	status, err := ts.Up(ctx)
	if err != nil {
		return fmt.Errorf("tailnet join: %w", err)
	}
	slog.Info("joined tailnet", "name", status.Self.DNSName, "addrs", status.TailscaleIPs)

	lc, err := ts.LocalClient()
	if err != nil {
		return fmt.Errorf("local client: %w", err)
	}

	sg, err := signer.New(signer.Config{
		Issuer: *issuer,
		Keys:   keySet,
		Identities: &tsnetid.Source{
			Local:       lc,
			Cap:         tailcfg.PeerCapability(*capName),
			AllowTagged: *allowTags,
		},
		Tenants: policy,
		TTL:     *ttl,
	})
	if err != nil {
		return err
	}

	px, err := proxy.New(proxy.Config{
		Upstream:   up,
		Signer:     sg,
		Audience:   *audience,
		Header:     *header,
		TenantFrom: tenantFromRequest,
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	// The key set is public by design: it holds only public keys, and a
	// verifier must be able to fetch it without a credential.
	mux.Handle("/.well-known/jwks.json", signer.JWKSHandler(keySet, *overlap/2))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	// Everything else is the proxied backend.
	mux.Handle("/", px)

	// Serve TLS by default.
	//
	// The traffic is already inside WireGuard, so this is not what keeps it
	// confidential. It is about the token. An assertion is a bearer
	// credential in a header, and a plain listener means every client has to
	// be told to send one over http://, which is a habit that does not stay
	// inside the tailnet. It also makes the service reachable at the URL its
	// own issuer claim names, rather than at that URL plus a port.
	//
	// ListenTLS gets a certificate for the node's MagicDNS name, which needs
	// HTTPS certificates enabled for the tailnet.
	var ln net.Listener
	if *plaintext {
		ln, err = ts.Listen("tcp", *listen)
	} else {
		ln, err = ts.ListenTLS("tcp", *listen)
	}
	if err != nil {
		if !*plaintext {
			return fmt.Errorf("listen TLS on %s: %w (if this tailnet has no "+
				"HTTPS certificates, enable them, or run with -plaintext)", *listen, err)
		}
		return fmt.Errorf("listen %s: %w", *listen, err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go rotateLoop(ctx, keySet, *rotate)

	// A plain listener whose only job is to send callers to the TLS one, so
	// that a request to http:// does not silently succeed and teach the
	// wrong habit.
	if *redirect != "" && !*plaintext {
		rln, err := ts.Listen("tcp", *redirect)
		if err != nil {
			return fmt.Errorf("listen %s for redirects: %w", *redirect, err)
		}
		rs := &http.Server{
			ReadHeaderTimeout: 10 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				u := *r.URL
				u.Scheme = "https"
				u.Host = strings.TrimSuffix(status.Self.DNSName, ".")
				http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
			}),
		}
		go func() {
			slog.Info("serving redirects to https", "listen", *redirect)
			if err := rs.Serve(rln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("redirect listener", "err", err)
			}
		}()
		go func() {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = rs.Shutdown(sctx)
		}()
	}

	// A backend has to fetch the key set, and it is not on the tailnet:
	// it sits behind this process. The tailnet listener cannot serve it,
	// so expose the key set, and nothing else, on an ordinary address.
	//
	// This is safe to expose more widely than the proxy. The set holds
	// only public keys, and a verifier must be able to fetch it without
	// a credential. Serving it is not a weakening of the model; refusing
	// to serve it would just move the problem.
	if *jwksLocal != "" {
		jm := http.NewServeMux()
		jm.Handle("/.well-known/jwks.json", signer.JWKSHandler(keySet, *overlap/2))
		js := &http.Server{
			Addr:              *jwksLocal,
			Handler:           jm,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			slog.Info("serving key set", "listen", *jwksLocal)
			if err := js.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("key set listener", "err", err)
			}
		}()
		go func() {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = js.Shutdown(sctx)
		}()
	}

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	scheme := "https"
	if *plaintext {
		scheme = "http"
	}
	slog.Info("serving", "listen", *listen, "scheme", scheme, "upstream", up.String(),
		"audience", *audience, "issuer", *issuer, "ttl", ttl.String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// rotateLoop rotates the signing key on a schedule.
func rotateLoop(ctx context.Context, set *keys.Set, every time.Duration) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := set.Rotate(); err != nil {
				slog.Error("key rotation failed", "err", err)
				continue
			}
			_, kid, _ := set.Current()
			slog.Info("rotated signing key", "kid", kid)
		}
	}
}

// tenantFromRequest reads the tenant a caller is asking to act for. A caller
// may ask, but the signer decides: a tenant the identity does not hold is
// refused.
func tenantFromRequest(r *http.Request) string {
	if t := r.Header.Get("X-Tsjwt-Tenant"); t != "" {
		return t
	}
	return r.URL.Query().Get("tenant")
}

// policyFile is the on-disk tenant policy. It keeps the org model out of the
// binary, so a deployment changes tenancy by changing a file.
type policyFile struct {
	// Tenants are every tenant known to this deployment.
	Tenants []policyTenant `json:"tenants"`
	// DefaultRole is granted inside a tenant to an identity that matches
	// the tenant but no role rule. Empty means no access.
	DefaultRole string `json:"defaultRole,omitempty"`
}

type policyTenant struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// Groups maps a tailnet group to a role inside this tenant.
	Groups map[string]string `json:"groups"`
	// Default marks this tenant as the one used when a caller names none.
	Default bool `json:"default,omitempty"`
}

// loadPolicy reads the policy file and returns it as a TenantResolver.
func loadPolicy(path string) (tsjwt.TenantResolver, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tenant policy: %w", err)
	}
	var p policyFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse tenant policy %s: %w", path, err)
	}
	if len(p.Tenants) == 0 {
		return nil, fmt.Errorf("tenant policy %s names no tenants", path)
	}
	var defaultID string
	for _, t := range p.Tenants {
		if (tsjwt.Tenant{ID: t.ID}).Valid() != nil {
			return nil, fmt.Errorf("tenant policy: %q is not a valid tenant id", t.ID)
		}
		if t.Default {
			if defaultID != "" {
				return nil, fmt.Errorf("tenant policy: %q and %q are both default", defaultID, t.ID)
			}
			defaultID = t.ID
		}
	}

	return tsjwt.TenantResolverFunc(func(id tsjwt.Identity) (tsjwt.Grant, error) {
		g := tsjwt.Grant{}
		for _, t := range p.Tenants {
			var roles []string
			seen := map[string]struct{}{}
			for _, grp := range id.Groups {
				role, ok := t.Groups[grp]
				if !ok {
					continue
				}
				if _, dup := seen[role]; dup {
					continue
				}
				seen[role] = struct{}{}
				roles = append(roles, role)
			}
			if len(roles) == 0 {
				if p.DefaultRole == "" {
					continue // no access to this tenant
				}
				roles = []string{p.DefaultRole}
			}
			g.Tenants = append(g.Tenants, tsjwt.Tenant{ID: t.ID, Name: t.Name, Roles: roles})
			if t.Default {
				g.Default = t.ID
			}
		}
		// When the caller reaches exactly one tenant, that is the
		// default, whatever the file says.
		if g.Default == "" && len(g.Tenants) == 1 {
			g.Default = g.Tenants[0].ID
		}
		return g, nil
	}), nil
}
