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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/k8sstore"
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
		hostname   = flag.String("hostname", "tsjwt", "tailnet hostname for this node")
		stateDir   = flag.String("state-dir", "/var/lib/tsjwt", "directory for tailnet node state")
		upstream   = flag.String("upstream", "", "backend URL to forward to (required)")
		audience   = flag.String("audience", "", "aud claim for minted tokens (required)")
		issuer     = flag.String("issuer", "", "iss claim; defaults to https://<hostname>")
		header     = flag.String("header", tsjwt.DefaultHeader, "header the assertion is injected into")
		bearer     = flag.Bool("bearer", false, "write the assertion as \"Bearer <token>\"; pair with -header=Authorization for a gateway that only reads Authorization")
		ttl        = flag.Duration("ttl", signer.DefaultTTL, "token lifetime")
		rotate     = flag.Duration("rotate", 24*time.Hour, "signing key rotation interval")
		overlap    = flag.Duration("overlap", time.Hour, "how long a retired key still verifies")
		tenantCfg  = flag.String("tenants", "", "path to the tenant policy JSON file (required)")
		listen     = flag.String("listen", ":443", "tailnet address to listen on")
		allowTags  = flag.Bool("allow-tagged", false, "issue tokens to tagged nodes as well as people")
		jwksLocal  = flag.String("jwks-listen", "", "also serve ONLY the key set on this ordinary address, for in-cluster verifiers")
		capName    = flag.String("cap", string(tsnetid.CapGroups), "tailnet capability that carries the caller's groups")
		plaintext  = flag.Bool("plaintext", false, "serve HTTP instead of HTTPS on -listen; for a tailnet with no certificates")
		redirect   = flag.String("redirect-listen", "", "serve permanent redirects to HTTPS on this address, conventionally :80")
		keyTags    = flag.String("key-tags", "", "comma-separated tags for a key minted at startup; enables minting")
		keyValid   = flag.Duration("key-validity", 90*24*time.Hour, "lifetime requested for a minted auth key")
		keyBuffer  = flag.Duration("key-buffer", time.Hour, "report unhealthy this long before the key expires")
		splayMin   = flag.Duration("key-splay-min", 3*time.Minute, "low end of the per-process health splay")
		splayMax   = flag.Duration("key-splay-max", 7*time.Minute, "high end of the per-process health splay")
		shareCM    = flag.String("share-keys", "", "publish verification keys to this Kubernetes ConfigMap, so more than one replica can serve")
		shareLease = flag.Duration("share-lease", 2*time.Minute, "how long a published key stays fresh without a refresh")
		shareGrace = flag.Duration("share-grace", 30*time.Minute, "how long a lapsed replica's keys are still served")
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

	policy, err := tsjwt.LoadPolicyFile(*tenantCfg)
	if err != nil {
		return err
	}

	keySet, err := keys.NewSet(keys.WithOverlap(*overlap))
	if err != nil {
		return fmt.Errorf("key set: %w", err)
	}

	// Credentials come from the environment, never a flag, so they do not
	// appear in the process table.
	authKey := os.Getenv("TS_AUTHKEY")
	expiry := tsnetid.NewExpiry(time.Time{}, *keyBuffer, *splayMin, *splayMax)

	// Prefer minting a key at startup over holding a static one.
	//
	// A static key expires on a date nobody is watching. The node keeps
	// running long past it, because a tagged node does not expire its node
	// key, so the failure only appears at the next restart — often months
	// later, in the middle of something else. Minting at startup means the
	// key in use is never older than the process.
	if *keyTags != "" {
		id, secret := os.Getenv("TS_OAUTH_CLIENT_ID"), os.Getenv("TS_OAUTH_CLIENT_SECRET")
		if id == "" || secret == "" {
			return errors.New("-key-tags is set, so TS_OAUTH_CLIENT_ID and " +
				"TS_OAUTH_CLIENT_SECRET must both be set")
		}
		minter := &tsnetid.AuthKeyMinter{
			ClientID:     id,
			ClientSecret: secret,
			Tags:         strings.Split(*keyTags, ","),
			Validity:     *keyValid,
		}
		mctx, mcancel := context.WithTimeout(context.Background(), time.Minute)
		minted, err := minter.Mint(mctx)
		mcancel()
		if err != nil {
			return fmt.Errorf("mint auth key: %w", err)
		}
		authKey = minted.Key
		expiry.Set(minted.Expires)
		slog.Info("minted auth key at startup",
			"expires", minted.Expires.UTC().Format(time.RFC3339),
			"splay", expiry.Splay().String(),
			"unhealthyAt", expiry.DeadlineAt().UTC().Format(time.RFC3339))
	}

	ts := &tsnet.Server{
		Hostname: *hostname,
		Dir:      *stateDir,
		AuthKey:  authKey,
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

	// More than one replica needs every replica's verification keys in one
	// published set, or a token minted by one fails at a backend that
	// fetched the set from another.
	//
	// Only public keys are shared. Each replica's private key is generated
	// here and never leaves this process, so a reader of the store cannot
	// mint anything. That is why the store is a ConfigMap: it holds nothing
	// that needs protecting, and saying so in the resource type makes the
	// property visible rather than assumed.
	var keySource signer.KeySource = keySet
	var published *keys.Published
	if *shareCM != "" {
		if *shareGrace <= *ttl {
			return fmt.Errorf("-share-grace (%s) must exceed -ttl (%s), or a token "+
				"minted by a departing replica stops verifying before it expires",
				*shareGrace, *ttl)
		}
		store, serr := k8sstore.New(*shareCM)
		if serr != nil {
			return serr
		}
		// The replica name must be unique per process. A pod name is.
		replica := os.Getenv("POD_NAME")
		if replica == "" {
			replica = *hostname + "-" + strconv.Itoa(os.Getpid())
		}
		published, serr = keys.NewPublished(keySet, store, replica,
			keys.WithLease(*shareLease), keys.WithGrace(*shareGrace))
		if serr != nil {
			return serr
		}
		keySource = published
		slog.Info("sharing verification keys",
			"configmap", *shareCM, "replica", replica,
			"lease", shareLease.String(), "grace", shareGrace.String())
	}

	sg, err := signer.New(signer.Config{
		Issuer: *issuer,
		Keys:   keySource,
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
		Bearer:     *bearer,
		TenantFrom: tenantFromRequest,
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	// The key set is public by design: it holds only public keys, and a
	// verifier must be able to fetch it without a credential.
	mux.Handle("/.well-known/jwks.json", signer.JWKSHandler(keySource, *overlap/2))
	// The health check fails before the key dies, not after.
	//
	// Failing early is what makes the restart a scheduled event rather than
	// an outage: the orchestrator replaces the process while the current key
	// still works, and the replacement mints a fresh one. The splay inside
	// Expiry is drawn per process, so replicas started together do not all
	// turn unhealthy in the same minute.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !expiry.Healthy() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "auth key expires %s; replace this process\n",
				expiry.DeadlineAt().UTC().Format(time.RFC3339))
			return
		}
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

	if published != nil {
		go published.Run(ctx, func(err error) {
			slog.Error("publishing verification keys failed", "err", err)
		})
	}

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
		jm.Handle("/.well-known/jwks.json", signer.JWKSHandler(keySource, *overlap/2))
		// The kubelet is not on the tailnet, so the probe endpoint has to
		// live on the ordinary listener beside the key set.
		jm.Handle("/healthz", mux)
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
