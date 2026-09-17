// Command tsjwt-dataplane is the Gateway API data plane.
//
// It joins the tailnet as its own node, reads the HTTPRoutes attached to one
// Gateway, and serves them: each request gets an identity established by
// asking the tailnet, and a token minted for the audience of the route it
// matched.
//
// It is its own node, and that is not an implementation choice. Anything
// downstream of a proxy that terminates the connection sees the proxy, not
// the caller. A Gateway that cannot see the caller cannot say who they are.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/k8sstore"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/routetable"
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
		gatewayRef = flag.String("gateway", "", "the Gateway this serves, as namespace/name (required)")
		routesPath = flag.String("routes", "/etc/tsjwt/routes.json", "the rendered route table, normally a mounted ConfigMap")
		routeCache = flag.String("route-cache", "", "where to keep the last table that parsed, so a restart during an outage still has routes; defaults to <state-dir>/routes.cache.json")
		hostname   = flag.String("hostname", "", "tailnet hostname; defaults to the Gateway name")
		stateDir   = flag.String("state-dir", "/var/lib/tsjwt", "directory for tailnet node state")
		issuer     = flag.String("issuer", "", "iss claim; defaults to https://<hostname>")
		tenants    = flag.String("tenants", "", "path to the tenant policy JSON file (required)")
		listen     = flag.String("listen", ":443", "tailnet address to listen on")
		jwksListen = flag.String("jwks-listen", "0.0.0.0:9100", "ordinary address for the key set and health")
		header     = flag.String("header", tsjwt.DefaultHeader, "header the assertion is injected into")
		bearer     = flag.Bool("bearer", false, `write the assertion as "Bearer <token>"`)
		capName    = flag.String("cap", string(tsnetid.CapGroups), "tailnet capability carrying the caller's groups")
		ttl        = flag.Duration("ttl", signer.DefaultTTL, "token lifetime")
		rotate     = flag.Duration("rotate", 24*time.Hour, "signing key rotation interval")
		overlap    = flag.Duration("overlap", time.Hour, "how long a retired key still verifies")
		resync     = flag.Duration("resync", 5*time.Second, "how often to re-read routes")
		keyTags    = flag.String("key-tags", "", "comma-separated tags for an auth key minted at startup")
		shareCM    = flag.String("share-keys", "", "publish verification keys to this ConfigMap")
		plaintext  = flag.Bool("plaintext", false, "serve HTTP instead of HTTPS")
		jwksTLS    = flag.Bool("jwks-tls", false, "serve the key set over HTTPS, using this node's own certificate")
	)
	flag.Parse()

	ns, name, ok := strings.Cut(*gatewayRef, "/")
	if !ok || ns == "" || name == "" {
		return errors.New("-gateway must be namespace/name")
	}
	if *tenants == "" {
		return errors.New("-tenants is required")
	}
	if *hostname == "" {
		*hostname = name
	}
	if *issuer == "" {
		*issuer = "https://" + *hostname
	}
	if *overlap <= *ttl {
		return fmt.Errorf("-overlap (%s) must exceed -ttl (%s)", *overlap, *ttl)
	}

	policy, err := tsjwt.LoadPolicyFile(*tenants)
	if err != nil {
		return err
	}

	keySet, err := keys.NewSet(keys.WithOverlap(*overlap))
	if err != nil {
		return fmt.Errorf("key set: %w", err)
	}

	authKey := os.Getenv("TS_AUTHKEY")
	expiry := tsnetid.NewExpiry(time.Time{}, time.Hour, 3*time.Minute, 7*time.Minute)
	if *keyTags != "" {
		id, secret := os.Getenv("TS_OAUTH_CLIENT_ID"), os.Getenv("TS_OAUTH_CLIENT_SECRET")
		if id == "" || secret == "" {
			return errors.New("-key-tags needs TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET")
		}
		mctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		minted, err := (&tsnetid.AuthKeyMinter{
			ClientID: id, ClientSecret: secret, Tags: strings.Split(*keyTags, ","),
		}).Mint(mctx)
		cancel()
		if err != nil {
			return fmt.Errorf("mint auth key: %w", err)
		}
		authKey = minted.Key
		expiry.Set(minted.Expires)
		slog.Info("minted auth key", "expires", minted.Expires.UTC().Format(time.RFC3339),
			"unhealthyAt", expiry.DeadlineAt().UTC().Format(time.RFC3339))
	}

	ts := &tsnet.Server{Hostname: *hostname, Dir: *stateDir, AuthKey: authKey,
		Logf: func(string, ...any) {}}
	defer ts.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	status, err := ts.Up(ctx)
	if err != nil {
		return fmt.Errorf("tailnet join: %w", err)
	}
	slog.Info("joined tailnet", "name", status.Self.DNSName, "gateway", *gatewayRef)

	lc, err := ts.LocalClient()
	if err != nil {
		return fmt.Errorf("local client: %w", err)
	}

	var keySource signer.KeySource = keySet
	var published *keys.Published
	if *shareCM != "" {
		store, serr := k8sstore.New(*shareCM)
		if serr != nil {
			return serr
		}
		replica := os.Getenv("POD_NAME")
		if replica == "" {
			replica = *hostname + "-" + strconv.Itoa(os.Getpid())
		}
		published, serr = keys.NewPublished(keySet, store, replica,
			keys.WithGrace(3**ttl))
		if serr != nil {
			return serr
		}
		keySource = published
	}

	sg, err := signer.New(signer.Config{
		Issuer: *issuer, Keys: keySource, TTL: *ttl,
		Identities: &tsnetid.Source{Local: lc, Cap: tailcfg.PeerCapability(*capName)},
		Tenants:    policy,
	})
	if err != nil {
		return err
	}

	// The route table starts empty. That is not an error state: a Gateway
	// with no routes yet answers 503, which tells a caller to retry rather
	// than that the path is wrong.
	dyn, err := proxy.NewDynamic(proxy.Config{
		Signer: sg, Header: *header, Bearer: *bearer,
	}, nil)
	if err != nil {
		return err
	}

	// Routes come from a file the controller renders, not from the API.
	//
	// The component whose job is to keep serving should not depend on the
	// thing most likely to be unavailable during an incident. A mounted
	// ConfigMap keeps working through an API outage, and this process
	// needs no RBAC at all.
	if *routeCache == "" {
		*routeCache = filepath.Join(*stateDir, "routes.cache.json")
	}
	source := &routetable.FileSource{
		Path:      *routesPath,
		CachePath: *routeCache,
		Interval:  *resync,
		OnChange: func(routes []proxy.Route) {
			if err := dyn.Set(routes); err != nil {
				// A refused table leaves the previous one serving,
				// so this is loud but not fatal.
				slog.Error("refused a new route table; keeping the one in use",
					"err", err, "routes", len(routes))
				return
			}
			for _, r := range routes {
				slog.Info("route", "name", r.Name, "hosts", r.Hostnames,
					"prefix", r.PathPrefix, "upstream", r.Upstream.String(),
					"audience", r.Audience)
			}
		},
	}
	// Load the cache before the first read, so an unreadable mount at
	// startup means stale routes rather than no routes.
	if err := source.LoadCache(); err != nil {
		slog.Error("could not load the cached route table", "err", err)
	}
	if routes := source.Routes(); len(routes) > 0 {
		if err := dyn.Set(routes); err != nil {
			slog.Error("the cached route table is unusable", "err", err)
		}
	}
	go source.Run(ctx)
	go rotateLoop(ctx, keySet, *rotate)
	if published != nil {
		go published.Run(ctx, func(err error) {
			slog.Error("publishing verification keys failed", "err", err)
		})
	}

	// Health and the key set live on an ordinary address: the kubelet is
	// not on the tailnet, and neither is a backend that needs the keys.
	ops := http.NewServeMux()
	ops.Handle("/.well-known/jwks.json", signer.JWKSHandler(keySource, *overlap/2))
	ops.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !expiry.Healthy() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "auth key is close to expiry; replace this process")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	ops.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		// Ready means routes have been read at least once. Serving
		// before that would answer 503 to everything, which looks like
		// an outage rather than a startup.
		if !source.Loaded() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "no route table yet")
			return
		}
		w.WriteHeader(http.StatusOK)
		// Say when the table came from the cache. The routes work, but
		// they are not known to be current, and that is worth alerting
		// on rather than discovering later.
		stale := ""
		if source.ServingFromCache() {
			stale = " (from cache: the rendered table is unreadable)"
		}
		fmt.Fprintf(w, "ok: %d routes at revision %d%s\n",
			len(dyn.Routes()), source.Revision(), stale)
	})
	// Fixed, small payloads (JWKS and a status line): bound the whole
	// request and response, not just the header, against a slow client.
	opsSrv := &http.Server{
		Addr:              *jwksListen,
		Handler:           ops,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if *jwksTLS {
		// Some verifiers refuse a key set over plain HTTP, reasonably:
		// Grafana is one, and says so rather than failing quietly.
		//
		// The certificate is this node's own, for its name on the
		// private network, issued by a public CA. A verifier that
		// resolves that name to this Service therefore validates
		// normally, with no private CA to distribute.
		opsSrv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				name := strings.TrimSuffix(status.Self.DNSName, ".")
				cert, key, err := lc.CertPair(hi.Context(), name)
				if err != nil {
					return nil, fmt.Errorf("certificate for %s: %w", name, err)
				}
				pair, err := tls.X509KeyPair(cert, key)
				if err != nil {
					return nil, err
				}
				return &pair, nil
			},
		}
	}
	go func() {
		scheme := "http"
		if *jwksTLS {
			scheme = "https"
		}
		slog.Info("serving health and key set", "listen", *jwksListen, "scheme", scheme)
		var err error
		if *jwksTLS {
			err = opsSrv.ListenAndServeTLS("", "")
		} else {
			err = opsSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("ops listener", "err", err)
		}
	}()

	var ln net.Listener
	if *plaintext {
		ln, err = ts.Listen("tcp", *listen)
	} else {
		ln, err = ts.ListenTLS("tcp", *listen)
	}
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listen, err)
	}

	// The proxy streams to backends (large queries, uploads, Grafana Live),
	// so a whole-request ReadTimeout or WriteTimeout would cut legitimate
	// traffic. Bound the header read and idle keep-alive; leave the body and
	// response to stream.
	srv := &http.Server{
		Handler:           dyn,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		_ = opsSrv.Shutdown(sctx)
	}()

	slog.Info("serving", "listen", *listen, "issuer", *issuer, "ttl", ttl.String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

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
