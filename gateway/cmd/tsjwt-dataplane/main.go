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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/gateway"
	"github.com/bitcomplete/tsjwt/k8sstore"
	"github.com/bitcomplete/tsjwt/keys"
	"github.com/bitcomplete/tsjwt/proxy"
	"github.com/bitcomplete/tsjwt/signer"
	"github.com/bitcomplete/tsjwt/tsnetid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
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
		gatewayRef = flag.String("gateway", "", "the Gateway to serve, as namespace/name (required)")
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

	// Kubernetes client. Routes come from the cluster, so this is a hard
	// dependency at startup even though a later failure is survivable.
	scheme := runtime.NewScheme()
	if err := gwapi.Install(scheme); err != nil {
		return fmt.Errorf("register gateway types: %w", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register core types: %w", err)
	}
	restCfg, err := ctrlconfig.GetConfig()
	if err != nil {
		return fmt.Errorf("kubernetes config: %w", err)
	}
	kc, err := ctrlclient.New(restCfg, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
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

	watcher := &gateway.Watcher{
		Client:   kc,
		Gateway:  types.NamespacedName{Namespace: ns, Name: name},
		Interval: *resync,
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
	go watcher.Run(ctx)
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
		if watcher.Revision() == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "routes not read yet")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ok: %d routes at revision %d\n", len(dyn.Routes()), watcher.Revision())
	})
	opsSrv := &http.Server{Addr: *jwksListen, Handler: ops, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		slog.Info("serving health and key set", "listen", *jwksListen)
		if err := opsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	srv := &http.Server{Handler: dyn, ReadHeaderTimeout: 10 * time.Second}
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
