// Package proxy is the identity-aware reverse proxy that fronts a backend.
//
// It is the piece that makes adoption cheap: a backend behind this proxy
// needs no code change beyond verifying a header, because the proxy
// establishes identity, mints the assertion and injects it.
package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/signer"
)

// Config configures a [Proxy].
type Config struct {
	// Router picks the backend and the audience per request. Either this
	// or Upstream plus Audience is required.
	//
	// Prefer this. One signer in front of many backends is the shape that
	// makes adoption cheap, and the audience has to be chosen by whatever
	// chooses the backend, or a token for one would work at another.
	Router *Router

	// Upstream is the single backend to forward to. A shorthand for a
	// Router with one route matching everything.
	Upstream *url.URL

	// Signer mints the assertion. Required.
	Signer *signer.Signer

	// Audience is the "aud" carried by tokens minted for Upstream.
	Audience string

	// Header is the header the assertion is injected into. Empty means
	// [tsjwt.DefaultHeader].
	Header string

	// Bearer writes the assertion as "Bearer <token>" instead of the bare
	// token.
	//
	// Some verifiers only read Authorization: Bearer. Envoy's JWT filter
	// is one, and that is the shape a gateway in front of many backends
	// wants. Set Header to "Authorization" alongside this.
	Bearer bool

	// TenantFrom selects the tenant for a request. Empty result means the
	// identity's default tenant. Nil means always the default. A route
	// that pins a tenant overrides this.
	TenantFrom func(*http.Request) string

	// Logger records refusals. Nil means slog.Default().
	Logger *slog.Logger

	// Transport carries requests to backends. Nil installs one tuned for
	// a gateway; see newTransport for why the default is not suitable.
	Transport http.RoundTripper

	// MaxIdleConnsPerHost bounds kept-alive connections to each backend.
	// Zero uses a gateway-appropriate default. Ignored when Transport is
	// set.
	MaxIdleConnsPerHost int
}

// Proxy forwards requests to a backend, carrying a fresh assertion.
type Proxy struct {
	cfg    Config
	router *Router
	// One reverse proxy per upstream, keyed by its URL, built once so a
	// request does not allocate one.
	rps map[string]*httputil.ReverseProxy
	// The union of every claim header any route writes, so all of them
	// can be stripped before routing.
	claimHeaders map[string]struct{}
	log          *slog.Logger
}

// New validates cfg and returns a proxy.
func New(cfg Config) (*Proxy, error) {
	if cfg.Signer == nil {
		return nil, fmt.Errorf("proxy: Signer is required")
	}
	router := cfg.Router
	if router == nil {
		// The single-upstream shorthand: one route that matches
		// everything.
		if cfg.Upstream == nil {
			return nil, fmt.Errorf("proxy: either Router or Upstream is required")
		}
		if strings.TrimSpace(cfg.Audience) == "" {
			return nil, fmt.Errorf("proxy: Audience is required alongside Upstream")
		}
		var err error
		router, err = NewRouter(Route{
			Name:     "default",
			Upstream: cfg.Upstream,
			Audience: cfg.Audience,
		})
		if err != nil {
			return nil, err
		}
	} else if cfg.Upstream != nil {
		return nil, fmt.Errorf("proxy: set Router or Upstream, not both")
	}
	if cfg.Header == "" {
		cfg.Header = tsjwt.DefaultHeader
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	p := &Proxy{
		cfg:          cfg,
		router:       router,
		rps:          make(map[string]*httputil.ReverseProxy),
		claimHeaders: make(map[string]struct{}),
		log:          cfg.Logger,
	}
	for _, rt := range router.Routes() {
		for h := range rt.ClaimHeaders {
			p.claimHeaders[h] = struct{}{}
		}
	}
	transport := cfg.Transport
	if transport == nil {
		transport = newTransport(cfg.MaxIdleConnsPerHost)
	}
	for _, rt := range router.Routes() {
		key := rt.Upstream.String()
		if _, built := p.rps[key]; built {
			continue
		}
		rp := httputil.NewSingleHostReverseProxy(rt.Upstream)
		rp.Transport = transport
		rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			p.log.Error("upstream failed", "upstream", key, "err", err, "path", r.URL.Path)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		}
		p.rps[key] = rp
	}
	return p, nil
}

// ServeHTTP implements [http.Handler].
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip first, and unconditionally. This runs before any path that
	// could return early, so no request can carry a caller-supplied
	// assertion through, even one that is refused later.
	//
	// The Set below would today overwrite a caller-supplied value on its
	// own, so this Del is not the only thing holding the property up.
	// It stays because the property must not depend on that: a later
	// change from Set to Add, or a second header name, would silently
	// turn a redundant line into the only defence. Strip-then-set is the
	// order that is correct under both.
	tsjwt.StripAssertion(r, p.cfg.Header)

	// Strip every claim header any route could write, not only the ones
	// this route writes. Otherwise a caller could supply a header that
	// some other route sets, and reach a backend through a route that
	// leaves it alone.
	for h := range p.claimHeaders {
		r.Header.Del(h)
	}

	route, ok := p.router.Match(r)
	if !ok {
		// No route is a routing failure, not an authorization one, and
		// it must not mint a token: there is no audience to mint it for.
		p.log.Warn("no route", "host", r.Host, "path", r.URL.Path, "remote", r.RemoteAddr)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	tenant := route.Tenant
	if tenant == "" && p.cfg.TenantFrom != nil {
		tenant = p.cfg.TenantFrom(r)
	}
	tok, claims, err := p.cfg.Signer.Mint(r.RemoteAddr, route.Audience, tenant)
	if err != nil {
		p.refuse(w, r, err)
		return
	}
	if p.cfg.Bearer {
		r.Header.Set(p.cfg.Header, "Bearer "+tok)
	} else {
		r.Header.Set(p.cfg.Header, tok)
	}
	for header, claim := range route.ClaimHeaders {
		if v := claimValue(claims, claim); v != "" {
			r.Header.Set(header, v)
		}
	}
	p.log.Info("assertion minted",
		"sub", claims.Subject, "tenant", claims.Tenant,
		"roles", claims.Roles, "aud", claims.Audience, "jti", claims.ID,
		"route", route.Name)
	p.rps[route.Upstream.String()].ServeHTTP(w, r)
}

// refuse maps a mint failure to a status. The body stays generic; the reason
// goes to the log.
func (p *Proxy) refuse(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	switch {
	case errorsIs(err, tsjwt.ErrNoIdentity):
		status = http.StatusUnauthorized
	case errorsIs(err, tsjwt.ErrNoTenant):
		status = http.StatusForbidden
	}
	p.log.Warn("refused", "status", status, "err", err, "remote", r.RemoteAddr, "path", r.URL.Path)
	http.Error(w, http.StatusText(status), status)
}

// newTransport returns a transport suitable for a proxy.
//
// The standard library's default is deliberately conservative: it keeps at
// most two idle connections per host, because it is built for a program that
// makes occasional outbound calls. A proxy is the opposite. Under
// concurrency it opens a new connection for nearly every request, cannot
// reuse them, and eventually fails to connect at all.
//
// Measured on 2026-09-15 with 8000 requests at concurrency 64 against a
// loopback backend: 2764 of them returned 502 on the default transport, and
// none did after this change.
func newTransport(maxIdlePerHost int) http.RoundTripper {
	if maxIdlePerHost <= 0 {
		maxIdlePerHost = 256
	}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		// The two that matter. MaxIdleConnsPerHost is the bug above;
		// MaxIdleConns bounds the total so many backends cannot
		// together exhaust the process.
		MaxIdleConnsPerHost:   maxIdlePerHost,
		MaxIdleConns:          maxIdlePerHost * 8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// Router returns the route table this proxy serves.
func (p *Proxy) Router() *Router { return p.router }

// claimValue reads one claim by name, for ClaimHeaders.
//
// Only claims that are safe to flatten into a header appear here. A list is
// joined with commas, which is what a backend reading a header expects.
func claimValue(c tsjwt.Claims, name string) string {
	switch name {
	case "sub", "subject":
		return c.Subject
	case "email":
		return c.Email
	case "name":
		return c.Name
	case "node":
		return c.Node
	case "tenant":
		return c.Tenant
	case "roles":
		return strings.Join(c.Roles, ",")
	case "groups":
		return strings.Join(c.Groups, ",")
	case "tenants":
		return strings.Join(c.Tenants, ",")
	default:
		return ""
	}
}
