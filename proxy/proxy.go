// Package proxy is the identity-aware reverse proxy that fronts a backend.
//
// It is the piece that makes adoption cheap: a backend behind this proxy
// needs no code change beyond verifying a header, because the proxy
// establishes identity, mints the assertion and injects it.
package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/signer"
)

// Config configures a [Proxy].
type Config struct {
	// Upstream is the backend to forward to. Required.
	Upstream *url.URL

	// Signer mints the assertion. Required.
	Signer *signer.Signer

	// Audience is the "aud" the minted token carries. It should name the
	// upstream, so a token for one backend is not accepted by another.
	// Required.
	Audience string

	// Header is the header the assertion is injected into. Empty means
	// [tsjwt.DefaultHeader].
	Header string

	// TenantFrom selects the tenant for a request. Empty result means the
	// identity's default tenant. Nil means always the default.
	TenantFrom func(*http.Request) string

	// Logger records refusals. Nil means slog.Default().
	Logger *slog.Logger
}

// Proxy forwards requests to an upstream, carrying a fresh assertion.
type Proxy struct {
	cfg Config
	rp  *httputil.ReverseProxy
	log *slog.Logger
}

// New validates cfg and returns a proxy.
func New(cfg Config) (*Proxy, error) {
	switch {
	case cfg.Upstream == nil:
		return nil, fmt.Errorf("proxy: Upstream is required")
	case cfg.Signer == nil:
		return nil, fmt.Errorf("proxy: Signer is required")
	case strings.TrimSpace(cfg.Audience) == "":
		return nil, fmt.Errorf("proxy: Audience is required")
	}
	if cfg.Header == "" {
		cfg.Header = tsjwt.DefaultHeader
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	p := &Proxy{
		cfg: cfg,
		log: cfg.Logger,
		rp:  httputil.NewSingleHostReverseProxy(cfg.Upstream),
	}
	p.rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		p.log.Error("upstream failed", "err", err, "path", r.URL.Path)
		http.Error(w, "bad gateway", http.StatusBadGateway)
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

	var tenant string
	if p.cfg.TenantFrom != nil {
		tenant = p.cfg.TenantFrom(r)
	}
	tok, claims, err := p.cfg.Signer.Mint(r.RemoteAddr, p.cfg.Audience, tenant)
	if err != nil {
		p.refuse(w, r, err)
		return
	}
	r.Header.Set(p.cfg.Header, tok)
	p.log.Info("assertion minted",
		"sub", claims.Subject, "tenant", claims.Tenant,
		"roles", claims.Roles, "aud", claims.Audience, "jti", claims.ID)
	p.rp.ServeHTTP(w, r)
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
