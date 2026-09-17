// Package verifier checks identity assertions on the backend side.
//
// A verifier holds only public keys. It never needs a shared secret, so a
// compromised backend cannot mint tokens for any other backend.
package verifier

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/jwt"
	"github.com/bitcomplete/tsjwt/keys"
)

// KeySource supplies verification keys by key id.
type KeySource interface {
	// Key returns the verification key for kid, or an error wrapping
	// tsjwt.ErrNoKey when the set holds no such key.
	Key(ctx context.Context, kid string) (*ecdsa.PublicKey, error)
}

// Config configures a [Verifier].
type Config struct {
	// Issuer is the exact "iss" value required. Required: an unchecked
	// issuer lets any signer whose key is in the set mint for this
	// backend.
	Issuer string

	// Audience is the exact "aud" value required. Required: it is what
	// stops a token minted for one backend being replayed at another.
	Audience string

	// Keys supplies verification keys. Required.
	Keys KeySource

	// Leeway tolerates clock skew on exp and nbf. Default 60s.
	Leeway time.Duration

	// MaxLifetime rejects a token whose exp is further from its iat than
	// this, whatever the signature says. It bounds the damage from a
	// signer that is misconfigured or compromised into minting long
	// tokens. Default 15m. Zero disables the check.
	MaxLifetime time.Duration

	// Replay, when set, rejects a token id that has been seen before.
	Replay ReplayGuard

	// Now replaces the time source. For tests.
	Now func() time.Time
}

// ReplayGuard records token ids that have been presented, so that a captured
// token cannot be used twice.
type ReplayGuard interface {
	// Seen records jti as used until exp, and reports whether it had
	// already been recorded.
	Seen(jti string, exp time.Time) bool
}

// Verifier checks tokens.
type Verifier struct {
	cfg Config
}

// New validates cfg and returns a verifier.
func New(cfg Config) (*Verifier, error) {
	switch {
	case strings.TrimSpace(cfg.Issuer) == "":
		return nil, fmt.Errorf("verifier: Issuer is required")
	case strings.TrimSpace(cfg.Audience) == "":
		return nil, fmt.Errorf("verifier: Audience is required")
	case cfg.Keys == nil:
		return nil, fmt.Errorf("verifier: Keys is required")
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = time.Minute
	}
	if cfg.MaxLifetime == 0 {
		cfg.MaxLifetime = 15 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg}, nil
}

// Verify checks a token and returns its claims.
//
// Every failure wraps [tsjwt.ErrInvalidToken]. The wrapped detail is for the
// server log; do not return it to the caller, because it distinguishes
// "expired" from "wrong audience" from "unknown key".
func (v *Verifier) Verify(ctx context.Context, token string) (tsjwt.Claims, error) {
	var zero tsjwt.Claims
	hdr, _, err := jwt.Parse(token)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", tsjwt.ErrInvalidToken, err)
	}
	if hdr.Kid == "" {
		return zero, fmt.Errorf("%w: header names no kid", tsjwt.ErrInvalidToken)
	}
	pub, err := v.cfg.Keys.Key(ctx, hdr.Kid)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", tsjwt.ErrInvalidToken, err)
	}
	payload, err := jwt.Verify(pub, token)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", tsjwt.ErrInvalidToken, err)
	}
	var c tsjwt.Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return zero, fmt.Errorf("%w: payload is not a claim set", tsjwt.ErrInvalidToken)
	}

	// Registered-claim checks. Order matters only for the log message.
	if c.Issuer != v.cfg.Issuer {
		return zero, fmt.Errorf("%w: issuer %q", tsjwt.ErrInvalidToken, c.Issuer)
	}
	if c.Audience != v.cfg.Audience {
		return zero, fmt.Errorf("%w: audience %q", tsjwt.ErrInvalidToken, c.Audience)
	}
	if c.Subject == "" {
		return zero, fmt.Errorf("%w: subject is empty", tsjwt.ErrInvalidToken)
	}
	if c.ID == "" {
		return zero, fmt.Errorf("%w: token has no jti", tsjwt.ErrInvalidToken)
	}
	now := v.cfg.Now()
	if c.Expiry == 0 || now.After(time.Unix(c.Expiry, 0).Add(v.cfg.Leeway)) {
		return zero, fmt.Errorf("%w: expired", tsjwt.ErrInvalidToken)
	}
	if c.NotBefore != 0 && now.Add(v.cfg.Leeway).Before(time.Unix(c.NotBefore, 0)) {
		return zero, fmt.Errorf("%w: not yet valid", tsjwt.ErrInvalidToken)
	}
	if v.cfg.MaxLifetime > 0 && c.IssuedAt != 0 {
		// A far-apart exp and iat overflow int64 nanoseconds and wrap to a
		// negative Duration, which would slip past a "> MaxLifetime" test.
		// Reject a non-positive span too, so a signer that mints an absurd
		// lifetime stays bounded, which is the point of this second limit.
		life := time.Unix(c.Expiry, 0).Sub(time.Unix(c.IssuedAt, 0))
		if life <= 0 || life > v.cfg.MaxLifetime {
			return zero, fmt.Errorf("%w: lifetime %s outside (0, %s]",
				tsjwt.ErrInvalidToken, life, v.cfg.MaxLifetime)
		}
	}
	if v.cfg.Replay != nil && v.cfg.Replay.Seen(c.ID, time.Unix(c.Expiry, 0)) {
		return zero, fmt.Errorf("%w: token id replayed", tsjwt.ErrInvalidToken)
	}
	return c, nil
}

// MemoryReplayGuard remembers token ids in memory until they expire.
//
// It is per-process, so it does not protect a horizontally scaled backend.
// Use a shared store for that; this type is the single-instance default.
type MemoryReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// NewMemoryReplayGuard returns an empty guard.
func NewMemoryReplayGuard() *MemoryReplayGuard {
	return &MemoryReplayGuard{seen: make(map[string]time.Time), now: time.Now}
}

// Seen implements [ReplayGuard].
func (g *MemoryReplayGuard) Seen(jti string, exp time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for k, t := range g.seen {
		if now.After(t) {
			delete(g.seen, k)
		}
	}
	if _, dup := g.seen[jti]; dup {
		return true
	}
	g.seen[jti] = exp
	return false
}

// LocalKeys adapts a local [keys.Set] to [KeySource]. It suits a process
// that both signs and verifies, and tests.
type LocalKeys struct{ Set *keys.Set }

// Key implements [KeySource].
func (l LocalKeys) Key(_ context.Context, kid string) (*ecdsa.PublicKey, error) {
	pub, ok := l.Set.PublicKey(kid)
	if !ok {
		return nil, fmt.Errorf("%w: kid %q", tsjwt.ErrNoKey, kid)
	}
	return pub, nil
}

// Middleware verifies the assertion header on every request and puts the
// claims in the request context. A request without a valid token is refused
// before the handler runs.
func (v *Verifier) Middleware(header string, next http.Handler) http.Handler {
	if header == "" {
		header = tsjwt.DefaultHeader
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get(header)
		// Accept "Bearer <token>" as well as a bare token, so the same
		// backend works behind a proxy that writes either.
		if rest, ok := strings.CutPrefix(tok, "Bearer "); ok {
			tok = rest
		}
		if tok == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := v.Verify(r.Context(), tok)
		if err != nil {
			// The detail stays out of the response on purpose.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(tsjwt.WithClaims(r.Context(), claims)))
	})
}
