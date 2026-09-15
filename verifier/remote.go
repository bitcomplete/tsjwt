package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/bitcomplete/tsjwt"
	"github.com/bitcomplete/tsjwt/keys"
)

// RemoteKeys fetches a signer's public key set over HTTP and caches it.
//
// It is the normal way a backend gets keys: the signer publishes, the
// backend fetches, and no secret is shared between them.
type RemoteKeys struct {
	// URL is the JWKS endpoint, typically
	// https://<signer>/.well-known/jwks.json. Required.
	URL string

	// Client is the HTTP client. Nil means a client with a 10s timeout.
	Client *http.Client

	// TTL is how long a fetched set is reused. It must be shorter than
	// the signer's key overlap window, or this cache can still hold a
	// retired key. Default 5 minutes.
	TTL time.Duration

	// MinRefetch bounds how often an unknown kid may trigger a fetch, so
	// that a stream of tokens naming unknown kids cannot be used to force
	// load onto the signer. Default 30 seconds.
	MinRefetch time.Duration

	// Now replaces the time source. For tests.
	Now func() time.Time

	mu        sync.RWMutex
	byKid     map[string]*ecdsa.PublicKey
	fetchedAt time.Time
	lastTry   time.Time
}

// Key implements [KeySource].
//
// On a miss it refetches once, because a miss is the expected shape of a
// rotation: the signer has published a new key that this cache has not seen.
func (r *RemoteKeys) Key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := r.now()

	r.mu.RLock()
	k, ok := r.byKid[kid]
	fresh := now.Sub(r.fetchedAt) < ttl
	r.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	if ok && !fresh {
		// The key is known but the set is stale. Serve it and let the
		// refresh below happen; a known kid is not a rotation signal.
		if err := r.refresh(ctx, false); err != nil {
			return k, nil // stale but usable beats failing closed here
		}
		r.mu.RLock()
		defer r.mu.RUnlock()
		if k2, ok := r.byKid[kid]; ok {
			return k2, nil
		}
		return nil, fmt.Errorf("%w: kid %q was withdrawn", tsjwt.ErrNoKey, kid)
	}

	// Unknown kid: refetch, rate limited.
	if err := r.refresh(ctx, true); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if k, ok := r.byKid[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: kid %q is not in the published set", tsjwt.ErrNoKey, kid)
}

// refresh fetches the key set. When rateLimit is set, a fetch is skipped if
// one was attempted within MinRefetch.
func (r *RemoteKeys) refresh(ctx context.Context, rateLimit bool) error {
	minGap := r.MinRefetch
	if minGap <= 0 {
		minGap = 30 * time.Second
	}
	now := r.now()

	r.mu.Lock()
	if rateLimit && !r.lastTry.IsZero() && now.Sub(r.lastTry) < minGap {
		r.mu.Unlock()
		return fmt.Errorf("%w: key set refetch is rate limited", tsjwt.ErrNoKey)
	}
	r.lastTry = now
	r.mu.Unlock()

	cl := r.Client
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", tsjwt.ErrNoKey, err)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("%w: fetch key set: %v", tsjwt.ErrNoKey, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: key set returned %s", tsjwt.ErrNoKey, resp.Status)
	}
	var set keys.JWKS
	// A key set is small. Cap the read so a hostile or broken endpoint
	// cannot exhaust memory here.
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("%w: key set is not JSON: %v", tsjwt.ErrNoKey, err)
	}

	parsed := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		pub, err := jwkToPublic(jwk)
		if err != nil {
			// Skip a key this package cannot use rather than
			// rejecting the whole set: a signer may publish a
			// type we do not verify.
			continue
		}
		parsed[jwk.Kid] = pub
	}
	if len(parsed) == 0 {
		return fmt.Errorf("%w: key set held no usable ES256 key", tsjwt.ErrNoKey)
	}

	r.mu.Lock()
	r.byKid = parsed
	r.fetchedAt = r.now()
	r.mu.Unlock()
	return nil
}

func (r *RemoteKeys) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// jwkToPublic converts a JWK to a public key, accepting only EC P-256 keys
// marked for ES256 signatures.
//
// This is the second half of the algorithm-confusion defence. The verifier
// only ever runs ES256, and this refuses to load a key of any other type, so
// a signer that published an RSA or symmetric key could not steer a verifier
// onto it.
func jwkToPublic(j keys.JWK) (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported key type %q/%q", j.Kty, j.Crv)
	}
	if j.Alg != "" && j.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported alg %q", j.Alg)
	}
	if j.Use != "" && j.Use != "sig" {
		return nil, fmt.Errorf("key is not for signatures")
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("x is not base64url")
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("y is not base64url")
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	// Reject a point that is not on the curve. Without this check a
	// malformed or hostile key set could supply an invalid point.
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("point is not on P-256")
	}
	return pub, nil
}
