package keys

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"time"
)

// ErrConflict means the store changed under a write. The caller should reload
// and try again.
var ErrConflict = errors.New("keys: the store changed under this write")

// Entry is one replica's published verification key.
//
// Only public material appears here. A replica's private key is generated in
// memory and never leaves the process, so a reader of the store cannot mint
// anything. That is the whole reason this type exists rather than a shared
// private key: read access to the store grants nothing.
type Entry struct {
	// Kid is the RFC 7638 thumbprint, and the primary key of an entry.
	Kid string `json:"kid"`
	// X and Y are the public point, base64url, as in a JWK.
	X string `json:"x"`
	Y string `json:"y"`
	// Replica names the process that published this key, so a replica can
	// find and refresh its own entries.
	Replica string `json:"replica"`
	// Lease is when this entry stops being refreshed by its owner. A
	// replica that dies stops renewing, and its keys age out.
	Lease time.Time `json:"lease"`
}

// Store holds the published key entries. Implementations must support
// optimistic concurrency: Save fails with ErrConflict if the stored version
// is not the one that was loaded.
type Store interface {
	// Load returns the current entries and an opaque version.
	Load(ctx context.Context) ([]Entry, string, error)
	// Save replaces the entries, but only if the store is still at
	// version. It returns ErrConflict otherwise.
	Save(ctx context.Context, entries []Entry, version string) error
}

// Published joins one replica's local signing keys to the set every replica
// publishes.
//
// Signing always uses the local set. Verification uses the union, so a token
// minted by any replica verifies at any backend. This is what makes more than
// one replica possible without a shared private key.
type Published struct {
	local   *Set
	store   Store
	replica string

	// lease is how long an entry stays valid without a refresh. It must
	// comfortably exceed the refresh interval, or a slow refresh looks
	// like a dead replica.
	lease time.Duration

	// grace is how long a lapsed entry is still served. It must exceed
	// the longest token lifetime, or a token minted by a replica that has
	// just gone away stops verifying before it expires.
	grace time.Duration

	now func() time.Time

	mu     sync.RWMutex
	merged []Entry
}

// PublishedOption configures a [Published].
type PublishedOption func(*Published)

// WithLease sets how long a published entry stays fresh without a refresh.
func WithLease(d time.Duration) PublishedOption { return func(p *Published) { p.lease = d } }

// WithGrace sets how long a lapsed entry is still served for verification.
// It must exceed the longest token lifetime.
func WithGrace(d time.Duration) PublishedOption { return func(p *Published) { p.grace = d } }

// WithPublishedClock replaces the time source. For tests.
func WithPublishedClock(now func() time.Time) PublishedOption {
	return func(p *Published) { p.now = now }
}

// NewPublished wraps a local key set with a shared store. replica must be
// unique per process; a pod name serves.
func NewPublished(local *Set, store Store, replica string, opts ...PublishedOption) (*Published, error) {
	if local == nil || store == nil || replica == "" {
		return nil, fmt.Errorf("keys: local set, store and replica name are all required")
	}
	p := &Published{
		local: local, store: store, replica: replica,
		lease: 2 * time.Minute, grace: 30 * time.Minute, now: time.Now,
	}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Publish writes this replica's public keys to the store and reads back the
// union. It removes its own stale entries, and drops any replica's entries
// that are past lease plus grace.
//
// On a conflict it reloads and retries, because a conflict means another
// replica published at the same moment, which is expected rather than
// exceptional.
func (p *Published) Publish(ctx context.Context) error {
	const attempts = 5
	var lastErr error
	for i := range attempts {
		if err := p.publishOnce(ctx); err == nil {
			return nil
		} else if !errors.Is(err, ErrConflict) {
			return err
		} else {
			lastErr = err
		}
		// Back off a little, with jitter, so two replicas that collided
		// do not collide again on the same schedule.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(1<<i)*20*time.Millisecond +
			time.Duration(rand.Int64N(int64(30*time.Millisecond)))):
		}
	}
	return fmt.Errorf("keys: publish gave up after %d conflicts: %w", attempts, lastErr)
}

func (p *Published) publishOnce(ctx context.Context) error {
	stored, version, err := p.store.Load(ctx)
	if err != nil {
		return err
	}
	now := p.now()
	mine := p.mineNow(now)

	next := make([]Entry, 0, len(stored)+len(mine))
	for _, e := range stored {
		if e.Replica == p.replica {
			continue // replaced below, so this replica never leaves a stale key
		}
		if e.Lease.Add(p.grace).Before(now) {
			continue // the owner stopped refreshing long enough ago
		}
		next = append(next, e)
	}
	next = append(next, mine...)
	sort.Slice(next, func(i, j int) bool { return next[i].Kid < next[j].Kid })

	if err := p.store.Save(ctx, next, version); err != nil {
		return err
	}
	p.mu.Lock()
	p.merged = next
	p.mu.Unlock()
	return nil
}

// mineNow renders this replica's current and still-valid retired keys as
// entries.
func (p *Published) mineNow(now time.Time) []Entry {
	jwks := p.local.JWKS()
	out := make([]Entry, 0, len(jwks.Keys))
	for _, k := range jwks.Keys {
		out = append(out, Entry{
			Kid: k.Kid, X: k.X, Y: k.Y,
			Replica: p.replica,
			Lease:   now.Add(p.lease),
		})
	}
	return out
}

// Refresh reloads the union without publishing, so a replica picks up a new
// peer's key between its own publishes.
func (p *Published) Refresh(ctx context.Context) error {
	stored, _, err := p.store.Load(ctx)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.merged = stored
	p.mu.Unlock()
	return nil
}

// JWKS returns the union of every live replica's public keys, plus this
// replica's own. The local keys are always included, even if a publish has
// not yet landed, so a freshly started replica never mints tokens that its
// own published set cannot verify.
func (p *Published) JWKS() JWKS {
	now := p.now()
	seen := make(map[string]struct{})
	out := JWKS{}

	for _, k := range p.local.JWKS().Keys {
		seen[k.Kid] = struct{}{}
		out.Keys = append(out.Keys, k)
	}

	p.mu.RLock()
	merged := p.merged
	p.mu.RUnlock()
	for _, e := range merged {
		if _, dup := seen[e.Kid]; dup {
			continue
		}
		if e.Lease.Add(p.grace).Before(now) {
			continue
		}
		seen[e.Kid] = struct{}{}
		out.Keys = append(out.Keys, JWK{
			Kty: "EC", Crv: "P-256", Kid: e.Kid, Use: "sig", Alg: "ES256",
			X: e.X, Y: e.Y,
		})
	}
	sort.Slice(out.Keys, func(i, j int) bool { return out.Keys[i].Kid < out.Keys[j].Kid })
	return out
}

// Current returns the local signing key. Signing never uses a peer's key.
func (p *Published) Current() (*ecdsa.PrivateKey, string, error) {
	return p.local.Current()
}

// Run publishes immediately, then keeps the lease alive until ctx ends.
//
// The interval is a third of the lease, so two refreshes can fail before a
// healthy replica looks dead to its peers.
func (p *Published) Run(ctx context.Context, onError func(error)) {
	interval := p.lease / 3
	if interval <= 0 {
		interval = 30 * time.Second
	}
	report := func(err error) {
		if err != nil && onError != nil {
			onError(err)
		}
	}
	report(p.Publish(ctx))

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report(p.Publish(ctx))
		}
	}
}

// MarshalEntries and UnmarshalEntries are the wire format a Store persists.
// They are exported so an implementation does not have to invent one.
func MarshalEntries(entries []Entry) ([]byte, error) {
	return json.Marshal(struct {
		Entries []Entry `json:"entries"`
	}{entries})
}

// UnmarshalEntries parses what MarshalEntries wrote. Empty input is an empty
// set, not an error: a store that has never been written is the normal state
// on first start.
func UnmarshalEntries(b []byte) ([]Entry, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var doc struct {
		Entries []Entry `json:"entries"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("keys: parse entries: %w", err)
	}
	return doc.Entries, nil
}
