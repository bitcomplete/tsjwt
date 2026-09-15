package keys_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt/keys"
)

// memStore is an in-memory Store with the same optimistic-concurrency
// semantics the Kubernetes one gets from resourceVersion.
type memStore struct {
	mu      sync.Mutex
	entries []keys.Entry
	version int
}

func (m *memStore) Load(context.Context) ([]keys.Entry, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]keys.Entry, len(m.entries))
	copy(out, m.entries)
	return out, itoa(m.version), nil
}

func (m *memStore) Save(_ context.Context, e []keys.Entry, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if version != itoa(m.version) {
		return keys.ErrConflict
	}
	m.entries = append([]keys.Entry(nil), e...)
	m.version++
	return nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// TestTwoReplicasVerifyEachOther is the property the whole design exists for:
// a token minted by one replica must verify against the key set published by
// another. Without it, more than one replica is not possible.
func TestTwoReplicasVerifyEachOther(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &memStore{}

	setA, _ := keys.NewSet()
	setB, _ := keys.NewSet()
	a, err := keys.NewPublished(setA, store, "replica-a")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := keys.NewPublished(setB, store, "replica-b")
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if err := a.Publish(ctx); err != nil {
		t.Fatalf("a publish: %v", err)
	}
	if err := b.Publish(ctx); err != nil {
		t.Fatalf("b publish: %v", err)
	}
	// b published second, so it already holds the union. a has to refresh.
	if err := a.Refresh(ctx); err != nil {
		t.Fatalf("a refresh: %v", err)
	}

	_, kidA, _ := setA.Current()
	_, kidB, _ := setB.Current()
	if kidA == kidB {
		t.Fatal("two replicas generated the same key; they must not")
	}
	for _, tc := range []struct {
		name string
		set  keys.JWKS
	}{
		{"a's published set", a.JWKS()},
		{"b's published set", b.JWKS()},
	} {
		got := map[string]bool{}
		for _, k := range tc.set.Keys {
			got[k.Kid] = true
			if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" {
				t.Fatalf("%s: published a key of the wrong type: %+v", tc.name, k)
			}
		}
		if !got[kidA] || !got[kidB] {
			t.Fatalf("%s: holds %v, want both %s and %s", tc.name, got, kidA, kidB)
		}
	}
}

// TestDepartedReplicaAgesOut checks that a replica which stops refreshing
// eventually leaves the set, but not before the grace window, so its
// still-live tokens keep verifying.
func TestDepartedReplicaAgesOut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &memStore{}
	now := time.Now()
	clock := func() time.Time { return now }

	gone, _ := keys.NewSet()
	g, _ := keys.NewPublished(gone, store, "departing",
		keys.WithLease(time.Minute), keys.WithGrace(10*time.Minute),
		keys.WithPublishedClock(clock))
	if err := g.Publish(ctx); err != nil {
		t.Fatalf("publish: %v", err)
	}
	_, goneKid, _ := gone.Current()

	live, _ := keys.NewSet()
	l, _ := keys.NewPublished(live, store, "survivor",
		keys.WithLease(time.Minute), keys.WithGrace(10*time.Minute),
		keys.WithPublishedClock(clock))

	// Inside the grace window the departed key is still served.
	now = now.Add(5 * time.Minute)
	if err := l.Publish(ctx); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !holds(l.JWKS(), goneKid) {
		t.Fatal("a departed replica's key must survive the grace window, or its live tokens break")
	}

	// Past lease plus grace it is dropped.
	now = now.Add(20 * time.Minute)
	if err := l.Publish(ctx); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if holds(l.JWKS(), goneKid) {
		t.Fatal("a departed replica's key must be dropped once its grace has passed")
	}
}

// TestConcurrentPublishConverges drives many replicas publishing at once, the
// case the retry-on-conflict loop exists for.
func TestConcurrentPublishConverges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &memStore{}
	const n = 8

	var wg sync.WaitGroup
	kids := make([]string, n)
	for i := range n {
		set, _ := keys.NewSet()
		_, kid, _ := set.Current()
		kids[i] = kid
		p, err := keys.NewPublished(set, store, "replica-"+itoa(i))
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.Publish(ctx); err != nil {
				t.Errorf("publish: %v", err)
			}
		}()
	}
	wg.Wait()

	final, _, _ := store.Load(ctx)
	got := map[string]bool{}
	for _, e := range final {
		got[e.Kid] = true
	}
	for i, kid := range kids {
		if !got[kid] {
			t.Fatalf("replica-%d's key was lost to a concurrent publish", i)
		}
	}
}

// TestLocalKeyAlwaysServed covers a replica that has not managed to publish:
// it must still serve its own key, or it would mint tokens its own endpoint
// cannot verify.
func TestLocalKeyAlwaysServed(t *testing.T) {
	t.Parallel()
	set, _ := keys.NewSet()
	p, _ := keys.NewPublished(set, &memStore{}, "lonely")
	_, kid, _ := set.Current()
	if !holds(p.JWKS(), kid) {
		t.Fatal("a replica must always serve its own key, published or not")
	}
}

func holds(set keys.JWKS, kid string) bool {
	for _, k := range set.Keys {
		if k.Kid == kid {
			return true
		}
	}
	return false
}
