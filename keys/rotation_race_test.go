package keys_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt/jwt"
	"github.com/bitcomplete/tsjwt/keys"
)

// Key rotation runs on a background timer while request handlers sign with the
// current key and verify against the set, and while replicas publish and read
// the shared union. This exercises all of that concurrently under -race (CI
// runs the suite with -race), so a missing lock on Set or Published shows up as
// a data race, and a rotation that drops a key inside its overlap window shows
// up as a failed lookup.
//
// It also asserts the trust-path invariant that matters: a token minted with
// the current key must remain verifiable through any number of concurrent
// rotations, as long as the overlap window has not passed.
func TestKeyRotationConcurrencyUnderLoad(t *testing.T) {
	// Overlap far longer than the test, so no key legitimately expires during
	// it: any lookup miss is then a real bug, not an expiry.
	set, err := keys.NewSet(keys.WithOverlap(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	published, err := keys.NewPublished(set, &memStore{}, "replica-1", keys.WithGrace(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	const signers = 8
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var cycles int64

	// Rotator: churn the signing key.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if err := set.Rotate(); err != nil {
					t.Errorf("rotate: %v", err)
					return
				}
				time.Sleep(time.Millisecond)
			}
		}
	}()

	// Signers: mint with the current key, then verify it still resolves in the
	// set. A miss here means a key vanished inside its overlap window.
	for i := 0; i < signers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					priv, kid, err := set.Current()
					if err != nil {
						t.Errorf("current: %v", err)
						return
					}
					tok, err := jwt.Sign(priv, kid, map[string]any{"sub": "x"})
					if err != nil {
						t.Errorf("sign: %v", err)
						return
					}
					pub, ok := set.PublicKey(kid)
					if !ok {
						t.Errorf("kid %q not in set right after signing (overlap is 1h)", kid)
						return
					}
					if _, err := jwt.Verify(pub, tok); err != nil {
						t.Errorf("verify a just-minted token: %v", err)
						return
					}
					atomic.AddInt64(&cycles, 1)
				}
			}
		}()
	}

	// Readers: hammer both JWKS views concurrently with the rotation and publish.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = set.JWKS()
					_ = published.JWKS()
				}
			}
		}()
	}

	// Publisher: write and re-read the shared union while keys rotate.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.Background()
		for {
			select {
			case <-stop:
				return
			default:
				_ = published.Publish(ctx)
				_ = published.Refresh(ctx)
			}
		}
	}()

	time.Sleep(time.Second)
	close(stop)
	wg.Wait()

	if cycles == 0 {
		t.Fatal("no sign+verify cycles ran")
	}
	t.Logf("sign+verify cycles across concurrent rotations: %d", atomic.LoadInt64(&cycles))
}
