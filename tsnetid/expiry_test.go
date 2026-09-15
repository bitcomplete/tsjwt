package tsnetid_test

import (
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt/tsnetid"
)

// TestExpiryFailsBeforeTheKeyDies is the property the health check exists
// for: it must report unhealthy while the key still works, so the restart is
// a scheduled event rather than an outage.
func TestExpiryFailsBeforeTheKeyDies(t *testing.T) {
	t.Parallel()
	const buffer = time.Hour
	expires := time.Now().Add(90 * 24 * time.Hour)
	e := tsnetid.NewExpiry(expires, buffer, 3*time.Minute, 7*time.Minute)

	if !e.Healthy() {
		t.Fatal("a key with 90 days left must be healthy")
	}
	deadline := e.DeadlineAt()
	if !deadline.Before(expires) {
		t.Fatalf("deadline %s must fall before expiry %s", deadline, expires)
	}
	if gap := expires.Sub(deadline); gap < buffer+3*time.Minute || gap > buffer+7*time.Minute {
		t.Fatalf("gap before expiry is %s, want between %s and %s",
			gap, buffer+3*time.Minute, buffer+7*time.Minute)
	}
}

// TestExpirySplayIsSpread checks that separate processes do not all pick the
// same moment. Without this, a set of replicas started together would fail
// their health checks in the same minute and go down as one.
func TestExpirySplayIsSpread(t *testing.T) {
	t.Parallel()
	const (
		lo = 3 * time.Minute
		hi = 7 * time.Minute
	)
	seen := make(map[time.Duration]int)
	for range 200 {
		s := tsnetid.NewExpiry(time.Now().Add(time.Hour), 0, lo, hi).Splay()
		if s < lo || s > hi {
			t.Fatalf("splay %s outside [%s, %s]", s, lo, hi)
		}
		seen[s.Truncate(time.Second)]++
	}
	// 200 draws over a four-minute window should not collapse onto a
	// handful of values.
	if len(seen) < 50 {
		t.Fatalf("only %d distinct splays in 200 draws; the jitter is not spreading", len(seen))
	}
}

// TestExpiryUnhealthyInsideTheWindow drives the transition itself.
func TestExpiryUnhealthyInsideTheWindow(t *testing.T) {
	t.Parallel()
	// Expiry is ten minutes out, and the buffer alone is an hour, so the
	// deadline is already past.
	e := tsnetid.NewExpiry(time.Now().Add(10*time.Minute), time.Hour, 3*time.Minute, 7*time.Minute)
	if e.Healthy() {
		t.Fatal("a key inside the buffer window must report unhealthy")
	}
}

// TestExpiryZeroMeansNoDeadline covers a static key whose expiry is unknown:
// it must not report unhealthy forever.
func TestExpiryZeroMeansNoDeadline(t *testing.T) {
	t.Parallel()
	e := tsnetid.NewExpiry(time.Time{}, time.Hour, 3*time.Minute, 7*time.Minute)
	if !e.Healthy() {
		t.Fatal("an unknown expiry must not report unhealthy")
	}
}
