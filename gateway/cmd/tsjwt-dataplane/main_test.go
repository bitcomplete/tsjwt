package main

import (
	"fmt"
	"testing"

	"github.com/bitcomplete/tsjwt"
)

// fakeIdentifier stands in for a *tsnetid.Source so the startup assertion can
// be exercised without a live tailnet. refuse=true models a correct guard
// (every non-peer source is refused with ErrNoIdentity); refuse=false models a
// weakened guard that hands back an identity for any address.
type fakeIdentifier struct{ refuse bool }

func (f fakeIdentifier) Identify(remoteAddr string) (tsjwt.Identity, error) {
	if f.refuse {
		return tsjwt.Identity{}, fmt.Errorf("%w: %s is not a tailnet peer", tsjwt.ErrNoIdentity, remoteAddr)
	}
	// A guard that trusts a non-tailnet source: this is the regression the
	// startup assertion exists to catch.
	return tsjwt.Identity{Subject: "spoofed:" + remoteAddr}, nil
}

func TestAssertRejectsNonTailnet_passesWhenGuardRefuses(t *testing.T) {
	if err := assertRejectsNonTailnet(fakeIdentifier{refuse: true}); err != nil {
		t.Fatalf("a source that refuses non-tailnet addresses must pass the startup check, got: %v", err)
	}
}

func TestAssertRejectsNonTailnet_failsWhenGuardTrustsNonTailnet(t *testing.T) {
	// This is the regression case. With the assertion in place it must return
	// an error; if the assertion body were removed (always return nil), this
	// test fails — which is the point of shipping the guard with a test.
	err := assertRejectsNonTailnet(fakeIdentifier{refuse: false})
	if err == nil {
		t.Fatal("a source that returns an identity for a non-tailnet address must fail the startup check; the guard did not catch it")
	}
}
