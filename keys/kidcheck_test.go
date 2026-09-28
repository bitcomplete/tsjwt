package keys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/bitcomplete/tsjwt/keys"
)

// A store entry whose kid is not the thumbprint of its key must not be
// republished in the union JWKS. A store writer is trusted to add a key, but an
// entry that labels a key with a kid that is not its own thumbprint is either a
// bug or an attempt to bind a chosen key to a kid others rely on; drop it.
//
// Regression for the kid==thumbprint-on-load hardening.
func TestPublishedJWKSExcludesForgedKid(t *testing.T) {
	local, err := keys.NewSet()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(b []byte) string {
		buf := make([]byte, 32)
		copy(buf[32-len(b):], b)
		return base64.RawURLEncoding.EncodeToString(buf)
	}
	x, y := enc(pk.X.Bytes()), enc(pk.Y.Bytes())
	goodKid, err := keys.Thumbprint(&pk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	store := &memStore{entries: []keys.Entry{
		{Kid: goodKid, X: x, Y: y, Replica: "peer", Lease: time.Now().Add(time.Hour)},
		{Kid: "forged-kid", X: x, Y: y, Replica: "peer", Lease: time.Now().Add(time.Hour)},
	}}
	p, err := keys.NewPublished(local, store, "me", keys.WithGrace(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	kids := map[string]bool{}
	for _, k := range p.JWKS().Keys {
		kids[k.Kid] = true
	}
	if kids["forged-kid"] {
		t.Error("a store entry whose kid is not its thumbprint was republished in the JWKS")
	}
	if !kids[goodKid] {
		t.Error("a valid peer key was dropped from the JWKS")
	}
}
