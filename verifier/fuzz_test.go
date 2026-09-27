package verifier

import (
	"encoding/json"
	"testing"

	"github.com/bitcomplete/tsjwt/keys"
)

// A backend fetches a JWKS from a signer it does not fully control; a hostile
// or broken endpoint can return any bytes. Decoding the set and converting each
// JWK to a public key must not panic on any input.
func FuzzJWKSToPublic(f *testing.F) {
	for _, s := range []string{
		`{"keys":[]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","kid":"k","use":"sig","alg":"ES256","x":"AA","y":"AA"}]}`,
		`{"keys":[{"kty":"RSA"}]}`, `{"keys":[{"kty":"EC","crv":"P-256","x":"!!","y":"!!"}]}`,
		`{"keys":null}`, `[`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var set keys.JWKS
		if err := json.Unmarshal(data, &set); err != nil {
			return
		}
		for _, j := range set.Keys {
			_, _ = jwkToPublic(j)
		}
	})
}
