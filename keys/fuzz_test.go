package keys_test

import (
	"testing"

	"github.com/bitcomplete/tsjwt/keys"
)

// UnmarshalEntries parses the shared key store, which a peer replica (or a
// hostile store writer) controls. It must not panic on any input, and a value
// it accepts must re-marshal without panicking.
func FuzzUnmarshalEntries(f *testing.F) {
	for _, s := range []string{
		``, `{}`, `{"entries":[]}`,
		`{"entries":[{"kid":"k","x":"AA","y":"AA","replica":"r"}]}`,
		`{"entries":null}`, `{"entries":123}`, `[`, `{"entries":[{"lease":"bad"}]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := keys.UnmarshalEntries(data)
		if err != nil {
			return
		}
		_, _ = keys.MarshalEntries(entries)
	})
}
