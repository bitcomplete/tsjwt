package tsjwt

import (
	"encoding/json"
	"testing"
)

// A token payload is attacker-controlled, and Claims.UnmarshalJSON has custom
// logic (it collects unknown members into Extra and rejects reserved-name
// collisions on marshal). Neither decode nor a re-marshal of what decoded may
// panic on any input.
func FuzzClaimsUnmarshal(f *testing.F) {
	for _, s := range []string{
		`{}`,
		`{"iss":"x","aud":"y","sub":"s","jti":"j","iat":1,"nbf":0,"exp":2}`,
		`{"extra":{"a":[1,2,{"b":null}]},"tenant":"t","roles":["a"]}`,
		`{"aud":123}`, `{"exp":"nope"}`, `{"tenants":null}`,
		`{"iat":9223372036854775807}`,
		`[]`, `null`, `"str"`, `{`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var c Claims
		if err := json.Unmarshal(data, &c); err != nil {
			return
		}
		// Whatever decoded must also re-marshal without panicking.
		_, _ = json.Marshal(c)
	})
}
