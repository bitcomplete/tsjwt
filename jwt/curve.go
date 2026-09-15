package jwt

import "crypto/elliptic"

// elliptic256 is the one curve this package accepts. It exists as a function
// so the restriction is stated in a single place.
func elliptic256() elliptic.Curve { return elliptic.P256() }
