package proxy

import "errors"

// errorsIs exists so the switch in refuse reads as a table.
func errorsIs(err, target error) bool { return errors.Is(err, target) }
