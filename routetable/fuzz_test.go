package routetable_test

import (
	"encoding/json"
	"testing"

	"github.com/bitcomplete/tsjwt/routetable"
)

// The rendered route file is read by the data plane from a mounted ConfigMap.
// Parsing it — JSON decode plus RouteFile.Parse, which url.Parse's each
// upstream — must never panic on a malformed or hostile file.
func FuzzRouteFileParse(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"routes":[]}`,
		`{"revision":1,"gateway":"g","routes":[{"name":"n","upstream":"http://x.svc:80","audience":"a"}]}`,
		`{"routes":[{"upstream":"://"}]}`, `{"routes":[{"upstream":""}]}`,
		`{"routes":null}`, `[`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var rf routetable.RouteFile
		if err := json.Unmarshal(data, &rf); err != nil {
			return
		}
		_, _ = rf.Parse()
	})
}
