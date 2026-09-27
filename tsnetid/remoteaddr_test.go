package tsnetid

import "testing"

// Identity is derived from the WireGuard peer, so a request whose source is not
// a tailnet address did not arrive directly and must be refused. Guards against
// a fronting L7 proxy or Tailscale Funnel presenting a non-tailnet source.
func TestIsTailnetAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"100.64.0.1:443", true},
		{"100.100.100.100:9", true},
		{"100.127.255.255:1", true},       // top of 100.64.0.0/10
		{"[fd7a:115c:a1e0::1]:443", true}, // Tailscale ULA
		{"100.128.0.1:1", false},          // just outside 100.64.0.0/10
		{"10.0.0.5:80", false},            // cluster / private
		{"172.16.0.1:80", false},          // private
		{"1.2.3.4:80", false},             // public (e.g. via Funnel)
		{"127.0.0.1:8080", false},         // loopback
		{"[::1]:80", false},               // v6 loopback
		{"[fd00::1]:80", false},           // some other ULA, not Tailscale's
		{"not-an-addr", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isTailnetAddr(c.addr); got != c.want {
			t.Errorf("isTailnetAddr(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}
