package tsnetid

import (
	"errors"
	"strings"
	"testing"

	"github.com/bitcomplete/tsjwt"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// The answers below are recorded from a live tailnet on 2026-09-16 with
// `tailscale whois --json`. They are not invented. The tagged shapes matter:
// a tagged node returns a complete, person-looking UserProfile, and every
// tagged node in the tailnet shares one user id.
const (
	taggedUserID = 1744579493730840
	humanUserID  = 729768600782029
)

func human() *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{
		Node: &tailcfg.Node{Name: "bc.example.ts.net.", User: humanUserID},
		UserProfile: &tailcfg.UserProfile{
			ID: humanUserID, LoginName: "person@example.com", DisplayName: "A Person",
		},
	}
}

func tagged(tag, name string) *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{
		Node: &tailcfg.Node{Name: name, User: taggedUserID, Tags: []string{tag}},
		// Note: NOT empty. This is what the control plane really returns.
		UserProfile: &tailcfg.UserProfile{
			ID: taggedUserID, LoginName: "tagged-devices", DisplayName: "Tagged Devices",
		},
	}
}

// A tagged node must not obtain a person's identity, even though its
// UserProfile is fully populated and looks like one.
func TestTaggedNodeIsRefused(t *testing.T) {
	var s Source
	for _, w := range []*apitype.WhoIsResponse{
		tagged("tag:k8s", "grafana.example.ts.net."),
		tagged("tag:k8s-example", "grafana-gw.example.ts.net."),
		tagged("tag:ci", "runner.example.ts.net."),
	} {
		got, err := s.identity(w)
		if !errors.Is(err, tsjwt.ErrNoIdentity) {
			t.Fatalf("%s: got (%+v, %v), want ErrNoIdentity", w.Node.Name, got, err)
		}
		if !strings.Contains(err.Error(), "tagged node") {
			t.Errorf("%s: error should name the reason, got %v", w.Node.Name, err)
		}
	}
}

// The specific bug the guard exists to prevent: guarding on an empty user
// profile admits every tagged node and collapses them into one principal.
func TestTaggedNodesDoNotCollapseIntoOnePrincipal(t *testing.T) {
	s := Source{AllowTagged: true} // machine identities deliberately enabled
	a, err := s.identity(tagged("tag:k8s", "grafana.example.ts.net."))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.identity(tagged("tag:ci", "runner.example.ts.net."))
	if err != nil {
		t.Fatal(err)
	}
	if a.Subject == b.Subject && a.Node == b.Node {
		t.Fatal("two different tagged nodes are indistinguishable")
	}
	// Documents the sharp edge: the subject IS shared, so a deployment that
	// turns AllowTagged on must key on Node, not Subject.
	if a.Subject != b.Subject {
		t.Errorf("tailnet no longer shares the tagged user id; revisit AllowTagged docs")
	}
}

// Nothing the peer sends over the connection appears in the identity. Every
// field is read from the control plane's answer.
func TestIdentityComesOnlyFromTheControlPlane(t *testing.T) {
	var s Source
	w := human()
	w.UserProfile.LoginName = "attacker-controlled@evil.example"
	w.UserProfile.ID = 1
	id, err := s.identity(w)
	if err != nil {
		t.Fatal(err)
	}
	// The subject follows the numeric id, which a peer cannot choose, and
	// never the login name, which can be reassigned.
	if id.Subject != "tailnet:1" {
		t.Errorf("subject = %q, want it derived from the numeric id", id.Subject)
	}
	if id.Groups != nil {
		t.Errorf("groups = %v, want none without a capability grant", id.Groups)
	}
}

// A node with no user profile gets nothing, rather than an empty identity.
func TestMissingUserProfileIsRefused(t *testing.T) {
	var s Source
	for name, w := range map[string]*apitype.WhoIsResponse{
		"nil profile": {Node: &tailcfg.Node{Name: "x."}},
		"empty login": {Node: &tailcfg.Node{Name: "x."}, UserProfile: &tailcfg.UserProfile{ID: 5}},
	} {
		if _, err := s.identity(w); !errors.Is(err, tsjwt.ErrNoIdentity) {
			t.Errorf("%s: got %v, want ErrNoIdentity", name, err)
		}
	}
}

// Groups come from the capability grant only. A peer that has no grant gets
// no groups, whatever it claims elsewhere.
func TestGroupsRequireACapabilityGrant(t *testing.T) {
	var s Source
	w := human()
	w.CapMap = tailcfg.PeerCapMap{
		CapGroups: []tailcfg.RawMessage{`{"groups":["group:admin"],"tenants":["acme"]}`},
	}
	id, err := s.identity(w)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "group:admin" {
		t.Fatalf("groups = %v", id.Groups)
	}
	// A grant under a different capability name must be ignored entirely.
	w2 := human()
	w2.CapMap = tailcfg.PeerCapMap{
		"example.com/cap/something-else": []tailcfg.RawMessage{`{"groups":["group:admin"]}`},
	}
	id2, err := s.identity(w2)
	if err != nil {
		t.Fatal(err)
	}
	if id2.Groups != nil {
		t.Errorf("groups leaked from an unrelated capability: %v", id2.Groups)
	}
}
