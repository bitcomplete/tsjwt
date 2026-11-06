package gateway_test

import (
	"github.com/bitcomplete/tsjwt/gateway"
	"strings"
	"testing"
)

func TestBackendWaitIsOptInAndValidated(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"", true}, {"60s", true}, {"2m", true}, {"0s", false}, {"-1s", false}, {"3m", false}, {"true", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			gw := gatewayWithClass("edge", "infra", "tsjwt")
			gw.Annotations = map[string]string{gateway.BackendWaitAnnotation: tc.value}
			sts, err := gateway.StatefulSet(gw, gateway.Config{Image: "img", CredentialSecret: "creds", Tag: "tag:example"}, "tenants")
			if (err == nil) != tc.valid {
				t.Fatalf("error %v, valid %v", err, tc.valid)
			}
			if err != nil {
				return
			}
			found := ""
			for _, arg := range sts.Spec.Template.Spec.Containers[0].Args {
				if strings.HasPrefix(arg, "-backend-wait-timeout=") {
					found = strings.TrimPrefix(arg, "-backend-wait-timeout=")
				}
			}
			if found != tc.value {
				t.Fatalf("wait arg %q, want %q", found, tc.value)
			}
		})
	}
}
