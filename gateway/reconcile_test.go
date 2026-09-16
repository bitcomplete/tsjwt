package gateway_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bitcomplete/tsjwt/gateway"
	"github.com/bitcomplete/tsjwt/routetable"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

func reconcileScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, rbacv1.AddToScheme, gwapi.Install,
	} {
		if err := add(s); err != nil {
			t.Fatalf("scheme: %v", err)
		}
	}
	return s
}

func gatewayClass(name string, controller string) *gwapi.GatewayClass {
	return &gwapi.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       gwapi.GatewayClassSpec{ControllerName: gwapi.GatewayController(controller)},
	}
}

func gatewayWithClass(name, ns, class string, hostnames ...string) *gwapi.Gateway {
	g := gw(name, ns, hostnames...)
	g.Spec.GatewayClassName = gwapi.ObjectName(class)
	return g
}

func newReconciler(t *testing.T, objs ...client.Object) (*gateway.GatewayReconciler, client.Client) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(reconcileScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&gwapi.Gateway{}, &gwapi.GatewayClass{}).
		Build()
	return &gateway.GatewayReconciler{
		Client: c,
		Config: gateway.Config{
			Image: "registry/tsjwt:v1", CredentialSecret: "creds", Tag: "tag:example",
		},
		TenantsConfigMap: "tsjwt-tenants",
	}, c
}

// TestReconcileProvisionsAndRenders is the base case: a Gateway plus an
// HTTPRoute produces a data plane and a route table it can mount.
func TestReconcileProvisionsAndRenders(t *testing.T) {
	t.Parallel()
	gc := gatewayClass("tsjwt", gateway.ControllerName)
	g := gatewayWithClass("edge", "infra", "tsjwt", "app.ts.net")
	hr := route("app", "infra", "edge", []string{"app.ts.net"}, rule("app-svc", 80))
	s := svc("app-svc", "infra", 80)

	r, c := newReconciler(t, gc, g, &hr, &s)
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "infra", Name: "edge"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var sts appsv1.StatefulSet
	if err := c.Get(ctx, types.NamespacedName{Namespace: "infra", Name: "tsjwt-edge"}, &sts); err != nil {
		t.Fatalf("statefulset: %v", err)
	}
	if len(sts.Spec.VolumeClaimTemplates) != 1 {
		t.Fatal("each data plane needs its own volume for tailnet state")
	}

	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Namespace: "infra", Name: "tsjwt-edge-routes"}, &cm); err != nil {
		t.Fatalf("routes configmap: %v", err)
	}
	var file routetable.RouteFile
	if err := json.Unmarshal([]byte(cm.Data["routes.json"]), &file); err != nil {
		t.Fatalf("rendered table is not valid JSON: %v", err)
	}
	if len(file.Routes) != 1 {
		t.Fatalf("rendered %d routes, want 1", len(file.Routes))
	}
	if file.Routes[0].Audience != "app-svc.infra" {
		t.Fatalf("audience = %q", file.Routes[0].Audience)
	}
	// The data plane must be able to parse what the controller wrote.
	if _, err := file.Parse(); err != nil {
		t.Fatalf("the data plane could not parse the controller's output: %v", err)
	}
}

// TestReconcileIgnoresOtherImplementations: a cluster may run several, and
// each must touch only its own.
func TestReconcileIgnoresOtherImplementations(t *testing.T) {
	t.Parallel()
	gc := gatewayClass("someone-else", "example.com/other-controller")
	g := gatewayWithClass("edge", "infra", "someone-else")

	r, c := newReconciler(t, gc, g)
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "infra", Name: "edge"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var sts appsv1.StatefulSet
	err := c.Get(ctx, types.NamespacedName{Namespace: "infra", Name: "tsjwt-edge"}, &sts)
	if err == nil {
		t.Fatal("provisioned a data plane for another implementation's Gateway")
	}
}

// TestProgrammedTracksTheDataPlane checks the Gateway does not claim to be
// programmed while nothing is serving. Status nobody can trust is worse than
// no status.
func TestProgrammedTracksTheDataPlane(t *testing.T) {
	t.Parallel()
	gc := gatewayClass("tsjwt", gateway.ControllerName)
	g := gatewayWithClass("edge", "infra", "tsjwt")

	r, c := newReconciler(t, gc, g)
	ctx := context.Background()
	key := types.NamespacedName{Namespace: "infra", Name: "edge"}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got gwapi.Gateway
	if err := c.Get(ctx, key, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if cond := findCondition(got.Status.Conditions, string(gwapi.GatewayConditionProgrammed)); cond == nil {
		t.Fatal("no Programmed condition")
	} else if cond.Status != metav1.ConditionFalse {
		t.Fatalf("Programmed = %s with no ready replica; want False", cond.Status)
	}
	if len(got.Status.Addresses) != 0 {
		t.Fatal("an address was published before anything was serving")
	}

	// Now the data plane reports ready.
	var sts appsv1.StatefulSet
	stsKey := types.NamespacedName{Namespace: "infra", Name: "tsjwt-edge"}
	if err := c.Get(ctx, stsKey, &sts); err != nil {
		t.Fatalf("statefulset: %v", err)
	}
	sts.Status.ReadyReplicas = 1
	if err := c.Status().Update(ctx, &sts); err != nil {
		t.Fatalf("update status: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := c.Get(ctx, key, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if cond := findCondition(got.Status.Conditions, string(gwapi.GatewayConditionProgrammed)); cond == nil ||
		cond.Status != metav1.ConditionTrue {
		t.Fatalf("Programmed should be True once a replica is ready, got %v", cond)
	}
	if len(got.Status.Addresses) != 1 || got.Status.Addresses[0].Value != "edge" {
		t.Fatalf("addresses = %v, want the tailnet name", got.Status.Addresses)
	}
}

// TestBadRouteDoesNotBreakTheGateway: one unusable HTTPRoute must not stop
// the others being served.
func TestBadRouteDoesNotBreakTheGateway(t *testing.T) {
	t.Parallel()
	gc := gatewayClass("tsjwt", gateway.ControllerName)
	g := gatewayWithClass("edge", "infra", "tsjwt")
	good := route("good", "infra", "edge", nil, rule("good-svc", 80))
	bad := route("bad", "infra", "edge", nil, rule("does-not-exist", 80))

	r, c := newReconciler(t, gc, g, &good, &bad, ptrTo(svc("good-svc", "infra", 80)))
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "infra", Name: "edge"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Namespace: "infra", Name: "tsjwt-edge-routes"}, &cm); err != nil {
		t.Fatalf("configmap: %v", err)
	}
	var file routetable.RouteFile
	if err := json.Unmarshal([]byte(cm.Data["routes.json"]), &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(file.Routes) != 1 || file.Routes[0].Audience != "good-svc.infra" {
		t.Fatalf("the usable route must still be rendered, got %v", file.Routes)
	}
}

func ptrTo(s corev1.Service) *corev1.Service { return &s }

func findCondition(conds []metav1.Condition, t string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}

// TestDataPlaneRoleCannotRewriteItsOwnRoutes is why the Role is provisioned
// per Gateway rather than installed once.
//
// The data plane publishes verification keys, so it needs get and update on
// one ConfigMap. A Role broad enough to be written statically would cover
// every ConfigMap in the namespace, including its own route table — which
// would let a compromised data plane rewrite where it forwards, and to which
// audience.
func TestDataPlaneRoleCannotRewriteItsOwnRoutes(t *testing.T) {
	t.Parallel()
	gc := gatewayClass("tsjwt", gateway.ControllerName)
	g := gatewayWithClass("edge", "infra", "tsjwt")

	r, c := newReconciler(t, gc, g)
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "infra", Name: "edge"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var role rbacv1.Role
	if err := c.Get(ctx, types.NamespacedName{Namespace: "infra", Name: "tsjwt-edge-keys"}, &role); err != nil {
		t.Fatalf("keys Role: %v", err)
	}

	for _, rule := range role.Rules {
		for _, verb := range rule.Verbs {
			if verb == "create" {
				continue // create cannot be name-scoped by the API
			}
			if len(rule.ResourceNames) == 0 {
				t.Fatalf("verb %q is granted on every ConfigMap in the namespace, "+
					"including the data plane's own route table", verb)
			}
			for _, n := range rule.ResourceNames {
				if n != "tsjwt-edge-keys" {
					t.Fatalf("verb %q reaches %q, which is not the key set", verb, n)
				}
			}
		}
	}

	var rb rbacv1.RoleBinding
	if err := c.Get(ctx, types.NamespacedName{Namespace: "infra", Name: "tsjwt-edge-keys"}, &rb); err != nil {
		t.Fatalf("keys RoleBinding: %v", err)
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != "tsjwt-edge-dataplane" {
		t.Fatalf("bound to %v, want the data plane's account", rb.Subjects)
	}
}

// TestProvisionedResourcesAreOwned checks everything the controller creates
// is garbage collected with its Gateway. Orphaned tailnet nodes are worse
// than orphaned Kubernetes objects: they keep a name and stay in the tailnet.
func TestProvisionedResourcesAreOwned(t *testing.T) {
	t.Parallel()
	gc := gatewayClass("tsjwt", gateway.ControllerName)
	g := gatewayWithClass("edge", "infra", "tsjwt")

	r, c := newReconciler(t, gc, g)
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "infra", Name: "edge"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	for _, tc := range []struct {
		name string
		obj  client.Object
	}{
		{"tsjwt-edge", &appsv1.StatefulSet{}},
		{"tsjwt-edge", &corev1.Service{}},
		{"tsjwt-edge-routes", &corev1.ConfigMap{}},
		{"tsjwt-edge-dataplane", &corev1.ServiceAccount{}},
		{"tsjwt-edge-keys", &rbacv1.Role{}},
		{"tsjwt-edge-keys", &rbacv1.RoleBinding{}},
	} {
		if err := c.Get(ctx, types.NamespacedName{Namespace: "infra", Name: tc.name}, tc.obj); err != nil {
			t.Fatalf("%T %s: %v", tc.obj, tc.name, err)
		}
		owners := tc.obj.GetOwnerReferences()
		if len(owners) != 1 || owners[0].Kind != "Gateway" || owners[0].Name != "edge" {
			t.Fatalf("%T %s has owners %v, want the Gateway", tc.obj, tc.name, owners)
		}
	}
}

// TestProbeSchemeFollowsTheKeySet guards a mistake that is invisible in the
// manifest and obvious only from the pod's logs. The probes share the port
// the key set is served on, so enabling TLS there without changing them
// leaves the kubelet speaking HTTP to an HTTPS listener: every probe fails,
// the pod restarts, and its logs say only "client sent an HTTP request to an
// HTTPS server".
func TestProbeSchemeFollowsTheKeySet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		tls  bool
		want corev1.URIScheme
	}{
		{"plain", false, corev1.URISchemeHTTP},
		{"tls", true, corev1.URISchemeHTTPS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gatewayWithClass("edge", "infra", "tsjwt")
			sts, err := gateway.StatefulSet(g, gateway.Config{
				Image: "img", CredentialSecret: "creds", Tag: "tag:example",
				JWKSOverTLS: tc.tls,
			}, "tenants")
			if err != nil {
				t.Fatalf("statefulset: %v", err)
			}
			c := sts.Spec.Template.Spec.Containers[0]
			for _, p := range []*corev1.Probe{c.ReadinessProbe, c.LivenessProbe} {
				if p == nil || p.HTTPGet == nil {
					t.Fatal("missing probe")
				}
				if p.HTTPGet.Scheme != tc.want {
					t.Fatalf("probe scheme = %q, want %q", p.HTTPGet.Scheme, tc.want)
				}
			}
		})
	}
}

// TestTwoGatewaysInOneNamespace is the case that found the shared
// ServiceAccount. Everything a Gateway provisions is owned by it, and two
// Gateways cannot own the same object: the second reconcile failed with
// "already owned by another Gateway" and provisioned nothing at all.
func TestTwoGatewaysInOneNamespace(t *testing.T) {
	t.Parallel()
	gc := gatewayClass("tsjwt", gateway.ControllerName)
	a := gatewayWithClass("alpha", "infra", "tsjwt")
	b := gatewayWithClass("beta", "infra", "tsjwt")

	r, c := newReconciler(t, gc, a, b)
	ctx := context.Background()
	for _, name := range []string{"alpha", "beta"} {
		if _, err := r.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Namespace: "infra", Name: name}}); err != nil {
			t.Fatalf("reconcile %s: %v", name, err)
		}
	}

	// Each Gateway gets its own set, owned by itself.
	for _, tc := range []struct{ gw, sa, sts string }{
		{"alpha", "tsjwt-alpha-dataplane", "tsjwt-alpha"},
		{"beta", "tsjwt-beta-dataplane", "tsjwt-beta"},
	} {
		var sa corev1.ServiceAccount
		if err := c.Get(ctx, types.NamespacedName{Namespace: "infra", Name: tc.sa}, &sa); err != nil {
			t.Fatalf("%s: service account: %v", tc.gw, err)
		}
		if o := sa.GetOwnerReferences(); len(o) != 1 || o[0].Name != tc.gw {
			t.Fatalf("%s: account owned by %v, want its own Gateway", tc.gw, o)
		}
		var sts appsv1.StatefulSet
		if err := c.Get(ctx, types.NamespacedName{Namespace: "infra", Name: tc.sts}, &sts); err != nil {
			t.Fatalf("%s: statefulset: %v", tc.gw, err)
		}
		if got := sts.Spec.Template.Spec.ServiceAccountName; got != tc.sa {
			t.Fatalf("%s: runs as %q, want %q", tc.gw, got, tc.sa)
		}
	}
}
