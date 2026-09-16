package gateway

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bitcomplete/tsjwt/routetable"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

// GatewayClassReconciler accepts the GatewayClasses that name this
// implementation and ignores the rest. A cluster may run several
// implementations side by side; each reconciles only its own.
type GatewayClassReconciler struct {
	client.Client
}

// Reconcile implements [reconcile.Reconciler].
func (r *GatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var gc gwapi.GatewayClass
	if err := r.Get(ctx, req.NamespacedName, &gc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if string(gc.Spec.ControllerName) != ControllerName {
		return ctrl.Result{}, nil
	}
	meta.setCondition(&gc.Status.Conditions, metav1.Condition{
		Type:               string(gwapi.GatewayClassConditionStatusAccepted),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gc.Generation,
		Reason:             string(gwapi.GatewayClassReasonAccepted),
		Message:            "accepted by tsjwt",
	})
	return ctrl.Result{}, r.Status().Update(ctx, &gc)
}

// SetupWithManager registers the reconciler.
func (r *GatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&gwapi.GatewayClass{}).Complete(r)
}

// GatewayReconciler provisions a data plane for each Gateway and keeps its
// route table rendered.
//
// Rendering here rather than in the data plane is what lets the data plane
// run without Kubernetes access. It resolves routes once, writes them to a
// ConfigMap, and the kubelet delivers them.
type GatewayReconciler struct {
	client.Client
	Config Config

	// TenantsConfigMap holds the tenant policy every data plane mounts.
	// Required.
	TenantsConfigMap string
}

// Reconcile implements [reconcile.Reconciler].
func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var gw gwapi.Gateway
	if err := r.Get(ctx, req.NamespacedName, &gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Only Gateways whose class names this implementation.
	var gc gwapi.GatewayClass
	if err := r.Get(ctx, types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}, &gc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if string(gc.Spec.ControllerName) != ControllerName {
		return ctrl.Result{}, nil
	}

	// Render the routes first. Provisioning a data plane that then finds
	// no route table is a worse first impression than the reverse, and
	// the ConfigMap mount is optional so it can be written either way.
	rendered, routeCount, routeErrs, err := r.render(ctx, &gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	cm := RoutesConfigMap(&gw, rendered)
	if err := r.apply(ctx, &gw, cm, func() error {
		cm.Data = map[string]string{"routes.json": rendered}
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("routes ConfigMap: %w", err)
	}

	// The account the data plane runs as must exist in the Gateway's own
	// namespace: a pod can only use an account in its own namespace, so an
	// account installed beside the controller would not do.
	sa := DataPlaneServiceAccount(&gw)
	if err := r.apply(ctx, &gw, sa, func() error { return nil }); err != nil {
		return ctrl.Result{}, fmt.Errorf("data plane ServiceAccount: %w", err)
	}

	// The data plane publishes its verification keys, so it needs a Role
	// naming exactly that ConfigMap. Provisioned per Gateway because the
	// name depends on the Gateway.
	role := KeysRole(&gw)
	if err := r.apply(ctx, &gw, role, func() error {
		role.Rules = KeysRole(&gw).Rules
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("keys Role: %w", err)
	}
	rb := KeysRoleBinding(&gw)
	if err := r.apply(ctx, &gw, rb, func() error {
		want := KeysRoleBinding(&gw)
		rb.RoleRef = want.RoleRef
		rb.Subjects = want.Subjects
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("keys RoleBinding: %w", err)
	}

	svc := Service(&gw)
	if err := r.apply(ctx, &gw, svc, func() error {
		svc.Spec.Selector = names{&gw}.labels()
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("service: %w", err)
	}

	want, err := StatefulSet(&gw, r.Config, r.TenantsConfigMap)
	if err != nil {
		return ctrl.Result{}, err
	}
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Name: want.Name, Namespace: want.Namespace}}
	if err := r.apply(ctx, &gw, sts, func() error {
		// VolumeClaimTemplates cannot be changed after creation, so
		// only the mutable half is reconciled. A change that needs new
		// storage needs the Gateway recreating, and saying so beats
		// failing every reconcile from here on.
		sts.Labels = want.Labels
		sts.Spec.Replicas = want.Spec.Replicas
		sts.Spec.Selector = want.Spec.Selector
		sts.Spec.ServiceName = want.Spec.ServiceName
		sts.Spec.PodManagementPolicy = want.Spec.PodManagementPolicy
		sts.Spec.Template = want.Spec.Template
		if len(sts.Spec.VolumeClaimTemplates) == 0 {
			sts.Spec.VolumeClaimTemplates = want.Spec.VolumeClaimTemplates
		}
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("statefulset: %w", err)
	}

	l.Info("reconciled", "gateway", req.NamespacedName, "routes", routeCount,
		"rejected", len(routeErrs))
	return ctrl.Result{}, r.status(ctx, &gw, sts, routeCount)
}

// render resolves the Gateway's routes and returns the file the data plane
// reads.
func (r *GatewayReconciler) render(ctx context.Context, gw *gwapi.Gateway) (string, int, []RouteError, error) {
	var routes gwapi.HTTPRouteList
	if err := r.List(ctx, &routes); err != nil {
		return "", 0, nil, fmt.Errorf("list HTTPRoutes: %w", err)
	}
	var services corev1.ServiceList
	if err := r.List(ctx, &services); err != nil {
		return "", 0, nil, fmt.Errorf("list Services: %w", err)
	}

	table, errs := Translate(gw, routes.Items, services.Items)
	// The generation is a usable revision: it changes when the Gateway
	// does, and the data plane only uses it for logs and readiness.
	file := routetable.Render(gw.Namespace+"/"+gw.Name, gw.Generation, table)
	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return "", 0, nil, err
	}
	return string(b) + "\n", len(table), errs, nil
}

// apply creates or updates an object owned by the Gateway, so that deleting
// the Gateway removes everything it provisioned.
func (r *GatewayReconciler) apply(ctx context.Context, gw *gwapi.Gateway, obj client.Object, mutate func() error) error {
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, obj, func() error {
		if err := mutate(); err != nil {
			return err
		}
		return controllerutil.SetControllerReference(gw, obj, r.Scheme())
	})
	return err
}

// status reports what the Gateway is doing, which is how anyone using
// Gateway API expects to find out.
func (r *GatewayReconciler) status(ctx context.Context, gw *gwapi.Gateway, sts *appsv1.StatefulSet, routeCount int) error {
	n := names{gw}

	meta.setCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               string(gwapi.GatewayConditionAccepted),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gw.Generation,
		Reason:             string(gwapi.GatewayReasonAccepted),
		Message:            "accepted by tsjwt",
	})

	// Programmed means the data plane is actually serving, not merely
	// that the objects exist. A Gateway that claims to be programmed
	// while its pod is not ready is the kind of status nobody trusts
	// twice.
	programmed := metav1.ConditionFalse
	reason := string(gwapi.GatewayReasonPending)
	msg := "the data plane is not ready yet"
	if sts.Status.ReadyReplicas > 0 {
		programmed = metav1.ConditionTrue
		reason = string(gwapi.GatewayReasonProgrammed)
		msg = fmt.Sprintf("%d replica(s) ready, serving %d route(s)",
			sts.Status.ReadyReplicas, routeCount)
	}
	meta.setCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               string(gwapi.GatewayConditionProgrammed),
		Status:             programmed,
		ObservedGeneration: gw.Generation,
		Reason:             reason,
		Message:            msg,
	})

	// The address is the tailnet name. It is a hostname rather than an
	// IP because that is what callers use, and because a tailnet address
	// means nothing to anyone off the tailnet.
	if sts.Status.ReadyReplicas > 0 {
		hostType := gwapi.HostnameAddressType
		gw.Status.Addresses = []gwapi.GatewayStatusAddress{{
			Type: &hostType, Value: n.hostname(),
		}}
	}
	return r.Status().Update(ctx, gw)
}

// SetupWithManager registers the reconciler, including the watches that make
// a route change reach the Gateway that serves it.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// An HTTPRoute change has to re-render the Gateway it is attached to.
	// Without this the table would only update when the Gateway itself
	// changed, which is almost never.
	routeToGateways := handler.EnqueueRequestsFromMapFunc(
		func(_ context.Context, obj client.Object) []reconcile.Request {
			hr, ok := obj.(*gwapi.HTTPRoute)
			if !ok {
				return nil
			}
			var out []reconcile.Request
			for _, p := range hr.Spec.ParentRefs {
				if p.Kind != nil && *p.Kind != "Gateway" {
					continue
				}
				ns := hr.Namespace
				if p.Namespace != nil {
					ns = string(*p.Namespace)
				}
				out = append(out, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: ns, Name: string(p.Name)},
				})
			}
			return out
		})

	return ctrl.NewControllerManagedBy(mgr).
		For(&gwapi.Gateway{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Watches(&gwapi.HTTPRoute{}, routeToGateways).
		Complete(r)
}

// meta holds the small condition helpers, so the reconcilers above read as
// intent rather than as list manipulation.
var meta = conditionHelpers{}

type conditionHelpers struct{}

// setCondition replaces a condition of the same type, preserving the
// transition time when the status has not changed. A transition time that
// moves on every reconcile makes it impossible to see when something
// actually broke.
func (conditionHelpers) setCondition(conds *[]metav1.Condition, c metav1.Condition) {
	if c.LastTransitionTime.IsZero() {
		c.LastTransitionTime = metav1.Now()
	}
	for i := range *conds {
		if (*conds)[i].Type != c.Type {
			continue
		}
		if (*conds)[i].Status == c.Status {
			c.LastTransitionTime = (*conds)[i].LastTransitionTime
		}
		(*conds)[i] = c
		return
	}
	*conds = append(*conds, c)
}

var _ = apierrors.IsNotFound
