// Command tsjwt-controller implements Gateway API for tsjwt.
//
// It watches GatewayClasses that name this implementation, provisions a data
// plane for each Gateway that uses one, renders the attached HTTPRoutes into
// a ConfigMap the data plane mounts, and reports status.
//
// It does not sit in the request path. The data planes it provisions do, and
// they keep serving whether or not this process is running: the routes they
// hold are already mounted, and they cache the last table that parsed. That
// separation is deliberate — a control plane going down should not take
// traffic with it.
package main

import (
	"flag"
	"os"

	"github.com/bitcomplete/tsjwt/gateway"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

func main() {
	var (
		image      = flag.String("dataplane-image", "", "image for provisioned data planes (required)")
		secret     = flag.String("credential-secret", "tsjwt-credentials", "Secret holding the tailnet OAuth client")
		tag        = flag.String("tag", "", "tailnet tag for minted auth keys (required)")
		sa         = flag.String("dataplane-service-account", "tsjwt-dataplane", "ServiceAccount for data planes")
		tenants    = flag.String("tenants-configmap", "tsjwt-tenants", "ConfigMap holding the tenant policy")
		storage    = flag.String("storage-class", "", "storage class for data plane volumes")
		zone       = flag.String("zone", "", "pin data planes to one zone")
		capability = flag.String("capability", "", "tailnet capability carrying caller groups; must match the tailnet policy grant")
		jwksTLS    = flag.Bool("jwks-tls", false, "data planes serve the key set over HTTPS, for verifiers that refuse plain HTTP")
		metricsRef = flag.String("metrics-bind-address", ":8080", "metrics address")
		probeAddr  = flag.String("health-probe-bind-address", ":8081", "health probe address")
		leader     = flag.Bool("leader-elect", true, "run only one active controller at a time")
	)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("setup")

	if *image == "" || *tag == "" {
		log.Error(nil, "-dataplane-image and -tag are both required")
		os.Exit(2)
	}

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, rbacv1.AddToScheme, gwapi.Install,
	} {
		if err := add(scheme); err != nil {
			log.Error(err, "registering types")
			os.Exit(1)
		}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: *metricsRef},
		HealthProbeBindAddress: *probeAddr,
		LeaderElection:         *leader,
		LeaderElectionID:       "tsjwt-gateway-controller.tsjwt.dev",
	})
	if err != nil {
		log.Error(err, "creating the manager")
		os.Exit(1)
	}

	if err := (&gateway.GatewayClassReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Error(err, "registering the GatewayClass reconciler")
		os.Exit(1)
	}
	if err := (&gateway.GatewayReconciler{
		Client: mgr.GetClient(),
		Config: gateway.Config{
			Image:            *image,
			ServiceAccount:   *sa,
			CredentialSecret: *secret,
			Tag:              *tag,
			StorageClass:     *storage,
			Zone:             *zone,
			Capability:       *capability,
			JWKSOverTLS:      *jwksTLS,
		},
		TenantsConfigMap: *tenants,
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "registering the Gateway reconciler")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		log.Error(err, "adding the health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		log.Error(err, "adding the readiness check")
		os.Exit(1)
	}

	log.Info("starting", "controller", gateway.ControllerName, "image", *image, "tag", *tag)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "running the manager")
		os.Exit(1)
	}
}
