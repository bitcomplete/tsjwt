package gateway

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

// Config is what the controller needs to know about its own deployment in
// order to provision data planes that look like it.
type Config struct {
	// Image is the data plane image. Required.
	Image string

	// ServiceAccount the data plane runs as. It needs no Kubernetes
	// access for routes — they arrive in a mounted ConfigMap — but it may
	// need access to publish verification keys.
	ServiceAccount string

	// CredentialSecret holds TS_OAUTH_CLIENT_ID and
	// TS_OAUTH_CLIENT_SECRET, used to mint a tailnet auth key at startup.
	// Required.
	CredentialSecret string

	// Tag is the tailnet tag minted keys carry. Required.
	Tag string

	// StorageClass backs each data plane's volume. Empty uses the
	// cluster default.
	StorageClass string

	// Zone pins data planes to one failure domain, when a cluster needs
	// it. Optional.
	Zone string

	// JWKSOverTLS makes every Gateway serve its key set over HTTPS. Prefer
	// the per-Gateway annotation: whether TLS is needed depends on the
	// consumer, and serving it where nothing needs it forces every
	// consumer to reach the gateway by its tailnet name.
	JWKSOverTLS bool

	// Capability is the tailnet capability carrying a caller's groups.
	// Empty uses the library default.
	//
	// It has to match the grant in the tailnet policy, and when it does
	// not the failure is quiet: WhoIs returns an empty capability map,
	// every caller resolves to no group and therefore no tenant, and the
	// gateway answers 403 to everyone. That looks like an authorization
	// bug rather than a name that does not match.
	Capability string
}

// names derives the resource names for one Gateway. They are derived rather
// than configurable so that a Gateway and everything it owns can always be
// found from the Gateway's own name.
type names struct{ gw *gwapi.Gateway }

func (n names) statefulSet() string { return "tsjwt-" + n.gw.Name }
func (n names) service() string     { return "tsjwt-" + n.gw.Name }
func (n names) routes() string      { return "tsjwt-" + n.gw.Name + "-routes" }
func (n names) keys() string        { return "tsjwt-" + n.gw.Name + "-keys" }

// serviceAccount is per Gateway, like everything else here. A shared account
// cannot be owned by a Gateway, and two Gateways in one namespace then fight
// over it: the second reconcile fails with "already owned by another
// Gateway". Per-Gateway naming also keeps one Gateway's data planes from
// holding another's permissions.
func (n names) serviceAccount() string { return "tsjwt-" + n.gw.Name + "-dataplane" }

// hostname is the name this Gateway answers to on the tailnet.
//
// A listener hostname is the Gateway API way to say "this is the name I
// serve", so it is used when given: its first label becomes the node's name,
// and the node is then reachable at exactly the name the Gateway declares.
// Without one the pod name is used, which works but reads as an
// implementation detail — tsjwt-grafana-0 rather than grafana.
//
// One replica only. Two data planes cannot both claim one name, so a Gateway
// that declares a hostname and runs more than one replica would have them
// fight over it. A single name across replicas needs a Tailscale Service,
// which is the unsolved half of running more than one.
func (n names) hostname() string {
	for _, l := range n.gw.Spec.Listeners {
		if l.Hostname == nil || *l.Hostname == "" {
			continue
		}
		h := string(*l.Hostname)
		if strings.HasPrefix(h, "*.") {
			continue // a wildcard is not a name this node can take
		}
		if label, _, ok := strings.Cut(h, "."); ok && label != "" {
			return label
		}
		return h
	}
	return n.gw.Name
}

func (n names) labels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "tsjwt",
		"app.kubernetes.io/managed-by": "tsjwt-gateway-controller",
		"tsjwt.dev/gateway":            n.gw.Name,
	}
}

// RoutesConfigMap is the ConfigMap the data plane mounts. It is the only
// channel between the controller and the data plane, which is why the data
// plane needs no Kubernetes access to serve.
func RoutesConfigMap(gw *gwapi.Gateway, rendered string) *corev1.ConfigMap {
	n := names{gw}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: n.routes(), Namespace: gw.Namespace, Labels: n.labels(),
		},
		Data: map[string]string{"routes.json": rendered},
	}
}

// Service exposes the data plane's key set and health to the cluster.
//
// It deliberately does not expose the proxy. Callers reach that over
// WireGuard, which never enters the cluster network, so there is nothing for
// a Service to balance. Verification is different: a backend fetches the key
// set over the cluster network, and any replica can answer.
func Service(gw *gwapi.Gateway) *corev1.Service {
	n := names{gw}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: n.service(), Namespace: gw.Namespace, Labels: n.labels(),
		},
		Spec: corev1.ServiceSpec{
			Selector: n.labels(),
			Ports: []corev1.ServicePort{{
				Name: "jwks", Port: 9100, TargetPort: intstr.FromString("jwks"),
			}},
		},
	}
}

// DataPlaneServiceAccount is the account a Gateway's data planes run as.
//
// It is provisioned per Gateway namespace rather than installed once,
// because a Gateway may live in any namespace and its data planes run beside
// it. Installing a single account in the controller's namespace does not
// help: a pod can only use an account in its own.
func DataPlaneServiceAccount(gw *gwapi.Gateway) *corev1.ServiceAccount {
	n := names{gw}
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: n.serviceAccount(), Namespace: gw.Namespace, Labels: n.labels(),
		},
	}
}

// JWKSOverTLSAnnotation makes one Gateway serve its key set over HTTPS.
//
// Whether TLS is needed is a property of the consumer, not of the cluster:
// Grafana refuses a key set over plain HTTP, and a backend in the same
// namespace is happy with the Service name. Serving TLS everywhere means
// every consumer must reach the gateway by its tailnet name, which needs the
// gateway's Service address pinned in the consumer's DNS — an address that
// is not known until the Gateway exists.
//
// So it is per Gateway, and defaults off.
const JWKSOverTLSAnnotation = "tsjwt.dev/jwks-tls"

// KeysRole lets one Gateway's data planes publish their verification keys,
// and nothing else.
//
// The Role is provisioned per Gateway rather than installed once because the
// ConfigMap name depends on the Gateway. A static Role could only be written
// by granting get and update on every ConfigMap in the namespace, which would
// include the data plane's own route table — the one thing it must not be
// able to rewrite.
func KeysRole(gw *gwapi.Gateway) *rbacv1.Role {
	n := names{gw}
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name: n.keys(), Namespace: gw.Namespace, Labels: n.labels(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				// create cannot be name-scoped by the API, so it is
				// granted on the resource. The name-scoped verbs below
				// are what keep this narrow.
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups:     []string{""},
				Resources:     []string{"configmaps"},
				ResourceNames: []string{n.keys()},
				Verbs:         []string{"get", "update"},
			},
		},
	}
}

// KeysRoleBinding binds [KeysRole] to the data plane's account.
func KeysRoleBinding(gw *gwapi.Gateway) *rbacv1.RoleBinding {
	n := names{gw}
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: n.keys(), Namespace: gw.Namespace, Labels: n.labels(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName, Kind: "Role", Name: n.keys(),
		},
		Subjects: []rbacv1.Subject{{
			Kind: "ServiceAccount", Name: n.serviceAccount(), Namespace: gw.Namespace,
		}},
	}
}

// StatefulSet provisions the data plane for one Gateway.
//
// A StatefulSet and not a Deployment, for two reasons that both come from the
// data plane being its own tailnet node. Each replica needs its own tailnet
// state, which is a node key and so cannot be shared. And each needs a stable
// name, because the tailnet hostname comes from the pod name: without that, a
// rescheduled replica registers as a new node and abandons the old one.
func StatefulSet(gw *gwapi.Gateway, cfg Config, tenantsConfigMap string) (*appsv1.StatefulSet, error) {
	if cfg.Image == "" {
		return nil, fmt.Errorf("gateway: Config.Image is required")
	}
	if cfg.CredentialSecret == "" {
		return nil, fmt.Errorf("gateway: Config.CredentialSecret is required")
	}
	if cfg.Tag == "" {
		return nil, fmt.Errorf("gateway: Config.Tag is required")
	}
	n := names{gw}
	replicas := int32(1)

	// The probes share the port the key set is on, so they have to follow
	// its scheme. Enabling TLS without this leaves the kubelet speaking
	// HTTP to an HTTPS listener, every probe failing, and the pod
	// restarting for a reason the pod's own logs describe only as a
	// handshake error. The kubelet does not verify the certificate, so a
	// certificate for a name it is not using is fine.
	probeScheme := corev1.URISchemeHTTP
	if cfg.JWKSOverTLS || gw.Annotations[JWKSOverTLSAnnotation] == "true" {
		probeScheme = corev1.URISchemeHTTPS
	}

	args := []string{
		"-gateway=" + gw.Namespace + "/" + gw.Name,
		hostnameArg(gw),
		"-routes=/etc/tsjwt/routes.json",
		"-state-dir=/var/lib/tsjwt",
		"-tenants=/etc/tsjwt-tenants/tenants.json",
		"-issuer=https://" + n.hostname(),
		"-listen=:443",
		"-jwks-listen=0.0.0.0:9100",
		"-key-tags=" + cfg.Tag,
		"-share-keys=" + n.keys(),
	}

	env := []corev1.EnvVar{
		{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
		{Name: "TS_OAUTH_CLIENT_ID", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: cfg.CredentialSecret},
				Key:                  "TS_OAUTH_CLIENT_ID"}}},
		{Name: "TS_OAUTH_CLIENT_SECRET", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: cfg.CredentialSecret},
				Key:                  "TS_OAUTH_CLIENT_SECRET"}}},
	}

	nonRoot := true
	noEscalate := false
	readOnlyRoot := true
	uid := int64(65532)

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: n.statefulSet(), Namespace: gw.Namespace, Labels: n.labels(),
		},
		Spec: appsv1.StatefulSetSpec{
			ServiceName:         n.service(),
			Replicas:            &replicas,
			PodManagementPolicy: appsv1.ParallelPodManagement,
			Selector:            &metav1.LabelSelector{MatchLabels: n.labels()},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: n.labels()},
				Spec: corev1.PodSpec{
					ServiceAccountName: n.serviceAccount(),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &nonRoot,
						// Distroless names its user, and the kubelet
						// cannot check a name against RunAsNonRoot.
						RunAsUser:      &uid,
						RunAsGroup:     &uid,
						FSGroup:        &uid,
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:    "tsjwt",
						Image:   cfg.Image,
						Command: []string{"/usr/local/bin/tsjwt-dataplane"},
						Args:    args,
						Env:     env,
						Ports: []corev1.ContainerPort{
							{Name: "jwks", ContainerPort: 9100},
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "state", MountPath: "/var/lib/tsjwt"},
							{Name: "routes", MountPath: "/etc/tsjwt", ReadOnly: true},
							{Name: "tenants", MountPath: "/etc/tsjwt-tenants", ReadOnly: true},
						},
						// Readiness, not liveness, for the route table.
						// A data plane with no routes yet is starting,
						// not broken, and restarting it would not help.
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
								Path: "/readyz", Port: intstr.FromString("jwks"), Scheme: probeScheme}},
							PeriodSeconds:    5,
							FailureThreshold: 24,
						},
						// Liveness tracks the auth key, which the data
						// plane reports unhealthy on before it expires
						// so the restart is scheduled rather than an
						// outage.
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
								Path: "/healthz", Port: intstr.FromString("jwks"), Scheme: probeScheme}},
							InitialDelaySeconds: 10,
							PeriodSeconds:       30,
							FailureThreshold:    4,
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &noEscalate,
							ReadOnlyRootFilesystem:   &readOnlyRoot,
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("10m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("256Mi"),
							},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "routes", VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: n.routes()},
								// Optional, so a data plane starts before
								// the controller has rendered anything.
								// It serves 503 until routes arrive,
								// rather than failing to mount.
								Optional: boolPtr(true),
							}}},
						{Name: "tenants", VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: tenantsConfigMap},
							}}},
					},
				},
			},
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{
				ObjectMeta: metav1.ObjectMeta{Name: "state"},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: resource.MustParse("1Gi"),
						}},
				},
			}},
		},
	}
	if cfg.StorageClass != "" {
		sts.Spec.VolumeClaimTemplates[0].Spec.StorageClassName = &cfg.StorageClass
	}
	if cfg.JWKSOverTLS || gw.Annotations[JWKSOverTLSAnnotation] == "true" {
		sts.Spec.Template.Spec.Containers[0].Args = append(
			sts.Spec.Template.Spec.Containers[0].Args, "-jwks-tls")
	}
	if cfg.Capability != "" {
		sts.Spec.Template.Spec.Containers[0].Args = append(
			sts.Spec.Template.Spec.Containers[0].Args, "-cap="+cfg.Capability)
	}
	if cfg.Zone != "" {
		sts.Spec.Template.Spec.NodeSelector = map[string]string{
			"topology.kubernetes.io/zone": cfg.Zone,
		}
	}
	return sts, nil
}

// hostnameArg gives the data plane its tailnet name. A Gateway that declares
// a listener hostname gets that name; otherwise the pod's, which is stable
// because this is a StatefulSet.
func hostnameArg(gw *gwapi.Gateway) string {
	if h := (names{gw}).hostname(); h != gw.Name {
		return "-hostname=" + h
	}
	return "-hostname=$(POD_NAME)"
}

func boolPtr(b bool) *bool { return &b }
