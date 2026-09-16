// Package gateway implements the Kubernetes Gateway API for tsjwt.
//
// The data plane has to be this project's own proxy rather than a general
// one. A Gateway that terminates the tailnet connection is the only thing
// that can ask the tailnet who the caller is, and that question is the whole
// point: anything downstream of a terminating proxy sees the proxy's address,
// not the caller's.
//
// So this is not a thin controller in front of Envoy. The controller
// provisions tsnet nodes, and those nodes route.
//
// It is a separate Go module because it needs the Kubernetes and Gateway API
// libraries, and the core of tsjwt imports only the standard library. A
// backend that merely verifies tokens should take on neither.
package gateway

// ControllerName is the GatewayClass controllerName this implementation
// claims. A cluster may run several implementations; each one reconciles only
// the GatewayClasses naming it.
const ControllerName = "tsjwt.dev/gateway-controller"
