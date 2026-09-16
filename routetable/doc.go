// Package routetable is the contract between a control plane that decides
// routes and a data plane that serves them.
//
// It is in the core module, and imports only the standard library, for one
// reason: the data plane must be buildable and runnable without the
// Kubernetes libraries. A component whose job is to keep serving should not
// depend on the API server, and the shape of that independence is that it
// reads a file rather than a resource.
package routetable
