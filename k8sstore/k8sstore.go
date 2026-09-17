// Package k8sstore keeps the published key set in a Kubernetes ConfigMap.
//
// A ConfigMap, not a Secret, and the choice is the point. Only public
// verification keys go here, so there is nothing to protect from a reader.
// Storing them somewhere that announces it holds no secrets makes that
// property visible to anyone auditing the deployment, instead of leaving it
// to be inferred.
//
// It speaks to the API server with the standard library alone, using the
// service account the pod already has, so the core module keeps its
// dependency-free property.
package k8sstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bitcomplete/tsjwt/keys"
)

const (
	tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // path, not a credential
	caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	nsPath    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	// dataKey is the ConfigMap key the entries live under.
	dataKey = "keys.json"
)

// Store implements [keys.Store] over a ConfigMap.
//
// Optimistic concurrency uses the ConfigMap's resourceVersion, which the API
// server rejects on a stale write with 409. That is exactly the semantics
// keys.Store asks for, so no locking is needed: a replica that loses a race
// reloads and republishes.
type Store struct {
	// Name is the ConfigMap name. Required.
	Name string
	// Namespace defaults to the pod's own namespace.
	Namespace string
	// Host defaults to the in-cluster API server.
	Host string
	// Client defaults to one trusting the cluster CA.
	Client *http.Client
	// Token, when set, is used verbatim on every request and never
	// refreshed. Leave it empty in a cluster: a projected service account
	// token expires, and the kubelet rewrites the file before it does, so a
	// token read once at startup stops working within the hour. An empty
	// Token makes each request read TokenPath instead. Set it only for a
	// test or a caller that manages rotation itself.
	Token string
	// TokenPath is the service account token file, read on each request
	// unless Token is set. Empty means the default in-pod path.
	TokenPath string
}

// bearer returns the token to present on a request. A fixed Token wins; other-
// wise the file is read afresh, so a rotated token is picked up without a
// restart.
func (s *Store) bearer() (string, error) {
	if s.Token != "" {
		return s.Token, nil
	}
	path := s.TokenPath
	if path == "" {
		path = tokenPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("k8sstore: read service account token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// New returns a store configured from the pod's service account.
func New(name string) (*Store, error) {
	if name == "" {
		return nil, errors.New("k8sstore: ConfigMap name is required")
	}
	ns, err := os.ReadFile(nsPath)
	if err != nil {
		return nil, fmt.Errorf("k8sstore: read namespace (is this running in a pod?): %w", err)
	}
	// Read the token once here only to fail fast when this is not running in
	// a pod. The value is deliberately not kept: each request reads the file
	// again through bearer, so a rotated token is picked up (see F1).
	if _, err := os.ReadFile(tokenPath); err != nil {
		return nil, fmt.Errorf("k8sstore: read service account token: %w", err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("k8sstore: read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("k8sstore: cluster CA is not valid PEM")
	}
	host := "https://kubernetes.default.svc"
	if h := os.Getenv("KUBERNETES_SERVICE_HOST"); h != "" {
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		if port == "" {
			port = "443"
		}
		host = "https://" + h + ":" + port
	}
	return &Store{
		Name:      name,
		Namespace: strings.TrimSpace(string(ns)),
		Host:      host,
		Client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			},
		},
	}, nil
}

func (s *Store) url() string {
	return fmt.Sprintf("%s/api/v1/namespaces/%s/configmaps/%s", s.Host, s.Namespace, s.Name)
}

func (s *Store) do(ctx context.Context, method, url string, body []byte, contentType string) (int, []byte, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return 0, nil, err
	}
	tok, err := s.bearer()
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, err
}

type configMap struct {
	Metadata struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace,omitempty"`
		ResourceVersion string `json:"resourceVersion,omitempty"`
	} `json:"metadata"`
	Data map[string]string `json:"data,omitempty"`
}

// Load implements [keys.Store].
//
// A missing ConfigMap is an empty set with an empty version, not an error:
// the first replica to start finds nothing, and that is normal.
func (s *Store) Load(ctx context.Context) ([]keys.Entry, string, error) {
	code, body, err := s.do(ctx, http.MethodGet, s.url(), nil, "")
	if err != nil {
		return nil, "", fmt.Errorf("k8sstore: load: %w", err)
	}
	if code == http.StatusNotFound {
		return nil, "", nil
	}
	if code != http.StatusOK {
		return nil, "", fmt.Errorf("k8sstore: load returned %d: %s", code, summarize(body))
	}
	var cm configMap
	if err := json.Unmarshal(body, &cm); err != nil {
		return nil, "", fmt.Errorf("k8sstore: parse ConfigMap: %w", err)
	}
	entries, err := keys.UnmarshalEntries([]byte(cm.Data[dataKey]))
	if err != nil {
		return nil, "", err
	}
	return entries, cm.Metadata.ResourceVersion, nil
}

// Save implements [keys.Store]. An empty version creates the ConfigMap; a
// non-empty one updates it only if the store is still at that version.
func (s *Store) Save(ctx context.Context, entries []keys.Entry, version string) error {
	payload, err := keys.MarshalEntries(entries)
	if err != nil {
		return err
	}
	var cm configMap
	cm.Metadata.Name = s.Name
	cm.Metadata.Namespace = s.Namespace
	cm.Metadata.ResourceVersion = version
	cm.Data = map[string]string{dataKey: string(payload)}
	body, err := json.Marshal(cm)
	if err != nil {
		return err
	}

	method, url := http.MethodPut, s.url()
	if version == "" {
		// Create. A 409 here means another replica created it first,
		// which is the same "reload and retry" situation as a stale
		// update.
		method = http.MethodPost
		url = fmt.Sprintf("%s/api/v1/namespaces/%s/configmaps", s.Host, s.Namespace)
	}
	code, respBody, err := s.do(ctx, method, url, body, "application/json")
	if err != nil {
		return fmt.Errorf("k8sstore: save: %w", err)
	}
	switch {
	case code == http.StatusOK || code == http.StatusCreated:
		return nil
	case code == http.StatusConflict:
		return keys.ErrConflict
	default:
		return fmt.Errorf("k8sstore: save returned %d: %s", code, summarize(respBody))
	}
}

// summarize keeps an API error readable without dumping a whole response.
func summarize(b []byte) string {
	var status struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(b, &status) == nil && status.Message != "" {
		return status.Message
	}
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}
