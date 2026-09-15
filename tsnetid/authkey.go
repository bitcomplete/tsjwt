package tsnetid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuthKeyMinter exchanges a long-lived OAuth client for a short-lived tailnet
// auth key.
//
// This inverts the usual arrangement, and deliberately. Holding a static auth
// key means holding a credential that expires on a date nobody is watching:
// the node keeps running long after the key dies, because a tagged node does
// not expire its node key, and the failure only appears at the next restart —
// often months later, during something unrelated.
//
// Minting at startup instead means the key in use is never older than the
// process. The OAuth client is still long-lived, but it is not a key: it
// cannot join a node by itself, and it can be revoked in one place.
type AuthKeyMinter struct {
	// ClientID and ClientSecret identify the OAuth client. The client
	// needs the auth_keys scope and must own the tags below. Required.
	ClientID     string
	ClientSecret string

	// Tags are applied to the minted key, and so to the node that uses
	// it. Required: an untagged key would make the node a user's device.
	Tags []string

	// Ephemeral marks the node for automatic removal after it goes
	// offline. Leave false for a node whose identity should persist.
	Ephemeral bool

	// Validity is the lifetime requested for the key. The API caps this
	// at 90 days. A short lifetime is fine and preferable: the key is
	// used once, at startup, and never needed again while the process
	// lives.
	Validity time.Duration

	// BaseURL overrides the API endpoint. For tests.
	BaseURL string

	// Client is the HTTP client. Nil means a client with a 30s timeout.
	Client *http.Client
}

// AuthKey is a minted key and the moment it stops being usable.
type AuthKey struct {
	Key     string
	Expires time.Time
}

const defaultBaseURL = "https://api.tailscale.com"

// Mint obtains an access token with the client credentials, then creates a
// tailnet auth key with it.
func (m *AuthKeyMinter) Mint(ctx context.Context) (AuthKey, error) {
	var zero AuthKey
	switch {
	case m.ClientID == "" || m.ClientSecret == "":
		return zero, fmt.Errorf("tsnetid: OAuth client id and secret are both required")
	case len(m.Tags) == 0:
		return zero, fmt.Errorf("tsnetid: at least one tag is required, or the node " +
			"would join as a user's device rather than as a service")
	}
	validity := m.Validity
	if validity <= 0 {
		validity = 90 * 24 * time.Hour
	}

	token, err := m.token(ctx)
	if err != nil {
		return zero, err
	}
	return m.createKey(ctx, token, validity)
}

func (m *AuthKeyMinter) base() string {
	if m.BaseURL != "" {
		return m.BaseURL
	}
	return defaultBaseURL
}

func (m *AuthKeyMinter) httpClient() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// token runs the OAuth2 client-credentials exchange.
func (m *AuthKeyMinter) token(ctx context.Context) (string, error) {
	form := url.Values{
		"client_id":     {m.ClientID},
		"client_secret": {m.ClientSecret},
		"grant_type":    {"client_credentials"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.base()+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("tsnetid: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("tsnetid: token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The body can carry the secret back in an error echo, so it is
		// deliberately not included here.
		return "", fmt.Errorf("tsnetid: token request returned %s", resp.Status)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("tsnetid: decode token: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("tsnetid: token response carried no access token")
	}
	return out.AccessToken, nil
}

// createKey asks for a tagged, pre-authorized, reusable key.
func (m *AuthKeyMinter) createKey(ctx context.Context, token string, validity time.Duration) (AuthKey, error) {
	var zero AuthKey
	body, err := json.Marshal(map[string]any{
		"capabilities": map[string]any{
			"devices": map[string]any{
				"create": map[string]any{
					// Reusable so that a container restart inside the
					// same pod lifetime can reuse it.
					"reusable":      true,
					"ephemeral":     m.Ephemeral,
					"preauthorized": true,
					"tags":          m.Tags,
				},
			},
		},
		"expirySeconds": int64(validity.Seconds()),
		"description":   "minted at startup by tsjwtd",
	})
	if err != nil {
		return zero, fmt.Errorf("tsnetid: build key request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.base()+"/api/v2/tailnet/-/keys", strings.NewReader(string(body)))
	if err != nil {
		return zero, fmt.Errorf("tsnetid: build key request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient().Do(req)
	if err != nil {
		return zero, fmt.Errorf("tsnetid: create key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return zero, fmt.Errorf("tsnetid: create key returned %s", resp.Status)
	}
	var out struct {
		Key     string    `json:"key"`
		Expires time.Time `json:"expires"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return zero, fmt.Errorf("tsnetid: decode key: %w", err)
	}
	if out.Key == "" {
		return zero, fmt.Errorf("tsnetid: key response carried no key")
	}
	if out.Expires.IsZero() {
		out.Expires = time.Now().Add(validity)
	}
	return AuthKey{Key: out.Key, Expires: out.Expires}, nil
}

// Expiry reports when the in-use auth key stops working, and decides when a
// process should be replaced so that it never reaches that moment.
//
// The health check fails early, by a buffer plus a per-process splay. The
// buffer gives the orchestrator time to replace the process before anything
// is actually broken. The splay is what stops a set of replicas, all started
// together and therefore all holding keys that expire together, from failing
// their health checks in the same minute and going down as one.
type Expiry struct {
	mu      sync.RWMutex
	expires time.Time
	buffer  time.Duration
	splay   time.Duration
	now     func() time.Time
}

// NewExpiry returns a tracker that reports unhealthy once the key is within
// buffer+splay of expiring. The splay is drawn once, per process, uniformly
// from [minSplay, maxSplay].
func NewExpiry(expires time.Time, buffer, minSplay, maxSplay time.Duration) *Expiry {
	if maxSplay < minSplay {
		minSplay, maxSplay = maxSplay, minSplay
	}
	splay := minSplay
	if d := maxSplay - minSplay; d > 0 {
		splay += time.Duration(rand.Int64N(int64(d)))
	}
	return &Expiry{expires: expires, buffer: buffer, splay: splay, now: time.Now}
}

// Splay reports the jitter this process drew, for logging.
func (e *Expiry) Splay() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.splay
}

// DeadlineAt reports the moment this process starts reporting unhealthy.
func (e *Expiry) DeadlineAt() time.Time {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.expires.Add(-(e.buffer + e.splay))
}

// Healthy reports whether the key still has more than buffer+splay left.
func (e *Expiry) Healthy() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.expires.IsZero() {
		return true // nothing to expire: a static key with no known expiry
	}
	return e.now().Before(e.expires.Add(-(e.buffer + e.splay)))
}

// Set replaces the tracked expiry, for a process that renews in place.
func (e *Expiry) Set(t time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expires = t
}
