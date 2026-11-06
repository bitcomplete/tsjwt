# Waiting for sleeping backends

A tsjwt Gateway can hold authorized requests until the configured upstream is
connectable. The tailnet listener and WhoIs identity lookup remain inside tsjwt.
Waiting is disabled by default. Enable it only after the platform has a working
external demand metric and autoscaler for every backend of the Gateway:

```yaml
metadata:
  annotations:
    tsjwt.dev/backend-wait-timeout: 60s
```

The controller validates a positive duration of at most two minutes and passes
it to the data plane as `-backend-wait-timeout`. Standalone data planes accept
that flag and `-backend-wait-max-pending` (default 128 per upstream).

Requests are authorized before they register demand. Each request waits at most
the configured timeout, or until its caller disconnects. Concurrent waiters
share a readiness probe per upstream. The default probe opens a TCP connection
to the configured upstream; for Kubernetes Services this relies on normal
ready-endpoint publication. Do not use publishNotReadyAddresses or an upstream
proxy that accepts connections before the target app is ready. Core consumers
can inject a stronger readiness probe using WaitConfig.Ready.

On readiness, the proxy reauthorizes the caller and mints a fresh assertion,
then forwards the original request once. The tenant selected on arrival stays
pinned through the wait, even if the caller's default changes; loss of access
to that tenant returns 403 rather than falling back to another tenant. It does not retry application requests
or replay POST bodies after forwarding. Failure or queue saturation returns 503
with Retry-After. Waiting does not read/buffer the body; memory used for waiting
requests is bounded by request limits rather than body size. Active requests,
including upgraded connections, remain demand until proxying finishes.

The gate exports the following on `/metrics` on the existing internal operations
listener (the listener serving JWKS and health), respecting its TLS setting:

- `tsjwt_backend_pending_requests{upstream="..."}`
- `tsjwt_backend_active_requests{upstream="..."}`
- `tsjwt_backend_last_activity_seconds{upstream="..."}`

These are process-local metrics keyed by configured upstream URL, shared across
route reloads. The platform must map ExternalName bridges and alternate ingress
paths to a stable backend identity and sum pending/active demand across them.
Retain a nonzero recommendation for the chosen idle window using last activity.
Metrics exist after the first authorized request, remain explicit zero when idle,
and are absent after restart until demand is seen again. Missing/stale metrics
must fail safe and never be converted to idle zero. Backends are retained for
explicit zero publication; a process admits at most 256 unique upstreams over
its lifetime, after which new ones return 503 until restarted. Labels never
contain caller-supplied hosts or paths.

This feature does not scale applications, create HPAs, discover dependency
workloads, or install a metrics adapter. In particular it cannot wake an app
without the platform consuming its demand metric. Keep gates, identity services,
metrics infrastructure and databases running. Check every ingress path before
enabling suspension. Keep HPA as the only replica writer.

Release the library first, then bump the deployment repository's pinned source
and enable the annotation for a disposable pilot through its normal CI/CD path.
After deployment validate the controller/dataplane rollout, Gateway conditions,
JWKS and unauthorized responses, then the pilot's idle → zero → held request →
ready → successful response lifecycle. Inspect demand metrics and HPA events.
Rollback through CI/CD: restore the workload's autoscaler minimum to one first,
wait for readiness, then disable waiting or revert the release. Never disable
the waiting gate while workloads remain asleep.
