# tsjwt

Turn a network-verified caller identity into a short-lived, asymmetrically
signed JWT.

A private network tells you who a caller is. Most applications cannot read
that, so the usual answer is a proxy that injects an identity header. That
works only while nothing else can reach the port, because the header is a
claim, not proof. `tsjwt` replaces the claim with a signature. Reaching the
port then proves nothing; only a token signed by a key the signer holds does.

The trust boundary collapses from a whole network range to one private key.

This is the identity-aware proxy pattern, the same shape as Cloudflare
Access `Cf-Access-Jwt-Assertion` and Google IAP `X-Goog-Iap-Jwt-Assertion`.

## What it is not

It is not tied to any one organisation. Tenancy, role names and group names
are all supplied by the caller. The only shipped identity source reads a
Tailscale tailnet, and it lives in a separate module so that nothing else
depends on it.

See [ARCHITECTURE.md](ARCHITECTURE.md) for how the parts fit together and
how this compares with tsidp, Pomerium and a shared secret.
See [SECURITY.md](SECURITY.md) for the threat model.

## Design

```
caller ──WireGuard──▶ signer ──X-Tailnet-Jwt-Assertion──▶ backend
                        │                                    │
                     WhoIs()                            verify against
                  (the trust anchor)                   /.well-known/jwks.json
```

1. The signer is a node on the private network. On each connection it asks
   the network who the peer is. A caller cannot influence the answer: it can
   only choose whether to connect.
2. It resolves that identity to the tenants it may act for, and the roles it
   holds in each.
3. It mints an `ES256` JWT, short-lived, with a unique `jti`, and injects it.
   Any inbound copy of the header is stripped first.
4. The backend verifies the signature against a published key set, selecting
   the key by `kid`. It holds only public keys, so a compromised backend
   cannot mint for any other backend.

## Layout

| Package | Depends on | Purpose |
|---|---|---|
| `tsjwt` | stdlib | Identity, Tenant, Grant, Claims, the two interfaces |
| `tsjwt/jwt` | stdlib | ES256 sign and verify, one algorithm only |
| `tsjwt/keys` | stdlib | Rotating key set, RFC 7638 key ids, JWKS |
| `tsjwt/signer` | stdlib | Mints assertions; serves JWKS |
| `tsjwt/verifier` | stdlib | Checks assertions; remote JWKS; middleware; replay guard |
| `tsjwt/proxy` | stdlib | The identity-aware reverse proxy |
| `tsjwt/k8sstore` | stdlib | Shared key set in a Kubernetes ConfigMap |
| `tsjwt/cmd/tsjwt-echo` | stdlib | Reference backend: verifies and echoes what it read |
| `tsjwt/tsnetid` | tailscale.com | Tailnet identity source, and the `tsjwtd` daemon |

The core module imports only the standard library. `tsnetid` is a separate Go
module, so a service that merely verifies tokens takes on no dependency.

## Security decisions, and why

**One algorithm.** `jwt` implements `ES256` and refuses everything else, in
both the parser and the verifier. A library that accepts many algorithms has
to be configured carefully to avoid algorithm confusion, where a public key
published for verification is accepted as an HMAC secret. Supporting one
algorithm removes that bug class instead of documenting it.

**Key ids are derived, never assigned.** A `kid` is the RFC 7638 thumbprint
of the key itself, so a key id can never be reused for a different key.

**Rotation has an overlap window, and it is checked.** A retired key keeps
verifying for the window, then stops. `tsjwtd` refuses to start if the
overlap does not exceed the token lifetime, because a token minted just
before a rotation would otherwise fail before it expired.

**Lifetime is capped twice.** The signer clamps to `MaxTTL`. The verifier
independently rejects a token whose `exp` is too far from its `iat`, whatever
the signature says, which bounds the damage from a signer minting long
tokens.

**Audience is mandatory.** Both sides require it. It is what stops a token
minted for one backend being replayed at another.

**Tagged nodes are refused by default.** A tagged node is a machine, not a
person, and has no user identity to assert. Turn it on deliberately.

**The proxy strips before it does anything else.** A caller-supplied
assertion header is removed unconditionally, before any path that could
return early, so no request carries one through.

**Errors do not leak.** Every rejection wraps `ErrInvalidToken`; the reason
goes to the log, and the caller gets `401`.

## Tenancy

`TenantResolver` is the extension point. It maps a verified identity to a
`Grant`: the tenants it may act for, and the roles held in each.

```go
type TenantResolver interface {
    Resolve(Identity) (Grant, error)
}
```

A resolver must fail closed. `tsjwtd` ships a file-driven implementation so a
deployment changes tenancy by changing a file, not the binary:

```json
{
  "tenants": [
    {"id": "acme", "default": true,
     "groups": {"group:admin": "admin", "group:eng": "editor"}},
    {"id": "globex",
     "groups": {"group:globex-admin": "admin"}}
  ],
  "defaultRole": "viewer"
}
```

A caller may ask for a tenant, with `X-Tsjwt-Tenant` or `?tenant=`. The
signer decides: a tenant the identity does not hold is refused with `403`.

## Use

Verify in a backend:

```go
v, _ := verifier.New(verifier.Config{
    Issuer:   "https://tsjwt.example.ts.net",
    Audience: "grafana",
    Keys:     remoteKeys, // or verifier.LocalKeys{Set: set}
    Replay:   verifier.NewMemoryReplayGuard(),
})
http.Handle("/", v.Middleware("", app))

// inside app
claims, ok := tsjwt.ClaimsFrom(r.Context())
if !ok || !claims.HasRole("editor") { ... }
```

Run the proxy:

```
tsjwtd \
  -hostname tsjwt \
  -upstream http://backend.internal \
  -audience backend \
  -tenants /etc/tsjwt/tenants.json \
  -ttl 5m -rotate 24h -overlap 1h
```

`TS_AUTHKEY` is read from the environment, never a flag, so it does not
appear in the process table.

## Claims

| Claim | Meaning |
|---|---|
| `iss` `sub` `aud` `iat` `nbf` `exp` `jti` | RFC 7519 |
| `email` `name` `node` | Informational. Never authorize on these. |
| `tenant` | The tenant this token acts for. Enforce isolation on this. |
| `tenants` | Every tenant the identity may act for. |
| `roles` | Roles held within `tenant`. Authorize on these. |
| `groups` | Raw identity-source groups. Informational: not tenant-scoped. |

`sub` is the identity source's stable id, not the login name, because a login
name can be reassigned.

## Limits

* **Device theft inherits identity**, under this scheme and every other.
* **Replay protection is per-process** by default. A horizontally scaled
  backend needs a shared store behind `ReplayGuard`.
* **Roles are coarse.** Per-action authorization stays an application
  concern.
* **Revocation is expiry.** There is no deny list. The lifetime cap is the
  control, which is why it is short and enforced on both sides.

## What this is not

**It is not an Ingress controller or a Gateway API implementation.** There is
no controller, no `GatewayClass`, nothing watching cluster resources. `tsjwtd`
is a process you configure with flags, and it forwards to **one** upstream.

Putting a second service behind it today means running a second instance. That
is the honest state of adoption, and the shape that would fix it is a gateway
in front of many backends — see
[ARCHITECTURE.md](ARCHITECTURE.md#a-gateway-in-front-of-many-backends).

## Status

Prototype, running in one deployment. The API may change.

The one assumption that is not yet measured: that a hostile peer cannot
change what the identity source reports about it. Everything else here rests
on that. See [SECURITY.md](SECURITY.md).
