# Architecture

This document tells you how `tsjwt` works. Read `SECURITY.md` for the
threat model.

## The problem

A private network knows who each caller is. Most applications cannot read
this. The usual answer is a proxy. The proxy adds an identity header, and
the application trusts the header.

This answer has a limit. A header is a claim. It is not proof. The answer
is safe only while no other workload can reach the port. One workload that
reaches the port can send any header, and become any person.

## The answer

Replace the claim with a signature.

```
caller ──WireGuard──▶ signer ──X-Tailnet-Jwt-Assertion──▶ backend
                        │                                   │
                     WhoIs()                        verify with the
                (the trust anchor)             published public key set
```

The signer is a node on the private network. For each request, the signer
does four steps:

1. The signer asks the network for the identity of the peer. The caller
   cannot change this answer. The caller can only decide to connect, or not
   to connect.
2. The signer finds the tenants for that identity, and the roles in each
   tenant.
3. The signer makes a JWT. The JWT uses `ES256`. It stays valid for five
   minutes. It has a unique `jti`.
4. The signer removes each copy of the assertion header from the request.
   Then the signer adds its own header, and sends the request to the
   backend.

The backend gets the public keys from a URL. The backend selects a key with
the `kid` in the token. The backend keeps no secret.

The trust boundary becomes one private key. It is no longer a network
range.

## The three interfaces

The design has three parts. Each part has one job.

| Interface | Job |
|---|---|
| `IdentitySource` | Tell the signer who the caller is |
| `TenantResolver` | Tell the signer which tenants the caller may use |
| `KeySource` | Give the backend a public key for a `kid` |

`IdentitySource` is the trust anchor. The package `tsnetid` has the only
implementation. It reads a Tailscale tailnet. A different network needs a
different implementation, and nothing else changes.

`TenantResolver` is where you add your own organization model. The library
has no opinion about tenant names, role names or group names.

## Packages

| Package | Depends on | Job |
|---|---|---|
| `tsjwt` | stdlib | Types and interfaces |
| `jwt` | stdlib | `ES256` signature and verification |
| `keys` | stdlib | Key rotation and the public key set |
| `signer` | stdlib | Make an assertion |
| `verifier` | stdlib | Check an assertion |
| `proxy` | stdlib | The identity-aware proxy |
| `tsnetid` | `tailscale.com` | Tailnet identity, and the `tsjwtd` command |

The core uses only the standard library. The Tailscale code is in a second
Go module. A backend that only checks tokens gets no dependency. A test in
CI enforces this rule.

## Tenants

A `Grant` is the result of authorization. It holds the tenants for one
identity, and the roles in each tenant.

The token carries these claims:

| Claim | Use |
|---|---|
| `tenant` | The tenant for this request. Isolate data with this claim. |
| `tenants` | All tenants for this identity. |
| `roles` | The roles in `tenant`. Authorize with these. |
| `groups` | The groups from the network. For information only. |

Authorize with `roles`, not with `groups`. A role applies to one tenant. A
group does not.

A caller can ask for a tenant. The signer decides. If the identity does not
hold that tenant, the signer refuses the request.

## Key rotation

The signer holds one current key, and it signs with that key. After a
rotation, the old key stays valid for an overlap window. Tokens from before
the rotation continue to work.

The overlap window must be longer than the token lifetime. If it is not, a
token can stop working before it expires. `tsjwtd` does not start if the
configuration breaks this rule.

A `kid` is the RFC 7638 thumbprint of the key. The key defines the `kid`, so
you cannot use one `kid` for two keys.

## The credential, and why it is minted rather than held

The signer is a node on the private network, so it needs a credential to join
one. Holding a static key is the obvious approach and the wrong one.

A key expires. A tagged node does not expire its node key, so the service goes
on running long past that date, and the failure appears only at the next
restart — often months later, during something unrelated.

So the signer holds a credential that **mints** keys rather than a key. It
mints one at startup, which makes the key in use never older than the process.
The minting credential cannot join a node by itself and is revocable in one
place.

That leaves one question: what replaces a process before its key dies? The
health check does. It reports unhealthy at `expiry - (buffer + splay)`, so an
orchestrator replaces the process while the current key still works, and the
replacement mints a fresh one. Expiry becomes a scheduled restart instead of
an outage.

The splay matters as soon as there is more than one replica. Replicas that
start together hold keys that expire together, so without a per-process offset
they would all report unhealthy in the same minute and stop as one.

## More than one replica

A replica makes its signing key at start and keeps it in memory. Two replicas
therefore hold two different keys. A token from one would fail at a backend
that read the key set from the other.

The answer is not to share the private key. A shared private key is the
authority to mint any identity in any tenant, and putting it in a store means
anyone who can read that store holds that authority.

Instead, each replica publishes only its **public** key to a shared store. The
key set is the union of every live replica's keys, and `kid` selects the
correct one. A verifier that meets an unknown `kid` fetches the set again.

```
replica A ──┐                      JWKS = union
            ├──▶ shared store ────▶  kid-A, kid-B
replica B ──┘   (public keys only)
```

A private key never leaves the process that made it. So:

* A reader of the store gets nothing. It holds no secret.
* A writer of the store can add a key of their own, and that is still full
  compromise. Write access needs the same care as any signing material.

Each entry carries a lease. A replica refreshes its own entries; a replica
that stops is dropped after the lease **plus a grace period**. The grace must
exceed the longest token lifetime, or a token from a replica that has just
gone away stops verifying before it expires. The daemon refuses to start if
the configuration breaks that rule.

The shipped store (`k8sstore`) uses a Kubernetes ConfigMap, not a Secret. That
is a statement, not an oversight: the data needs no protection, and the
resource type makes that visible to anyone auditing the deployment.

## A gateway in front of many backends

The signer is the identity edge: it is the tailnet node, and it is the only
component that turns a network-verified caller into a token. It is not a
router. Putting it in front of every service one at a time means a cutover
per service, and it makes the signer a shared point of failure.

A gateway solves that. The signer mints once, at the edge; the gateway
verifies the token, routes to many backends, and can pass validated claims on
as headers.

```
caller ──WireGuard──▶ signer ──JWT──▶ gateway ──▶ many backends
                    (WhoIs, mint)   (verify, route,
                                     claims to headers)
```

The gateway needs nothing from this project beyond the published key set,
because the token is an ordinary `ES256` JWT and the key set is an ordinary
JWKS. Envoy Gateway, for example, validates against `remoteJWKS.uri` and maps
claims to headers with `ClaimToHeader`.

Two details make that work:

* **Write the token where the gateway reads it.** Many gateways read only
  `Authorization: Bearer`. Use `-bearer` with `-header=Authorization`.
* **A backend should still verify.** A gateway that verifies protects the
  path through the gateway. A backend that verifies protects itself, whatever
  path a request took. The second is what makes reaching a port prove
  nothing.

## Why not tsidp

Tailscale has an OIDC identity provider, `tsidp`. It looks like an answer to
the same problem. It is not.

| Item | tsidp | tsjwt |
|---|---|---|
| Flow | Browser redirect, then a cookie | No redirect, no cookie |
| Agents and CLI tools | Difficult. They have no browser. | Same path as a person |
| Status | Experimental. Breaking changes are possible. | You control the code |
| Proxy-side mint | Not documented | The primary function |

The important difference is the cookie. A browser can keep a session. An
agent, a CLI tool or an MCP server cannot do this easily. `tsjwt` uses
WireGuard as the session, so each caller type uses one path.

`tsidp` also does not close the gap that this library exists to close. It
proves an identity to an application after a login. It does not stop a
workload that reaches a port and sends a header.

## Why not Pomerium

Pomerium is mature, and it uses the same header pattern. But Pomerium
authenticates through its own identity provider with a browser session. It
adds a cookie between the browser and the proxy, and it adds a component to
operate.

Pomerium is a good choice if you prefer to run a product. `tsjwt` is a
library of about 1800 lines with no dependencies in its core.

## Why not a shared secret

An HMAC with a shared secret also works. But each backend must then hold
the secret. A backend with the secret can make tokens for every other
backend. Rotation becomes a task for each backend.

Asymmetric signatures are better. A backend holds only public keys.
Rotation happens in one place.
