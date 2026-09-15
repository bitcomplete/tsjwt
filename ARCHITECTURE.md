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
