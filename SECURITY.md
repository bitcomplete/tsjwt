# Security

## How to report a problem

Use the "Report a vulnerability" button on the Security tab. Do not open a
public issue.

## What the design assumes

Three assumptions hold up this design. If one fails, the others do not help.

**The network tells the truth about identity.** The signer asks the network
who the caller is. The caller must not be able to change that answer. For a
Tailscale tailnet, `tailscaled` accepts a packet only from a peer with an
authenticated node key. The map from address to identity comes from the
control plane, not from the peer.

*Measured on 2026-09-16.* We tried to change the answer. Results:

| Attack | Result |
|---|---|
| Set `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `X-Forwarded-Host`, or a fake assertion header to name a different tailnet address | Identity unchanged. The proxy reads `r.RemoteAddr` only. No header is consulted. |
| Ask for the identity of an address that is not a proven peer | `WhoIs` returns *peer not found*. A forged address gives no identity, not a wrong one. |
| Present a tagged node's full, person-looking `UserProfile` | Refused. The guard reads the tag, not the profile. |
| Reassign a login name to move a subject | Subject follows the numeric user id, which the peer cannot choose. |
| Claim groups without a capability grant, or under another capability name | No groups. Groups come from the named grant only. |

Each case is a test in `tsnetid/whois_test.go`, built from `WhoIs` answers
recorded off a live tailnet. Each test was mutation-checked: we broke the
guard three ways (guard on the empty profile, delete the guard, key the
subject on the login name) and confirmed the tests fail every time.

*What remains unmeasured.* Two items, both below this library:

- **Source-address spoofing at the transport.** WireGuard accepts a packet
  for an address only if that address is in the sending peer's AllowedIPs,
  so a forged source is dropped before `tailscaled` sees it. This is a
  property of WireGuard, which we did not re-test here.
- **A second human account.** The tailnet used has one human account. We
  could not make one person's node present as another person. Impersonation
  across *machine* principals was tested, and is refused.

**The signing key stays private.** A person with the signing key can make a
token for any identity, in any tenant. Protect the key more than any other
item in the deployment.

**Each backend verifies.** A backend that reads the header, but does not
check the signature, has the problem that this library removes.

## What is not in scope

* **A stolen device.** A person with an unlocked device gets the identity of
  the owner. This is true for each design of this type.
* **Revocation that is faster than expiry.** There is no deny list. The
  short lifetime is the control.
* **Authorization for each action.** Roles are not precise. An application
  must do more work for a rule like "may silence this alert, but not that
  alert".

## Design decisions

Each decision below is a security decision.

**One algorithm.** The library makes and accepts `ES256` only. The parser,
the verifier and the key loader each refuse a different algorithm.

A library with many algorithms needs careful configuration. If it does not
get it, an attacker can use a public key as an HMAC secret. This is
algorithm confusion. One algorithm removes the problem. Configuration cannot
remove it.

**Key ids come from the key.** A `kid` is the RFC 7638 thumbprint. You
cannot use one `kid` for two different keys.

**A tagged node cannot get a token.** This default is important, and the
reason is not obvious.

We measured a live tailnet on 2026-09-15. For a tagged node, `WhoIs` does
not return an empty user. It returns a complete user:

```json
{"ID": <a stable numeric id>,
 "LoginName": "tagged-devices",
 "DisplayName": "Tagged Devices"}
```

Each tagged node in the tailnet has that same ID. An implementation that
tests only for an empty user accepts each tagged workload. It then makes
each workload into one principal that looks like a person.

The test must be on the tag. The test must run before the code reads the
user.

**A gateway derives the audience from the backend.** Two services behind one
gateway cannot share an audience, so a token minted for one is refused by the
other. Nobody has to choose a name for this to hold, which is why it holds.

**Claim headers are a migration path, not a destination.** A route can write
verified claims into request headers, so a backend that already trusts an
identity header works behind the gateway unchanged. Read it as what it is: a
backend reading that header still trusts its network position, and only
verifying the assertion removes that. The gateway strips the union of every
claim header any route writes, before routing, so a caller cannot supply one
that a different route sets.

**Replicas share public keys, never the private one.** Each replica makes its
own signing key and keeps it in memory. Only public keys go to the shared
store, so read access to that store gives an attacker nothing. Write access is
still equivalent to holding a signing key, because a new public key could be
added; protect writes accordingly.

**Two limits on the lifetime.** The signer limits the lifetime. The verifier
also refuses a token with a lifetime that is too long. The second limit does
not trust the configuration of the first. A signer with a bad configuration
stays bounded.

**The audience is necessary.** The signer and the verifier each need an
audience. Without it, a token for one backend works at a different backend.

**The signer removes the header first.** The signer deletes each copy of the
assertion header before it does other work. A header from the caller must
never continue to the backend.

**An error does not say why.** Each refusal gives `401`. The reason goes to
the log. "The token expired" and "the audience is wrong" are useful to an
attacker.

## What we tested

An automatic test drives the full path with two tenants that have no
relation to each other. The test shows that:

* a token for one tenant cannot read the data of the other tenant;
* a request for a tenant that the identity does not hold gets a refusal;
* a false assertion sent directly to the backend gets `401`;
* a token made before a key rotation is still valid after the rotation.

A second test makes sure the header removal works. We disabled the removal,
and the test failed. A test that stays green when you break the code does
not prove anything.
