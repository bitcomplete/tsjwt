# Security

## Reporting

Report a vulnerability privately through GitHub's "Report a vulnerability"
button on the Security tab. Please do not open a public issue.

## Scope and threat model

This library mints and verifies short-lived identity assertions. It assumes:

* **The identity source is honest.** Everything rests on the transport
  establishing who a caller is, and the caller not being able to influence
  that answer. For the shipped Tailscale source, that is a property of
  WireGuard peer authentication and the control plane's address-to-identity
  map. If the identity source can be fooled, nothing downstream helps.
* **The signing key stays private.** A leaked signing key is total
  compromise: it mints any identity for any tenant. Rotate on the schedule,
  and treat the key's storage as the most sensitive thing in the deployment.
* **Backends verify.** A backend that reads the header without verifying it
  is in exactly the position this library exists to fix.

## Explicitly out of scope

* **Device theft.** A stolen, unlocked device inherits its owner's identity,
  under this scheme and every other.
* **Revocation faster than expiry.** There is no deny list. The lifetime cap
  is the control, which is why it is short and enforced on both sides.
* **Per-action authorization.** Roles are coarse by design.

## Design decisions that are security decisions

| Decision | Why |
|---|---|
| One algorithm (ES256), enforced in parser, verifier and key loader | Removes algorithm confusion as a bug class |
| Key ids are RFC 7638 thumbprints | A key id can never be reused for a different key |
| Tagged nodes refused by default | A tagged node reports a shared pseudo-user; admitting it collapses every machine into one principal |
| Lifetime capped at signer *and* verifier | The cap must not depend on the signer being correctly configured |
| Audience mandatory on both sides | Stops a token for one backend being replayed at another |
| Assertion header stripped before minting | A caller-supplied header must never survive |
| Rejections do not say why | "Expired" versus "wrong audience" is useful to an attacker |
