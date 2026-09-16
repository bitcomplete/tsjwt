# Install

These manifests are an **example**, not a deployment. Copy them, or overlay
them with kustomize; do not edit them in place and apply.

That is not style advice. Editing them in place is how one deployment's
registry, tailnet tag and Secret names ended up committed to this repository,
which is meant to be generic.

Every value marked `REPLACE_ME` or `example.com` is yours to set:

| Where | What |
|---|---|
| `kustomization.yaml` `images[].newName` | your registry |
| `controller.yaml` `-dataplane-image` | the same reference, in full |
| `controller.yaml` `-tag` | the tailnet tag minted auth keys carry |
| `controller.yaml` `-capability` | must match the capability grant in your tailnet policy |
| `controller.yaml` `-credential-secret` | Secret holding the tailnet OAuth client |

`-dataplane-image` is a flag, not an `image:` field, so kustomize's image
transformer does **not** rewrite it. Setting only `images[]` leaves the
controller provisioning data planes from a name that cannot be pulled.

## Order

1. The [Gateway API CRDs](https://gateway-api.sigs.k8s.io/), installed
   separately. Gateway API is explicit that CRDs are not owned by any one
   implementation.
2. A Secret with `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_CLIENT_SECRET`, for a
   client scoped to the tag above.
3. A ConfigMap with the tenant policy, named by `-tenants-configmap`.
4. `kubectl apply -k .`

Then a `Gateway` using the `tsjwt` class provisions its own data plane, and an
`HTTPRoute` attaches a backend to it.
