# Production Sigstore round-trip runbook

Operator-actionable runbook for executing the production Sigstore round-trip described in justsign issue #23. Estimated time: ~10 minutes including OIDC setup.

## Why this runbook exists

Every live test in justsign's CI matrix points at **staging** Sigstore endpoints (`fulcio.sigstage.dev` / `rekor.sigstage.dev` / `tuf-repo-cdn.sigstage.dev`). We have no automated proof that signatures justsign produces verify against the **production** Sigstore trust roots, or that production Fulcio + Rekor accept our wire shape unchanged from staging.

The single most likely failure mode for a v0.1.0 launch is "signed something against prod, cosign rejects it". This runbook reduces that risk to zero by performing the round trip once, manually, before publishing to crates.io.

## Prerequisites

- A justsign binary built with `--features oidc`. Build:
  ```sh
  cargo build --release --bin justsign --features oidc
  ```
- Upstream `cosign` binary installed (for cross-verification). Latest 2.x release from https://github.com/sigstore/cosign/releases.
- An OIDC identity-token issuer Sigstore trusts. Two options:
  - **Google ID token** (zero-config): `gcloud auth print-identity-token --audiences=sigstore`. Requires a `gcloud` CLI logged into any Google account.
  - **GitHub Actions OIDC** (CI-driven): only works inside a GitHub Actions run; not local-friendly.

This runbook uses the Google-ID-token path because it's the lowest-friction local option.

## Steps

### 1. Mint the OIDC token

```sh
TOKEN=$(gcloud auth print-identity-token --audiences=sigstore)
echo "$TOKEN" | head -c 30
echo "..."
```

The token is a JWT with `aud=sigstore`. Don't paste it into the issue / public logs — it's an identity assertion bound to your Google account.

### 2. Pick a target artefact

Anything you're willing to permanently associate with your Google identity in the public Rekor log. **The signature is immutable.** A safe choice: a string like `"justsign #23 production round-trip $(date -u +%Y-%m-%dT%H:%M:%SZ)"` written to a tempfile.

```sh
ARTEFACT=$(mktemp)
echo "justsign #23 production round-trip $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ARTEFACT"
sha256sum "$ARTEFACT"
```

### 3. Sign against production Sigstore

```sh
SIGSTORE_ID_TOKEN="$TOKEN" \
  ./target/release/justsign sign-blob \
    --keyless \
    --rekor https://rekor.sigstore.dev \
    --payload-type text/plain \
    "$ARTEFACT" \
    > bundle.json
```

This:

1. Generates a fresh ECDSA P-256 keypair in process.
2. Builds a CSR.
3. POSTs it to `https://fulcio.sigstore.dev/api/v2/signingCert` with the OIDC token; gets a short-lived cert chain.
4. Signs the DSSE PAE of the artefact with the ephemeral private key.
5. Submits a hashedrekord entry to `https://rekor.sigstore.dev/api/v1/log/entries`.
6. Bundles cert chain + signature + Rekor inclusion proof into a Sigstore Bundle v0.3 JSON.

Expected size: bundle is ~3-5 KB.

### 4. Verify with justsign

```sh
./target/release/justsign verify-blob \
  --keyless \
  --rekor https://rekor.sigstore.dev \
  --bundle bundle.json \
  --expected-san "$YOUR_EMAIL_OR_OIDC_SUBJECT" \
  "$ARTEFACT"
```

`$YOUR_EMAIL_OR_OIDC_SUBJECT` is the value Fulcio embedded in the leaf cert's SAN — for Google ID tokens, your email. Inspect the cert chain with:

```sh
jq -r '.verificationMaterial.x509CertificateChain.certificates[0].rawBytes' bundle.json \
  | base64 -d \
  | openssl x509 -inform DER -text -noout \
  | grep -A1 "Subject Alternative Name"
```

### 5. Cross-verify with upstream cosign

This is the load-bearing check. If our bundle round-trips through justsign but NOT cosign, that's a wire-shape gap.

```sh
cosign verify-blob \
  --bundle bundle.json \
  --certificate-identity "$YOUR_EMAIL_OR_OIDC_SUBJECT" \
  --certificate-oidc-issuer https://accounts.google.com \
  "$ARTEFACT"
```

Expected: `Verified OK`.

If cosign rejects the bundle, **do not close issue #23**. Comment with cosign's exact stderr; that's a wire-shape divergence to triage.

### 6. Document the result

Comment on issue #23 with:

```
Production round-trip executed YYYY-MM-DD by <maintainer>.

OIDC issuer: https://accounts.google.com (Google ID token, aud=sigstore)
Subject:     <email>
Artefact:    <description>, sha256:<hex>
Bundle size: <bytes>
Rekor URL:   https://search.sigstore.dev/?logIndex=<N>
cosign verify-blob: PASS

Conclusion: justsign-produced bundle round-trips through cosign 2.x
against production Sigstore. No wire-shape drift.
```

The `Rekor URL` is permanent and publicly searchable — that's the durable evidence.

Then:

```sh
gh issue close 23 --repo sweengineeringlabs/justsign --comment "<paste the above>"
```

## Failure modes

| Symptom | Likely cause |
|---|---|
| Fulcio returns 4xx with `oidc token unsupported` | OIDC issuer not trusted by production Fulcio. Use Google or GitHub Actions; staging Fulcio accepts more issuers but production is strict. |
| Rekor returns 409 `entry already exists` | You signed identical bytes twice. The previous bundle is still valid; just re-fetch it via `gh search` on Rekor's logIndex. |
| `cosign verify-blob` rejects with "no matching signatures" | Wire-shape drift between justsign's Bundle v0.3 emit and cosign's expected shape. Triage by paste both bundle JSONs into a diff. **Do not close #23.** |
| `cosign verify-blob` rejects with "could not find a valid identity" | `--certificate-identity` doesn't match the SAN. Inspect the cert (step 4) and re-run with the right identity. |
| Local `gcloud auth print-identity-token` returns nothing | `gcloud auth login` first. The CLI needs an authenticated Google account. |

## Re-running after a wire-shape fix

If round-trip fails and we land a fix in justsign (new commit on `main`), re-run from step 3 with the fixed binary. The previous Rekor entry stays in the log forever; just sign fresh bytes.

## Cleanup

The Rekor entry is permanent and intentional — it's the evidence. Don't try to remove it. The OIDC token is short-lived (typically 1 hour); it expires on its own.

The local bundle.json + artefact tempfile are safe to delete:

```sh
rm bundle.json "$ARTEFACT"
```

## See also

- [`integration_guide.md`](../3-design/integration_guide.md) — integration patterns (library, CLI, sigstore-rs replacement).
- [`deployment_guide.md`](./deployment_guide.md) — CI signing patterns (staging-side; this runbook is the production equivalent).
- justsign issue #23 — open until a maintainer executes this runbook and pastes the result.
