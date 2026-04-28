# Production Sigstore round-trip runbook

**Audience**: Release engineers and maintainers executing (or re-executing) the cosign-against-production-Sigstore regression check before any wire-shape change ships.

> **TLDR**: Build justsign with `--features oidc-browser`, sign a one-line artefact against `https://fulcio.sigstore.dev` + `https://rekor.sigstore.dev` via the interactive-browser OIDC flow, then verify the resulting bundle with `cosign verify-blob --new-bundle-format`. Expected output: `Verified OK`. Last passed 2026-04-28 at logIndex [1396196448](https://search.sigstore.dev/?logIndex=1396196448). Re-run on every wire-shape change to `spec`, `rekor`, or `sign`.

Operator-actionable runbook for executing the production Sigstore round-trip described in justsign issue #23. Estimated time: ~5 minutes once cosign + a browser are available.

> **Status (2026-04-28):** the round-trip was executed by phdsystems and verified `OK` by cosign 3.0.6 against production Fulcio + Rekor. Permanent evidence at <https://search.sigstore.dev/?logIndex=1396196448>. Issue #23 is closed. Re-run this runbook on every wire-shape change touching `spec`, `rekor`, or `sign`.

## What counts as a wire-shape change

Re-run this runbook before merging any PR that touches:

| Crate / file | Why it triggers a re-run |
|---|---|
| `spec/src/sigstore_bundle.rs` | Changes the JSON structure cosign parses |
| `spec/src/dsse.rs` | Changes the DSSE envelope encoding |
| `spec/src/in_toto.rs` | Changes the in-toto statement shape inside the bundle |
| `rekor/src/client.rs` | Changes what we submit to Rekor or how we parse the response |
| `sign/src/lib.rs` (`sign_blob*`) | Changes the signing flow or cert handling |
| `fulcio/src/client.rs` | Changes the CSR format or cert-chain handling |

Changes to `tuf/`, `oidc/`, test files, docs, or CI config do NOT require a re-run.

## Why this runbook exists

Every live test in justsign's CI matrix points at **staging** Sigstore endpoints (`fulcio.sigstage.dev` / `rekor.sigstage.dev` / `tuf-repo-cdn.sigstage.dev`). We have no automated proof that signatures justsign produces verify against the **production** Sigstore trust roots, or that production Fulcio + Rekor accept our wire shape unchanged from staging.

The single most likely failure mode for a v0.1.0 launch is "signed something against prod, cosign rejects it". This runbook reduces that risk to zero by performing the round trip once, manually, before publishing to crates.io — and is the canonical regression check for any future bundle wire-shape change.

## Prerequisites

- A justsign binary built with `--features oidc-browser`. Build:
  ```sh
  # Unix
  cargo build --release --bin justsign --features oidc-browser

  # Windows (PowerShell)
  cargo build --release --bin justsign --features oidc-browser
  ```
  The `oidc-browser` feature pulls in the local HTTP listener used by the interactive OAuth flow. The lighter `--features oidc` is enough only if you have a pre-minted Sigstore-trusted OIDC token in `SIGSTORE_ID_TOKEN`.
- Upstream `cosign` binary, **3.0+** — the `--new-bundle-format` flag is required, and 2.x will not parse our v0.3 bundle. Latest 3.x release from <https://github.com/sigstore/cosign/releases>.
- A browser on the same machine that can reach `https://oauth2.sigstore.dev/auth` and `http://localhost:NNNNN` (ephemeral port the listener picks).
- **Go 1.23+** — required only for the diagnostic snippet in step 4 when cosign rejects a bundle. Install from <https://go.dev/dl/>. Skip if you don't anticipate needing the diag tool.

### Picking an OIDC issuer

Sigstore's production Fulcio accepts a closed set of issuers. The two locally-friendly options are:

| Provider | How |
|---|---|
| **Interactive browser** (recommended) | `--oidc-provider interactive-browser`. Drives the full OAuth code+PKCE dance against Sigstore's Dex broker (`oauth2.sigstore.dev`), which fronts GitHub / Google / Microsoft. No pre-minted token, no service-account setup. |
| **Pre-minted Google service-account ID token** | `gcloud auth print-identity-token --audiences=sigstore` — only works for service accounts. User accounts get `Invalid account type for --audiences` and must use the interactive flow. |

GitHub Actions OIDC is the third option but only works inside a GHA run.

This runbook uses the **interactive-browser** path because it works for any operator without SA setup.

## Steps

### 1. Pick a target artefact

Anything you're willing to permanently associate with your OIDC identity in the public Rekor log. **The signature is immutable.** A safe choice: a string with a UTC timestamp written to a tempfile.

```sh
# Unix
mkdir -p roundtrip
ARTEFACT=roundtrip/blob.txt
echo "justsign production round-trip $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ARTEFACT"
sha256sum "$ARTEFACT"
```

```powershell
# Windows (PowerShell)
New-Item -ItemType Directory -Force roundtrip | Out-Null
$ARTEFACT = "roundtrip\blob.txt"
"justsign production round-trip $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))" | Set-Content $ARTEFACT
Get-FileHash $ARTEFACT -Algorithm SHA256
```

### 2. Sign against production Sigstore

Run the appropriate variant for your shell:

```sh
# Unix
./target/release/justsign sign-blob "$ARTEFACT" \
  --keyless \
  --fulcio https://fulcio.sigstore.dev \
  --oidc-provider interactive-browser \
  --rekor=https://rekor.sigstore.dev \
  --shape message \
  --output-bundle roundtrip/bundle.json
```

```powershell
# Windows (PowerShell)
.\target\release\justsign.exe sign-blob $ARTEFACT `
  --keyless `
  --fulcio https://fulcio.sigstore.dev `
  --oidc-provider interactive-browser `
  --rekor=https://rekor.sigstore.dev `
  --shape message `
  --output-bundle roundtrip\bundle.json
```

Important:

- **Production endpoints MUST be passed explicitly** — the CLI defaults to staging (`https://fulcio.sigstage.dev` / `https://rekor.sigstage.dev`) so a typo'd command doesn't burn a permanent identity entry into the public production Rekor log.
- `--shape message` is the cosign-blob interop shape (MessageSignature content + `hashedrekord` Rekor schema). Use `--shape dsse` only when you need cosign-attestation interop (DSSE envelope + `dsse` Rekor schema). See [step 2b](#2b-dsse-shape-variant) below if you need to verify the DSSE path.
- The CLI prints an `https://oauth2.sigstore.dev/auth/auth?…` URL to stderr. **Open it** (it may auto-open in your default browser). Pick GitHub / Google / Microsoft, complete 2FA, and the redirect to `localhost:NNNNN` lands a "authentication complete — close this tab" page. The listener waits 15 minutes; after that it times out.

What the CLI does per call:

1. Resolves the OIDC token via the Dex broker at `oauth2.sigstore.dev` (PKCE S256, RFC 7636).
2. Mints a fresh ECDSA P-256 keypair in process.
3. Builds a CSR via `sign::fulcio::build_csr`, base64-encodes it for the protobuf `bytes` field, and POSTs to `https://fulcio.sigstore.dev/api/v2/signingCert`. Receives a 10-minute leaf cert chained to a Sigstore intermediate.
4. Signs the artefact bytes with the ephemeral private key — RustCrypto's `Signer::sign` auto-hashes via SHA-256, so the signature is over `SHA-256(payload)`. Matches Rekor's `hashedrekord` verification model (`ecdsa.VerifyASN1(pub, digest, sig)`).
5. Submits a `hashedrekord` entry to `https://rekor.sigstore.dev/api/v1/log/entries`. Captures the integration timestamp, signed entry timestamp (SET), inclusion proof, and signed checkpoint envelope from the response.
6. Wraps cert + signature + tlog entry into a Sigstore Bundle v0.3 JSON (`mediaType: application/vnd.dev.sigstore.bundle.v0.3+json`), written to `roundtrip/bundle.json`.

Expected size: bundle is ~5 KB.

### 2b. DSSE shape variant

Run this in addition to step 2 when any PR touches `spec/src/dsse.rs`, `rekor/src/client.rs` (DSSE submission path), or the `sign_oci` / `attest` API surface. The `message` shape above does not exercise the DSSE encoder.

```sh
# Unix
./target/release/justsign sign-blob "$ARTEFACT" \
  --keyless \
  --fulcio https://fulcio.sigstore.dev \
  --oidc-provider interactive-browser \
  --rekor=https://rekor.sigstore.dev \
  --shape dsse \
  --output-bundle roundtrip/bundle-dsse.json
```

```powershell
# Windows (PowerShell)
.\target\release\justsign.exe sign-blob $ARTEFACT `
  --keyless `
  --fulcio https://fulcio.sigstore.dev `
  --oidc-provider interactive-browser `
  --rekor=https://rekor.sigstore.dev `
  --shape dsse `
  --output-bundle roundtrip\bundle-dsse.json
```

Then verify (step 4) substituting `bundle-dsse.json` for `bundle.json`. Document both Rekor log indices in the result comment.

### 3. Inspect the cert

The leaf cert's Subject Alternative Name is the Fulcio-embedded OIDC subject (your email or workflow ID). Inspect with:

```sh
# Unix
jq -r '.verificationMaterial.certificate.rawBytes' roundtrip/bundle.json \
  | base64 -d \
  | openssl x509 -inform DER -text -noout \
  | grep -A1 "Subject Alternative Name"
```

```powershell
# Windows (PowerShell) — requires openssl on PATH (e.g. from Git for Windows)
$raw = (Get-Content roundtrip\bundle.json | ConvertFrom-Json).verificationMaterial.certificate.rawBytes
[System.IO.File]::WriteAllBytes("roundtrip\leaf.der", [Convert]::FromBase64String($raw))
openssl x509 -inform DER -in roundtrip\leaf.der -text -noout | Select-String -A1 "Subject Alternative Name"
```

The OIDC issuer is encoded in the cert's `1.3.6.1.4.1.57264.1.1` extension — extract it with `openssl x509 -text` if you don't remember which provider you picked:

```sh
# Unix
jq -r '.verificationMaterial.certificate.rawBytes' roundtrip/bundle.json \
  | base64 -d \
  | openssl x509 -inform DER -text -noout \
  | grep -A1 "1.3.6.1.4.1.57264.1.1"
```

```powershell
# Windows (PowerShell)
openssl x509 -inform DER -in roundtrip\leaf.der -text -noout | Select-String -A1 "1.3.6.1.4.1.57264.1.1"
```

Note: justsign emits the protobuf-specs v0.3 final singular `certificate` leaf shape (cosign 3.0+ requirement). For bundles produced by cosign 2.x or older sigstore-rs, the leaf lived under `verificationMaterial.x509CertificateChain.certificates[0].rawBytes` instead — substitute that path when inspecting legacy bundles. Our decoder accepts both for back-compat.

### 4. Cross-verify with upstream cosign

This is the load-bearing check. justsign verifying its own output proves only self-consistency. cosign accepting the bundle is the test that actually proves Sigstore-ecosystem compatibility — if cosign rejects, the "drop-in replacement for sigstore-rs" claim is false.

**4a. justsign self-verify (static key only — placeholder)**

justsign's `verify-blob` does not yet support `--keyless` (tracked v0 follow-up, issue #TBD). Once that ships, add this step before the cosign check:

```sh
# Not yet available — update this runbook when --keyless lands in verify-blob.
# Expected command shape:
# ./target/release/justsign verify-blob roundtrip/blob.txt \
#   --bundle roundtrip/bundle.json \
#   --keyless \
#   --certificate-identity "$YOUR_OIDC_SUBJECT" \
#   --certificate-oidc-issuer "$YOUR_OIDC_ISSUER"
```

**4b. cosign cross-verify**

```sh
# Unix
cosign verify-blob \
  --bundle roundtrip/bundle.json \
  --new-bundle-format \
  --certificate-identity "$YOUR_OIDC_SUBJECT" \
  --certificate-oidc-issuer "$YOUR_OIDC_ISSUER" \
  roundtrip/blob.txt
```

```powershell
# Windows (PowerShell)
cosign verify-blob `
  --bundle roundtrip\bundle.json `
  --new-bundle-format `
  --certificate-identity $YOUR_OIDC_SUBJECT `
  --certificate-oidc-issuer $YOUR_OIDC_ISSUER `
  roundtrip\blob.txt
```

`$YOUR_OIDC_ISSUER` is the URL inside the cert's `1.3.6.1.4.1.57264.1.1` extension. For the common providers:

| Provider used at OAuth time | `--certificate-oidc-issuer` value |
|---|---|
| GitHub | `https://github.com/login/oauth` |
| Google | `https://accounts.google.com` |
| Microsoft | `https://login.microsoftonline.com` |

Expected: `Verified OK`.

If cosign rejects the bundle, **do not declare success**. Comment on the regression issue with cosign's exact stderr; that's a wire-shape divergence to triage. Common diagnostic moves:

```sh
# Re-load via sigstore-go directly to get the actual decoder error:
cd roundtrip && mkdir -p diag && cd diag && cat > main.go <<'EOF'
package main
import (
  "fmt"; "os"
  sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
)
func main() {
  if _, err := sgbundle.LoadJSONFromPath(os.Args[1]); err != nil {
    fmt.Println("LoadJSONFromPath ERROR:", err); os.Exit(1)
  }
  fmt.Println("LoadJSONFromPath OK")
}
EOF
echo 'module diag
go 1.23' > go.mod
go run . ../bundle.json
```

cosign's surface-level error (`bundle does not contain cert for verification`) is misleading: cosign falls back to the legacy bundle parser if sigstore-go rejects the v0.3 bundle. The diag tool above surfaces the real `protojson` rejection.

### 5. Document the result

Comment on the relevant issue (or future regression issue) with:

```
Production round-trip executed YYYY-MM-DD by <maintainer>.

OIDC issuer:   <issuer URL from cert>
Subject:       <SAN from cert>
Artefact:      <description>, sha256:<hex>
Bundle size:   <bytes>
Rekor URL:     https://search.sigstore.dev/?logIndex=<N>
cosign verify-blob: PASS (cosign <version>)

Conclusion: justsign-produced bundle round-trips through cosign 3.x
against production Sigstore. No wire-shape drift.
```

The `Rekor URL` is permanent and publicly searchable — that's the durable evidence.

## Failure modes

| Symptom | Likely cause |
|---|---|
| Fulcio returns 4xx with `oidc token unsupported` | OIDC issuer not in production Fulcio's allow-list. Pick a different provider in the Dex chooser; staging Fulcio is more permissive than production. |
| Browser tab shows `Bad Request — PKCE S256 is required` | Building from a stale tag pre-PKCE. Re-build from the current `main` and re-run. |
| Browser tab shows the Dex info page (not the provider chooser) | The CLI is hitting `<issuer>` instead of `<issuer>/auth`. Re-build from the current `main`; OIDC discovery is required. |
| Rekor returns 409 `entry already exists` | You signed identical bytes twice. The previous bundle is still valid; re-fetch via `https://rekor.sigstore.dev/api/v1/log/entries?logIndex=<N>`. |
| Rekor returns `invalid signature when validating ASN.1 encoded signature` | Producer signed the digest twice (over `SHA-256(SHA-256(payload))`) — the signer must hand `payload` (not the digest) to RustCrypto's `Signer::sign`, which auto-hashes once. |
| `cosign verify-blob` rejects with `bundle does not contain cert for verification` | Misleading. sigstore-go's `LoadJSONFromPath` rejected the bundle and cosign fell back to the legacy parser. Run the sigstore-go diag tool above to see the real error. Common causes: missing/wrong `logId` shape, missing `canonicalizedBody`, `integratedTime: 0`, empty SET / checkpoint, or `tlogEntries[*].logIndex` >= `inclusionProof.treeSize`. |
| `cosign verify-blob` rejects with `failed to verify log inclusion: index is beyond size` | Sharded Rekor returns DIFFERENT `logIndex` values at the entry top-level (global) vs inside `inclusionProof` (shard-local). Producer must keep them as separate fields, not collapse to one. |
| `cosign verify-blob` rejects with `could not find a valid identity` | `--certificate-identity` doesn't match the SAN. Inspect the cert (step 3) and re-run with the right identity. |
| `oidc fetch: oidc: timed out waiting for browser redirect` | The 15-minute listener window elapsed before you completed the auth flow. Re-run; the timeout is in `sign/src/oidc/interactive_browser.rs::REDIRECT_TIMEOUT`. |

## Re-running after a wire-shape fix

If round-trip fails and we land a fix in justsign (new commit on `main`), re-run from step 1 with the fixed binary. The previous Rekor entry stays in the log forever; just sign fresh bytes.

## Cleanup

The Rekor entry is permanent and intentional — it's the evidence. Don't try to remove it. The OIDC token is short-lived (typically 5–10 minutes) and the leaf cert is valid for 10 minutes; both expire on their own.

The local round-trip dir is safe to delete:

```sh
rm -rf roundtrip/
```

It's `.gitignore`'d to avoid checking in operator-bound OIDC identities.

## See also

- [`integration_guide.md`](../3-design/integration_guide.md) — integration patterns (library, CLI, sigstore-rs replacement).
- [`deployment_guide.md`](./deployment_guide.md) — CI signing patterns (staging-side; this runbook is the production equivalent).
- justsign issue #23 — closed 2026-04-28; the result comment is the durable record.
