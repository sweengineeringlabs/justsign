# Deployment guide

How to integrate justsign into a release pipeline. Two patterns are covered: keyless CI signing (the common case for OSS releases) and static-key release signing using PKCS#11 hardware (the common case for org-internal compliance regimes).

## Pattern 1 — Keyless CI signing (GitHub Actions)

Use case: a CI run signs a release artefact using the runner's GHA OIDC identity, fetches a short-lived Fulcio cert, signs the artefact, embeds a Rekor inclusion proof, and pushes the bundle as an OCI referrer.

```yaml
name: Release sign
on:
  release:
    types: [published]

jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # for the GHA OIDC token
      contents: read
    steps:
      - uses: actions/checkout@v5
      - uses: dtolnay/rust-toolchain@stable

      - name: Build justsign
        run: cargo build --release --bin justsign --features oidc

      - name: Sign release artefact
        env:
          ACTIONS_ID_TOKEN_REQUEST_URL: ${{ env.ACTIONS_ID_TOKEN_REQUEST_URL }}
          ACTIONS_ID_TOKEN_REQUEST_TOKEN: ${{ env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }}
        run: |
          # Fetch GHA OIDC token via the OidcProvider trait
          TOKEN=$(./target/release/justsign oidc-token --provider github-actions)

          # Sign the artefact (bundle written to bundle.json)
          SIGSTORE_ID_TOKEN="$TOKEN" ./target/release/justsign sign-blob \
            --keyless \
            --rekor https://rekor.sigstore.dev \
            --payload-type application/octet-stream \
            ./dist/release-artefact.tar.gz \
            > bundle.json

      - name: Upload bundle as release asset
        uses: softprops/action-gh-release@v2
        with:
          files: bundle.json
```

Verifier-side:

```sh
# Anyone can verify, no setup
justsign verify-blob \
  --bundle bundle.json \
  --expected-san "https://github.com/<org>/<repo>/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --rekor https://rekor.sigstore.dev \
  ./release-artefact.tar.gz
```

The `--expected-san` pin is critical — without it the verifier accepts any leaf cert chained to the trusted Fulcio root. Pinning the SAN to the workflow path bounds who can sign on behalf of your project.

## Pattern 2 — Static-key release signing (PKCS#11 hardware)

Use case: an org-internal release pipeline signs with a key bound to a YubiKey HSM (FIPS 140-2 Level 3) instead of Sigstore keyless. The verifier-side identity is stable across releases (the public key, embedded in the bundle).

```sh
# On the signer host (operator with HSM access)
SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf justsign sign-blob \
  --signer pkcs11 \
  --pkcs11-module /usr/lib/softhsm/libsofthsm2.so \
  --pkcs11-slot 0 \
  --pkcs11-pin-env HSM_PIN \
  --pkcs11-key-label release-key-2026 \
  --rekor https://rekor.sigstore.dev \
  --payload-type application/octet-stream \
  ./dist/release-artefact.tar.gz \
  > bundle.json
```

(The exact CLI flag names may differ — read `cli/src/lib.rs` for the canonical surface.)

Build with:

```sh
cargo build --release --bin justsign --features pkcs11
```

`cryptoki` loads the platform-specific `.so` / `.dll` / `.dylib` from a runtime path. No FFI at compile time; no PKCS#11 SDK on the build host. The runtime host needs the appropriate vendor library: SoftHSM2 (`libsofthsm2.so`) for tests, `libykcs11` for YubiKey, vendor library for HSMs.

## Bundling justsign as a binary release

```sh
cargo build --release --bin justsign
ls -lh target/release/justsign
```

Default-features build is ~5–8 MB on x86_64 Linux. Per-feature additive sizes:

| Features | Approximate size delta |
|---|---|
| (default) | baseline |
| `+pkcs11` | +200 KB (cryptoki + libloading) |
| `+oidc` | +400 KB (reqwest already in default) |
| `+oidc,oidc-browser` | +500 KB |
| `+ed25519,ecdsa-p384,secp256k1` | +1.2 MB (RustCrypto stack expansion) |
| `+aws-kms,gcp-kms,azure-kv,vault-transit` | negligible (stubs only) |

CI matrix tests `x86_64-unknown-linux-gnu`. Cross-compilation to other targets is best-effort; check `.github/workflows/ci.yml` for the canonical platform support.

## Operator runbooks

Already in this repo:

- **TUF root rotation** — see `docs/3-design/adr/001_sigstore_tuf_bootstrap.md`. The bundled v14 root rotates via release; chain-walk handles rotations Sigstore publishes with a chain (the common case). Build-time check fails the build if the bundled asset corrupts or expires; runtime guard returns `TufError::EmbeddedRootExpired` on stale bundle.
- **Staging integration tests** — `.github/workflows/staging.yml` triggers on manual dispatch. Sets the env vars from repo secrets. Use to verify wire shape against Sigstore staging before promoting to production verification.
- **Justoci e2e** — the cross-repo `JustsignInvoker` in justoci's attest crate is the integration witness. Running the justoci e2e harness with `--features justsign` confirms our bundles are accepted by a cosign-shape verifier.

## Production-readiness gaps

These are open issues that block calling justsign "production-ready":

| Issue | Title | Impact |
|---|---|---|
| #15 | crates.io publication | No pinned-version published artifact. Consumers track via git tags. |
| #23 | Production Sigstore round-trip | Live tests point at staging only. Wire compat against production Sigstore is unverified. |
| #28 | MSRV stability policy | Bumped 4× during v0; no documented bump cadence. Distros lag. |
| #29 | `VerifyingKey` migration guide | Multi-algo enum changed `verify_blob`'s `trusted_keys` parameter — migration notes pending. |

For the full list, run `gh issue list --repo sweengineeringlabs/justsign --label prod-ready`.

## Stability promise

Public APIs (`sign_blob`, `verify_blob`, `attest`, `verify_attestation`, `sign_oci`, `verify_oci`, `sign_blob_keyless`, `verify_blob_keyless`) are stable as of v0.1.0. New algorithms / providers / features ship as additive surfaces; existing callers don't need to migrate per release.

The `Signer` / `RekorClient` / `FulcioClient` / `OidcProvider` traits are stable; new impls land alongside.

Wire format is pinned to Sigstore protobuf-specs v0.3 — see `docs/3-design/integration_guide.md`.

## See also

- [`integration_guide.md`](../3-design/integration_guide.md) — three integration shapes (library, CLI, sigstore-rs replacement).
- [`threat_model.md`](../3-design/threat_model.md) — what the verifier guarantees vs what callers must enforce.
- [`testing_strategy.md`](../5-testing/testing_strategy.md) — four test layers and the bug-class convention.
- [`developer_guide.md`](../4-development/developer_guide.md) — local setup, branch flow, conventions.
