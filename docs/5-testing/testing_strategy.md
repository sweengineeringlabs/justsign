# Testing strategy

justsign is a security library — every test exists to prevent a specific regression that would change a verification outcome or compromise a signing guarantee. This document describes the four test layers, the bug-class doc-comment convention, and what's NOT yet tested.

## Layer 1 — Unit tests (`#[cfg(test)] mod tests`)

Per-crate, per-module unit tests covering individual primitives:

- DSSE PAE construction (`spec/src/dsse.rs`)
- Bundle JSON encode/decode round-trips (`spec/src/sigstore_bundle.rs`)
- Cert-chain walk + SAN validation (`sign/src/cert_chain.rs`)
- TUF canonical-JSON encoding (`tuf/src/canonical.rs`)
- TUF span-preserving parser (`tuf/src/span.rs`)
- Rekor inclusion-proof Merkle math (`rekor/src/merkle.rs`)
- Per-algorithm signers (`sign/src/signer.rs`, `sign/src/pkcs11.rs`, `sign/src/kms/*.rs`)

```sh
cargo test --workspace
```

## Layer 2 — Per-feature unit tests

Each feature flag introduces opt-in surfaces that have their own tests:

```sh
cargo test -p swe_justsign_sign --features ed25519
cargo test -p swe_justsign_sign --features ecdsa-p384
cargo test -p swe_justsign_sign --features secp256k1
cargo test -p swe_justsign_sign --features pkcs11
cargo test -p swe_justsign_sign --features oidc
cargo test -p swe_justsign_sign --features oidc,oidc-browser
cargo test -p swe_justsign_sign --all-features
cargo test -p swe_justsign_fulcio --features async
cargo test -p swe_justsign_rekor --features async
```

Stub feature tests (KMS providers `aws-kms`, `gcp-kms`, `azure-kv`, `vault-transit`) deliberately assert the `SignerError::Stubbed` return — they catch any regression that lands a real SDK call before the per-provider follow-up issue (#17–#20) ships its real impl.

## Layer 3 — Skip-pass live integration tests

The load-bearing differentiator. Sigstore's wire shape and the kernel's actual behaviour against a SoftHSM2 token are not the same set of bytes that unit tests pin. Three external validators are wired in:

| Test | Env vars | What it catches |
|---|---|---|
| `test_http_fulcio_client_signs_cert_against_staging` | `JUSTSIGN_FULCIO_STAGING=1` + `JUSTSIGN_OIDC_TOKEN=<JWT>` | Wire-format drift between our CSR/JSON and Fulcio's actual API. |
| `test_http_rekor_client_round_trips_against_staging` | `JUSTSIGN_REKOR_STAGING=1` | Wire-format drift between our hashedrekord JSON envelope and Rekor's actual API. |
| `test_tuf_client_walks_real_sigstore_chain_when_configured` | `JUSTSIGN_TUF_LIVE=1` + `JUSTSIGN_TUF_BOOTSTRAP=...` | Drift between the TUF spec we implement and what Sigstore's actual repo serves. |
| `test_pkcs11_signer_signs_against_softhsm_when_configured` | `JUSTSIGN_SOFTHSM_LIB=...` + `JUSTSIGN_SOFTHSM_PIN=...` + `JUSTSIGN_SOFTHSM_KEY_LABEL=...` | Drift between our `cryptoki` calls and the actual PKCS#11 API as exposed by SoftHSM2 / YubiKey. |

**Skip-pass pattern**: every test is *always-on* (no `#[ignore]`). When env vars are unset, the test prints `SKIP: <reason>` and returns success. CI's default `cargo test` flow runs them; they no-op without secrets. CI's manual-dispatch `staging.yml` workflow sets the env vars to actually drive the live calls.

## Layer 4 — Fuzzing

`fuzz/` carries `cargo-fuzz` targets for the wire-decode surfaces:

| Target | Bug class |
|---|---|
| `envelope_decode_json` | DSSE wire panic / parser DoS |
| `bundle_decode_json` | Sigstore Bundle JSON parser |
| `statement_decode_json` | in-toto Statement parser |
| `tuf_canonicalize` | Canonical JSON encoder edge cases |
| `tuf_parse_with_signed_span` | Span-preserving TUF parser |
| `fulcio_parse_chain` | PEM/DER cert chain parser |
| `rekor_decode_log_entry_bytes` | Rekor LogEntry decoder |
| `oci_parse_referrer_manifest` | OCI 1.1 referrer manifest parser |

Fuzzing requires nightly Rust + libFuzzer runtime. Linux CI runs each target for 5 minutes on `workflow_dispatch` (`.github/workflows/fuzz.yml`). Local Windows runs may hit a `clang_rt.fuzzer*.dll` PATH gap; the harness *builds* on Windows but runtime fuzzing wants a Linux/macOS host or a Windows host with the libFuzzer DLL on PATH.

## Bug-class doc-comment convention

Every test names a concrete regression class above its `#[test]`:

```rust
/// Bug it catches: a verifier that always accepted the first
/// subject without comparing its digest to the expected value
/// would let an attacker swap in an attestation about a
/// different artifact and still pass policy.
#[test]
fn test_verify_attestation_rejects_subject_digest_mismatch() { /* ... */ }
```

A test that just exercises a code path without naming what it would catch is rejected at review. Tests are signal, not noise — every test must be able to fail when its claim is wrong.

## Coverage map

Run `cargo test --workspace 2>&1 | grep "test result:"` for current per-crate counts. Numbers shift release-to-release; this section pins the principle, not the count: every public function in `sign_blob`, `verify_blob`, `attest`, `verify_attestation`, `sign_oci`, `verify_oci`, `sign_blob_keyless`, `verify_blob_keyless` has at least one happy-path test, one signature-failure test, one input-shape-failure test, and one cross-API mismatch test (e.g. verifying a signature with the wrong key, decoding a payload with the wrong type).

## What's NOT tested

Honest gaps tracked as `prod-ready` GitHub issues:

- **#23**: production Sigstore round-trip — every live test points at staging. We have no evidence that bundles produced by justsign verify against the *production* Sigstore trust roots. Likely the highest-impact pre-1.0 gap.
- **#26**: cert expiry enforcement was the v0 placeholder; landed but the keyless verifier's clock-skew window edge cases need more coverage.
- **#17–#20**: KMS providers ship as stubs. Stub tests confirm the surface is typed; real SDK round-trips are the per-provider follow-up.
- **#34**: cross-verification of the bundled Sigstore root against cosign's published bundle. We trust our `include_bytes!` asset matches cosign's; not yet automated.
- **Fork verification against cosign 2.x output**: every bundle justsign produces should round-trip through `cosign verify-blob`. Justoci's `justsign_e2e_test` covers this against staging — production pinning is #23.

## CI gates

| Job | Trigger | What runs |
|---|---|---|
| `cargo test (stable)` | push to all 6 branches | full workspace test suite, default features |
| `cargo check (MSRV 1.88)` | push to all 6 branches | check-only build at the MSRV pin |
| `cargo clippy` | push to all 6 branches | `--all-targets -- -D warnings` |
| `cargo fmt --check` | push to all 6 branches | `--all -- --check` |
| `staging.yml` | manual dispatch | live Fulcio / Rekor / TUF / SoftHSM2 integration |
| `fuzz.yml` | manual dispatch | each cargo-fuzz target for 5 minutes |
| `pages.yml` | push to main | mdBook build + Pages deploy |

A change must pass `dev` CI before ff-cascading to `test`, and so on through `prd → main`. The `main` branch publishes the docs site.

## Adding a new test

The hard part is the bug-class doc comment. Force yourself to articulate, in one sentence, the regression that this test catches. If you can't name a concrete past or potential bug, the test is decorative — drop it. The right tests prevent specific regressions; the wrong tests inflate the pass count without changing the failure surface.
