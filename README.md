# justsign

Pure-Rust Sigstore client, producer, and verifier. justsign is the
target drop-in replacement for [`sigstore-rs`] in cosign-shape
workflows: it produces and verifies Sigstore bundles, talks to a
real Fulcio (keyless certs) and Rekor (transparency log), and
walks a TUF root against the Sigstore mirror — without pulling in
a Go binary or a network of cosign-shape side processes.

> **Status:** alpha. Ship-stable APIs are `sign_blob`, `verify_blob`,
> `attest`, `verify_attestation`, `sign_oci`, `verify_oci`. Trust-root
> handling and the clock SPI are still evolving — see [What's NOT
> done](#whats-not-done) below.

---

## What works

These are real features, exercised by tests in this repo today.

- **Wire formats**: DSSE envelope, Sigstore Bundle v0.3 (`spec`),
  in-toto Statement v1, SLSA Provenance v1, SBOM predicates
  (CycloneDX 1.5 + SPDX 2.3).
- **Sign + verify** against Sigstore-shape bundles, both static-key
  (`sign_blob` / `verify_blob`) and keyless against a caller-supplied
  Fulcio cert chain (`sign_blob_keyless` / `verify_blob_keyless`).
- **Attestations**: `attest` / `verify_attestation` for any in-toto
  predicate, plus the convenience helpers `sign_slsa_provenance`,
  `sign_cyclonedx`, `sign_spdx` and matching verifiers.
- **OCI artifact signing**: `sign_oci` / `verify_oci` produce + verify
  the OCI 1.1 referrer manifest cosign uses for image signing.
- **Real HTTP Fulcio + Rekor** clients, blocking by default
  (`reqwest::blocking`) and async on opt-in: `fulcio` and `rekor`
  each expose an `async = ["dep:async-trait", "dep:tokio"]` feature
  that lights up an `AsyncFulcioClient` / `AsyncRekorClient` trait.
- **TUF root walker** against the Sigstore mirror, with
  span-preserving signature verification ([#21][i21], [#22][i22]) so
  signed-bytes drift between fetch and re-encode can't be hidden.
- **Multi-algo signers**: P-256 by default; Ed25519, P-384, and
  secp256k1 are opt-in via `--features ed25519`, `--features
  ecdsa-p384`, `--features secp256k1`. The `VerifyingKey` enum on the
  verifier side surfaces the matching variants behind the same flags.
- **PKCS#11 hardware key support** (YubiKey, SoftHSM2, vendor HSMs)
  via `--features pkcs11`. The provider library (`.so` / `.dll` /
  `.dylib`) is loaded from a caller-supplied path at runtime.
- **OIDC identity-token providers** for keyless flows: `Static`,
  `GitHubActionsOidcProvider`, `GcpMetadataOidcProvider` behind
  `--features oidc`; the `InteractiveBrowserOidcProvider` adds
  `--features oidc-browser` (pulls the `open` crate to launch the
  operator's default browser).

## What's stub

These types are real and feature-gated, but their network-call paths
return a typed `SignerError::Stubbed` pointing at a follow-up issue.
Downstream callers can declare a KMS signer in their code today; the
real SDK integration lands as separate slices to keep the dep-tree
balloon scoped.

- **KMS signers** — typed surface only:
  - `AwsKmsSigner` (`--features aws-kms`) — see [#17][i17].
  - `GcpKmsSigner` (`--features gcp-kms`) — see [#18][i18].
  - `AzureKeyVaultSigner` (`--features azure-kv`) — see [#19][i19].
  - `VaultTransitSigner` (`--features vault-transit`) — see [#20][i20].

## What's NOT done

These are the known production-readiness gaps for v0.1.0. Each has
a tracking issue; the README will be updated as they close.

- **Production Sigstore round-trip not yet validated** — fulcio/rekor
  unit tests run against staging only; the prod-vs-staging drift
  matrix isn't in CI yet. See [#23][i23].
- **No fuzzing harness yet** for the wire-decode parsers (Bundle JSON,
  DSSE envelope, in-toto Statement, TUF metadata). In flight — see
  [#24][i24].
- **No threat model document yet**. In flight — see [#25][i25].
- **Cert expiry not yet enforced** in `verify_blob_keyless`: the
  `VerifyError::CertExpired` variant is defined but never produced
  because the clock SPI is pending. See [#26][i26].
- **Sigstore TUF root bootstrap is caller-supplied** — no bundled
  trust root for the public-good Sigstore instance. See [#27][i27].
- **MSRV stability policy not yet documented**. The workspace declares
  `rust-version = "1.88"` because the active dep graph requires it,
  but the cadence for bumping it is not written down. See [#28][i28].
- **`VerifyingKey` migration guide pending** — `verify_blob`'s
  `trusted_keys` parameter changed from `&[p256::ecdsa::VerifyingKey]`
  to `&[VerifyingKey]` of the algorithm-tagged enum. The deprecation
  path / migration notes haven't been written. See [#29][i29].
- **Bundle JSON shape pinning pending** — `certificate.certificates`
  vs `verificationMaterial.x509CertificateChain`. See [#31][i31].
- **Granular `RekorError` variants pending** — transport vs HTTP
  status vs decode aren't separated yet. See [#32][i32].

## Quickstart

A minimal sign-then-verify of a blob, default features only:

```rust
use sign::{sign_blob, verify_blob, EcdsaP256Signer, VerifyingKey};
use p256::ecdsa::SigningKey;
use rand_core::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sk = SigningKey::random(&mut OsRng);
    let vk = *sk.verifying_key();
    let signer = EcdsaP256Signer::new(sk, None);

    let bundle = sign_blob(b"hello", "text/plain", &signer, None)?;
    verify_blob(&bundle, &[VerifyingKey::P256(vk)], None)?;
    Ok(())
}
```

For real-world flows:

- Pass a `&dyn rekor::RekorClient` as the fourth argument to
  `sign_blob` to embed a transparency-log entry in the bundle, and
  pass the same client to `verify_blob` to re-check the inclusion
  proof.
- For attestations, call `attest(subject_name, algo, hex,
  predicate_type, predicate, &signer, rekor)` and then
  `verify_attestation(&bundle, &keys, expected_predicate_type,
  expected_subject_digest, rekor)`.
- For OCI artifacts, call `sign_oci(subject_digest,
  subject_media_type, subject_size, &signer, rekor)` to produce an
  OCI 1.1 referrer manifest pair, and `verify_oci(&manifest_bytes,
  &bundle, &keys, rekor)` to verify what you pulled from a registry.
- For keyless flows, use `sign_blob_keyless` with a Fulcio-issued
  cert chain and `verify_blob_keyless` with caller-supplied trust
  anchors and an expected SAN.

## Crates

| Crate                  | Role                                                                                                                |
|------------------------|---------------------------------------------------------------------------------------------------------------------|
| `swe_justsign_spec`    | Wire formats: DSSE envelope, in-toto Statement, Sigstore Bundle JSON, Rekor entries. Pure structs + serde, no IO.   |
| `swe_justsign_fulcio`  | Fulcio client: OIDC token to CSR to short-lived cert chain. Blocking by default; `--features async` for async.      |
| `swe_justsign_tuf`     | TUF metadata fetch + verify; establishes Sigstore root of trust via span-preserving JSON.                           |
| `swe_justsign_rekor`   | Rekor client: submit + Merkle inclusion-proof verification. Independent — works with static keys too.               |
| `swe_justsign_sign`    | High-level API: `sign_blob`, `verify_blob`, `attest`, `verify_attestation`, `sign_oci`, `verify_oci`.               |
| `swe_justsign_cli`     | `justsign` operator binary.                                                                                         |

## Architecture

A standalone architecture document is not yet in the repo. The crate
table above plus the module-level rustdoc on `sign/src/lib.rs` is the
current source of truth. A `docs/3-design/architecture.md` is planned
as part of [#25][i25] (threat model) so the trust boundaries diagram
lands once, in one place.

## Documentation

- [Threat model](docs/3-design/threat_model.md) — what the v0 verifier
  guarantees, what it doesn't, and the caller-side checklist.

## Build

```sh
cargo build --workspace
cargo test  --workspace
```

To exercise the opt-in surfaces:

```sh
cargo build -p swe_justsign_sign --features ed25519,ecdsa-p384,secp256k1
cargo build -p swe_justsign_sign --features pkcs11
cargo build -p swe_justsign_sign --features oidc
cargo build -p swe_justsign_fulcio --features async
cargo build -p swe_justsign_rekor --features async
```

Minimum supported Rust version: **1.88** (driven by the active dep
graph; see workspace `Cargo.toml` for the full reasoning). The MSRV
stability policy is not yet documented — see [#28][i28].

## Sibling repos

- [`vmisolate`](../vmisolate)
- [`justoci`](../justoci) — historical `sigstore-rs` consumer; the
  swap to justsign tracks under [#16][i16] (closed as of v0.1.0 prep).
- [`justcas`](../justcas)
- [`justext4`](../justext4)

## License

[Apache-2.0](LICENSE). Matches `justoci`, `justcas`, `justext4`,
the OCI specs, and every CNCF project.

## Maintainers

[SWE Engineering Labs](https://github.com/sweengineeringlabs).

---

[i16]: https://github.com/sweengineeringlabs/justsign/issues/16
[i17]: https://github.com/sweengineeringlabs/justsign/issues/17
[i18]: https://github.com/sweengineeringlabs/justsign/issues/18
[i19]: https://github.com/sweengineeringlabs/justsign/issues/19
[i20]: https://github.com/sweengineeringlabs/justsign/issues/20
[i21]: https://github.com/sweengineeringlabs/justsign/issues/21
[i22]: https://github.com/sweengineeringlabs/justsign/issues/22
[i23]: https://github.com/sweengineeringlabs/justsign/issues/23
[i24]: https://github.com/sweengineeringlabs/justsign/issues/24
[i25]: https://github.com/sweengineeringlabs/justsign/issues/25
[i26]: https://github.com/sweengineeringlabs/justsign/issues/26
[i27]: https://github.com/sweengineeringlabs/justsign/issues/27
[i28]: https://github.com/sweengineeringlabs/justsign/issues/28
[i29]: https://github.com/sweengineeringlabs/justsign/issues/29
[i31]: https://github.com/sweengineeringlabs/justsign/issues/31
[i32]: https://github.com/sweengineeringlabs/justsign/issues/32

[`sigstore-rs`]: https://github.com/sigstore/sigstore-rs
