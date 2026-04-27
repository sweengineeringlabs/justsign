# Integration guide

How to integrate justsign into other systems. Three integration shapes are supported: as a Rust library, as a CLI binary, and as a `sigstore-rs` replacement behind a feature flag.

## As a library

Minimal `Cargo.toml` to sign + verify a blob with the default ECDSA P-256 path:

```toml
[dependencies]
sign      = { package = "swe_justsign_sign",   git = "https://github.com/sweengineeringlabs/justsign", tag = "v0.1.0" }
spec      = { package = "swe_justsign_spec",   git = "https://github.com/sweengineeringlabs/justsign", tag = "v0.1.0" }
p256      = { version = "0.13", default-features = false, features = ["std", "ecdsa", "pkcs8"] }
rand_core = { version = "0.6",  default-features = false, features = ["std", "getrandom"] }
```

Sign and verify:

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

For attestations:

```rust
use sign::{attest, verify_attestation, EcdsaP256Signer, VerifyingKey};

let bundle = attest(
    "pkg:oci/example@sha256:abc",
    "sha256",
    "abc...64hex",
    "https://slsa.dev/provenance/v1",
    serde_json::json!({ "buildType": "..." }),
    &signer,
    None,
)?;

let verified = verify_attestation(
    &bundle,
    &[VerifyingKey::P256(vk)],
    "https://slsa.dev/provenance/v1",
    Some(("sha256", "abc...64hex")),
    None,
)?;
```

For OCI-shape artefacts:

```rust
use sign::{sign_oci, verify_oci};

let artifacts = sign_oci(
    "sha256:abc...",
    "application/vnd.oci.image.manifest.v1+json",
    4096,
    &signer,
    None,
)?;
// artifacts.bundle_bytes + artifacts.referrer_manifest go to a registry
```

## As a CLI

The `justsign` binary covers operator-side signing and verification without writing Rust.

```sh
# Generate a keypair (SPKI PEM public, PKCS#8 PEM private)
justsign generate-key-pair --out-priv key.priv --out-pub key.pub

# Print the public key for an existing private key
justsign public-key --in key.priv

# Sign a blob (writes a Sigstore Bundle JSON to stdout)
justsign sign-blob --key key.priv --payload-type text/plain ./payload.txt > bundle.json

# Verify the bundle
justsign verify-blob --key key.pub --bundle bundle.json ./payload.txt

# Fetch an OIDC token via a configured provider (Static / GitHubActions / GcpMetadata / InteractiveBrowser)
justsign oidc-token --provider github-actions
```

See `cli/src/lib.rs` for the full subcommand reference. Bare `--rekor` defaults to `https://rekor.sigstage.dev`; pass an explicit URL for production.

## As a `sigstore-rs` replacement

The cross-repo justoci sibling demonstrates the swap. Its `attest` crate exposes a `CosignInvoker` trait with three impls:

- `SigstoreInvoker` — `sigstore-rs` SDK (default, `--features sigstore-rs`).
- `RealCosignInvoker` — subprocess to the `cosign` binary (`--features cosign-subprocess`).
- `JustsignInvoker` — pure Rust via justsign (`--features justsign`).

The justsign-backed invoker uses:

- `swe_justsign_fulcio::HttpFulcioClient` for the cert exchange.
- `swe_justsign_rekor::HttpRekorClient` for the transparency log.
- `swe_justsign_sign::sign_blob_keyless` to assemble the Sigstore bundle with the chain attached.

Operators who want to drop the `sigstore-rs` dep tree entirely build justoci with `--no-default-features --features justsign` (and any optional persistence features). See justoci issue #16 for the full integration history.

## Feature flags

| Flag | What it enables | Dep cost | Status |
|---|---|---|---|
| (default) | ECDSA P-256, Sigstore Bundle, DSSE, in-toto, sync HTTP clients | minimal RustCrypto + reqwest | real |
| `ed25519` | `Ed25519Signer` + `VerifyingKey::Ed25519` | `ed25519-dalek` | real |
| `ecdsa-p384` | `EcdsaP384Signer` + `VerifyingKey::P384` | `p384` | real |
| `secp256k1` | `Secp256k1Signer` + `VerifyingKey::K256` | `k256` | real |
| `pkcs11` | `Pkcs11Signer` for hardware key signing (YubiKey, SoftHSM, HSMs) | `cryptoki` (loads `.so`/`.dll`/`.dylib` at runtime) | real |
| `oidc` | `OidcProvider` trait + Static / GitHubActions / GcpMetadata providers | `reqwest` | real |
| `oidc-browser` | `InteractiveBrowserOidcProvider` (OAuth dance with localhost listener) | `open` (browser launcher) | real |
| `aws-kms` | `AwsKmsSigner` typed surface | (none yet) | **stub** — see #17 |
| `gcp-kms` | `GcpKmsSigner` typed surface | (none yet) | **stub** — see #18 |
| `azure-kv` | `AzureKeyVaultSigner` typed surface | (none yet) | **stub** — see #19 |
| `vault-transit` | `VaultTransitSigner` typed surface | (none yet) | **stub** — see #20 |
| `async` (fulcio + rekor) | `AsyncFulcioClient` + `AsyncRekorClient` traits using non-blocking reqwest | `tokio`, `async-trait` | real |

Stubs return `SignerError::Stubbed("...; SDK integration tracked in justsign#NN")` on every `sign()` call. They give callers the typed surface today; real SDK integration lands per-provider when downstream demand arrives.

## Wire compatibility

justsign's `Bundle::encode_json` emits the protobuf-specs v0.3 canonical shape: `verificationMaterial.x509CertificateChain.certificates[].rawBytes` (NOT the legacy `certificate.certificates`). Decode accepts both shapes for backwards compat with older cosign / sigstore-rs producers. Pinned by `test_encode_json_emits_canonical_certificate_shape` in `spec/src/sigstore_bundle.rs`.

Bundles produced by justsign verify against:

- justsign's own `verify_blob` / `verify_blob_keyless`.
- cosign 2.x `cosign verify-blob` (verified by the e2e harness in justoci's `attest/tests/justsign_e2e_test.rs` against staging Sigstore).
- Production Sigstore round-trip is **NOT yet validated** — see prod-readiness issue #23.

## Stability promise

The high-level API (`sign_blob`, `verify_blob`, `attest`, `verify_attestation`, `sign_oci`, `verify_oci`) is stable as of v0.1.0. The `VerifyingKey` enum may grow new variants in a minor release (each gated on a new feature flag) — match it `match key { VerifyingKey::P256(vk) => ..., _ => return Err(...) }` if you want to be explicit about supported algorithms.

The `Signer` and `RekorClient` and `FulcioClient` traits are stable; existing impls won't change shape. New impls land alongside.

The `OidcProvider` trait is stable; new providers land as separate types in `sign::oidc::*`.

Wire format follows protobuf-specs v0.3 — backwards-compatible JSON shape changes only.

## Production readiness

See `docs/3-design/threat_model.md` for what the verifier guarantees vs what callers must enforce themselves. The README's "What's NOT done" section + the `prod-ready` issue label track the gaps that block a v0.1.0 production-ready label.
