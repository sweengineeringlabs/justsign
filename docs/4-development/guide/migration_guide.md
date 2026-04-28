# Migration guide

**Audience**: Library consumers upgrading justsign across versions; downstream maintainers planning a version bump.

This document tracks API changes between justsign releases that require caller-side adjustment. Entries are in reverse chronological order (newest at the top).

## post-v0.1.0 (#38) — bundle wire shape: singular `certificate` leaf, not `x509CertificateChain`

**Affects**: downstream tools that parse the JSON bundle directly (jq, sigstore-go, sigstore-python, custom verifiers). The Rust API is unchanged.

### What changed

`Bundle::encode_json` now emits the cert material at the singular `verificationMaterial.certificate.rawBytes` (protobuf `X509Certificate` arm of the `VerificationMaterial.content` oneof — the shape protobuf-specs v0.3 final settled on after deprecating `x509_certificate_chain`).

Before (#31 pin):

```json
{
  "verificationMaterial": {
    "x509CertificateChain": {
      "certificates": [
        { "rawBytes": "<base64 leaf DER>" },
        { "rawBytes": "<base64 intermediate DER>" }
      ]
    }
  }
}
```

After (#38):

```json
{
  "verificationMaterial": {
    "certificate": { "rawBytes": "<base64 leaf DER>" }
  }
}
```

Only the leaf is emitted. Verifiers reconstruct intermediates and the trusted root from their TUF-validated trust anchors, not from the bundle.

### Why we made the change

cosign 3.0+ rejects bundles carrying `x509CertificateChain` with `bundle does not contain cert for verification, please provide public key`. Producing the deprecated arm makes every justsign-signed artifact unverifiable on cosign 3.x.

### Caller-side impact

The Rust API is unchanged: `sign_blob_keyless(payload, media_type, signer, cert_chain_der, rekor)` still accepts the full DER chain `&[Vec<u8>]` and the in-memory `Certificate { certificates: Vec<Vec<u8>> }` model is preserved for any verifier that walks the chain in-process. The leaf-only emit is purely a serialisation change.

If you parse the bundle JSON directly:

```sh
# before (#31): chain wrapper, one entry per cert in chain
jq -r '.verificationMaterial.x509CertificateChain.certificates[0].rawBytes' bundle.json

# after (#38): singular leaf
jq -r '.verificationMaterial.certificate.rawBytes' bundle.json
```

### Decode compatibility

`Bundle::decode_json` accepts BOTH shapes — the new singular `certificate` AND the legacy `x509CertificateChain` wrapper — so existing bundles produced by cosign 2.x or older sigstore-rs continue to load. Bundles populating BOTH arms simultaneously are rejected with `BundleDecodeError::BothCertificateShapesSet`.

### Downstream upgrade path

- **cosign 2.x consumers**: upgrade to cosign 3.0+ to read justsign-produced bundles. cosign 2.x will reject the singular leaf shape.
- **sigstore-rs consumers**: pin to a recent version that handles the protobuf-specs v0.3 final shape. Older versions that only decode `x509CertificateChain` will see no cert material in justsign-produced bundles.
- **sigstore-go / sigstore-python**: any version that follows protobuf-specs v0.3 final will work; legacy versions that only handle the chain wrapper will not.
- **Custom jq / shell pipelines**: substitute `verificationMaterial.certificate.rawBytes` for the old chain path.

## v0.1.0 — `verify_blob`'s `trusted_keys` parameter changed shape

**Affects**: callers of `verify_blob`, `verify_blob_keyless`, `verify_attestation`, `verify_oci`, `verify_slsa_provenance`, `verify_cyclonedx`, `verify_spdx`.

### Before (pre-#12)

```rust
use sign::verify_blob;
use p256::ecdsa::VerifyingKey;

let vk: VerifyingKey = /* parse SPKI PEM, etc. */;
verify_blob(&bundle, &[vk], None)?;
```

The verifier accepted a slice of `p256::ecdsa::VerifyingKey` directly — single-algorithm, no opt-in for other curves.

### After (post-#12)

```rust
use sign::{verify_blob, VerifyingKey};
use p256::ecdsa::VerifyingKey as P256Vk;

let vk_p256: P256Vk = /* parse SPKI PEM, etc. */;
verify_blob(&bundle, &[VerifyingKey::P256(vk_p256)], None)?;
```

`VerifyingKey` is now an algorithm-tagged enum. Default-feature builds carry only the `P256` variant; `Ed25519`, `P384`, `K256` variants gate on their respective feature flags (`ed25519`, `ecdsa-p384`, `secp256k1`).

### Quick migration: the `From` lift

If you have a `p256::ecdsa::VerifyingKey` and want a one-line migration:

```rust
verify_blob(&bundle, std::slice::from_ref(&vk.into()), None)?;
```

The `From<p256::ecdsa::VerifyingKey> for VerifyingKey` impl wraps your existing key in the `P256` variant. Less ceremonial than `VerifyingKey::P256(vk)` for callers that don't care about other algorithms.

### Why we made the change

Multi-algorithm signers (Ed25519 / P-384 / secp256k1) needed verifier-side dispatch. Adding a parameter to `verify_blob` (e.g. `algorithm: Algorithm`) would have spread algorithm awareness across every call site. An algorithm-tagged enum keeps the dispatch local to the verify loop and lets callers mix algorithms in one `&[VerifyingKey]` slice (useful for org-wide trust roots that span multiple key types).

### Rolling out across multiple call sites

If you have many callers, the path of least resistance:

1. Bump justsign to v0.1.0 in your `Cargo.toml`.
2. Run `cargo build` to surface every call site that fails.
3. For each: change `vk` to `VerifyingKey::P256(vk)` if you know the algorithm, OR `vk.into()` if you want the `From` lift.
4. If you carry trust roots from multiple algorithms, build a `Vec<VerifyingKey>` once and reuse it.

`verify_blob` returns `VerifyError::SignatureInvalid` when none of the supplied keys validates the signature — same as before. The error variant set is otherwise unchanged.

### Affected wrappers

These convenience wrappers all accept `&[VerifyingKey]` post-#12; same migration applies:

- `verify_blob_keyless` (per #5 + #26)
- `verify_attestation` (per #7)
- `verify_oci` (per #6)
- `verify_slsa_provenance` (per #8)
- `verify_cyclonedx` + `verify_spdx` (per #9)

## v0.0.x — pre-publication releases

Not migrated from. v0.1.0 is the first published release (#15).

## Future migration entries

Land here in reverse chronological order. Each entry covers:

- One-sentence summary of the API change.
- Before / after code snippets.
- A copy-paste migration recipe (preferably one-line if possible).
- Rationale for the change.

## See also

- [`msrv_policy.md`](./msrv_policy.md) — when MSRV bumps land + impact on consumers.
- [`integration_guide.md`](../3-design/integration_guide.md) — three integration shapes (library, CLI, sigstore-rs replacement).
- [`developer_guide.md`](./developer_guide.md) — local setup, branch flow, conventions.
