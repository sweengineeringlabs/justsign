# Migration guide

This document tracks API changes between justsign releases that require caller-side adjustment. Entries are in reverse chronological order (newest at the top).

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
