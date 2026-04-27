//! High-level sign / verify API.
//!
//! v0 covers the **blob** case end-to-end: take payload bytes +
//! a [`Signer`], optionally submit to a [`rekor::RekorClient`],
//! and emit a [`spec::Bundle`] that round-trips through
//! [`verify_blob`].
//!
//! OCI artifact + container signing land in subsequent slices.
//!
//! ## Wire-shape decisions for v0
//!
//! * **Bundle content** is always [`spec::BundleContent::DsseEnvelope`].
//!   The `MessageSignature` arm is for the cosign-compat raw-hash
//!   shape and isn't this v0's job.
//! * **Verification material** has no `Certificate` set — Fulcio /
//!   keyless flows land in v0.5. Verifiers in v0 are given the
//!   trusted public keys directly.
//! * **`tlog_entries`** are populated only when a [`rekor::RekorClient`]
//!   is supplied to [`sign_blob`]. The mock client lands a single-
//!   leaf log proof; the real HTTP client (v0.5) populates the
//!   same shape.
//!
//! ## What the verifier checks
//!
//! [`verify_blob`] enforces, in order:
//!
//! 1. Bundle's content variant is `DsseEnvelope` (not message-sig).
//! 2. At least ONE of the envelope's signatures validates against
//!    one of the trusted [`VerifyingKey`]s. The PAE is re-derived
//!    from the envelope's `payload_type` + `payload`; the signature
//!    is interpreted as DER-encoded ECDSA-P256.
//! 3. **Optionally**, if the caller passes a [`rekor::RekorClient`]
//!    AND the bundle has `tlog_entries`, every entry's inclusion
//!    proof verifies against its claimed root.
//!
//! Step 3 is intentionally OPTIONAL: a caller that doesn't supply
//! a Rekor client says "I don't care about transparency this time"
//! — useful for offline verification flows. Policy that REQUIRES
//! transparency lives one layer up.

pub use fulcio;
pub use rekor;
pub use spec;
pub use tuf;

pub mod cert_chain;
mod error;
#[cfg(any(
    feature = "aws-kms",
    feature = "gcp-kms",
    feature = "azure-kv",
    feature = "vault-transit"
))]
pub mod kms;
pub mod oci;
#[cfg(feature = "oidc")]
pub mod oidc;
pub mod sbom;
mod signer;
pub mod slsa;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

pub use error::{OciError, SignError, VerifyError};
pub use sbom::{sign_cyclonedx, sign_spdx, verify_cyclonedx, verify_spdx};
pub use signer::{EcdsaP256Signer, MockSigner, Signer, SignerError};

// Per-algorithm signer re-exports (issue #12). Each is feature-gated
// so the default build still surfaces only the P-256 surface — same
// posture as the KMS / PKCS#11 signers above.
#[cfg(feature = "ecdsa-p384")]
pub use signer::EcdsaP384Signer;
#[cfg(feature = "ed25519")]
pub use signer::Ed25519Signer;
#[cfg(feature = "secp256k1")]
pub use signer::Secp256k1Signer;

// Per-provider KMS signer re-exports. Each is feature-gated so the
// default build surfaces no KMS types and pulls no KMS deps (there
// are no KMS deps in v0; the gating keeps the surface honest as
// real SDKs land per follow-up issue).
#[cfg(feature = "aws-kms")]
pub use kms::aws::AwsKmsSigner;
#[cfg(feature = "azure-kv")]
pub use kms::azure::AzureKeyVaultSigner;
#[cfg(feature = "gcp-kms")]
pub use kms::gcp::GcpKmsSigner;
#[cfg(feature = "vault-transit")]
pub use kms::vault::VaultTransitSigner;
#[cfg(feature = "pkcs11")]
pub use pkcs11::Pkcs11Signer;

// OIDC identity-token providers — see `sign/src/oidc/mod.rs` for the
// full taxonomy (Static / GitHubActions / GcpMetadata /
// InteractiveBrowser). All four impl the same `OidcProvider` trait
// and produce a JWT string the caller hands to Fulcio.
#[cfg(feature = "oidc-browser")]
pub use oidc::InteractiveBrowserOidcProvider;
#[cfg(feature = "oidc")]
pub use oidc::{
    GcpMetadataOidcProvider, GitHubActionsOidcProvider, OidcError, OidcProvider, StaticOidcProvider,
};

pub use slsa::{
    sign_slsa_provenance, verify_slsa_provenance, VerifiedSlsaProvenance,
    SLSA_PROVENANCE_V1_PREDICATE_TYPE,
};
pub use spec::{CYCLONEDX_BOM_V1_5_PREDICATE_TYPE, SPDX_DOCUMENT_V2_3_PREDICATE_TYPE};

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::Signature as P256Signature;

use rekor::{DsseRekord, HashedRekord, HashedRekordHash, LogEntry, PublicKey, RekorClient};
use sha2::{Digest, Sha256};
use spec::{
    Bundle, BundleContent, Certificate as SpecCertificate, Checkpoint, Envelope, HashOutput,
    InclusionProof, KindVersion, Signature as DsseSignature, Statement, Subject, TlogEntry,
    VerificationMaterial, IN_TOTO_STATEMENT_V1_TYPE, SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE,
};
use std::collections::BTreeMap;

/// DSSE `payload_type` value carried by every in-toto attestation
/// bundle. The Sigstore bundle spec, the in-toto Statement v1 spec,
/// and cosign all pin this exact string — verifiers route on it to
/// distinguish "this DSSE wraps an attestation Statement" from
/// "this DSSE wraps an arbitrary blob".
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Algorithm-tagged verifying key passed to [`verify_blob`] (and
/// every higher-level verifier that composes on top of it).
///
/// Each variant wraps the per-algorithm verifying key from the
/// matching RustCrypto crate and is gated behind the same feature
/// flag that pulls that crate in. The default build only surfaces
/// the [`VerifyingKey::P256`] variant — adding `ed25519`,
/// `ecdsa-p384`, or `secp256k1` to the feature list lights up the
/// other variants.
///
/// # Why an enum and not a trait object
///
/// The variants disagree on signature wire shape:
///
/// * P-256 / P-384 / secp256k1 — DER-encoded ECDSA, parsed via
///   `Signature::from_der`.
/// * Ed25519 — raw 64-byte concatenation of `r || s`, parsed via
///   `Signature::from_bytes`.
///
/// A trait object hiding both behind one `verify(&[u8], &[u8])`
/// would force every caller to pre-encode the signature into one
/// universal shape, which doesn't exist. The enum lets
/// [`verify_blob`]'s match arm reach for the right parser per
/// variant.
///
/// # Why this is a v0 BREAKING change
///
/// `verify_blob`'s `trusted_keys` parameter previously took
/// `&[p256::ecdsa::VerifyingKey]`. v0.2 takes `&[VerifyingKey]` of
/// this enum — every caller MUST wrap their key in the matching
/// variant (e.g. `VerifyingKey::P256(vk)`). The breakage is
/// localised; the v0 surface is small enough that updating
/// callers in-tree is cheaper than carrying both APIs forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyingKey {
    /// ECDSA over NIST P-256, DER-encoded signatures, SHA-256
    /// digest. The default-on variant — present in every build.
    P256(p256::ecdsa::VerifyingKey),

    /// Ed25519 PureEd25519 (RFC 8032), raw 64-byte signatures.
    /// Gated on the `ed25519` feature.
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519_dalek::VerifyingKey),

    /// ECDSA over NIST P-384, DER-encoded signatures, SHA-384
    /// digest. Gated on the `ecdsa-p384` feature.
    #[cfg(feature = "ecdsa-p384")]
    P384(p384::ecdsa::VerifyingKey),

    /// ECDSA over secp256k1 (Bitcoin / Ethereum curve), DER-encoded
    /// signatures, SHA-256 digest. Gated on the `secp256k1` feature.
    #[cfg(feature = "secp256k1")]
    K256(k256::ecdsa::VerifyingKey),
}

impl From<p256::ecdsa::VerifyingKey> for VerifyingKey {
    /// `From` lift so existing P-256 callers can still write
    /// `&[vk.into()]` instead of explicitly typing
    /// `VerifyingKey::P256(vk)`. Kept narrow on purpose — we do
    /// NOT provide a `From<&[u8]>` because the byte shape is
    /// algorithm-specific and that would re-introduce the exact
    /// dispatch ambiguity the enum exists to remove.
    fn from(vk: p256::ecdsa::VerifyingKey) -> Self {
        VerifyingKey::P256(vk)
    }
}

#[cfg(feature = "ed25519")]
impl From<ed25519_dalek::VerifyingKey> for VerifyingKey {
    fn from(vk: ed25519_dalek::VerifyingKey) -> Self {
        VerifyingKey::Ed25519(vk)
    }
}

#[cfg(feature = "ecdsa-p384")]
impl From<p384::ecdsa::VerifyingKey> for VerifyingKey {
    fn from(vk: p384::ecdsa::VerifyingKey) -> Self {
        VerifyingKey::P384(vk)
    }
}

#[cfg(feature = "secp256k1")]
impl From<k256::ecdsa::VerifyingKey> for VerifyingKey {
    fn from(vk: k256::ecdsa::VerifyingKey) -> Self {
        VerifyingKey::K256(vk)
    }
}

/// Try to verify `pae_bytes` under `key` against the algorithm-
/// specific signature shape carried in `sig_bytes`. Returns `true`
/// iff the parse + verify both succeed.
///
/// Held as an internal helper so [`verify_blob`]'s outer loop stays
/// readable: it iterates `(envelope.signatures × trusted_keys)` and
/// shorts on the first hit. The per-algorithm sig-shape parsing
/// lives here, in one place.
///
/// Bug it pre-empts: a verifier that handed an Ed25519
/// signature's 64 bytes to `P256Signature::from_der` would always
/// fail on shape (raw bytes aren't valid DER), but a verifier that
/// handed a DER ECDSA signature to `Ed25519Signature::from_bytes`
/// would either fail on length (DER ECDSA-P256 sigs are typically
/// 70-72 bytes, not 64) — meaning a regression where the enum
/// dispatch matched the WRONG arm would silently reject every
/// signature. The cross-algorithm rejection tests below catch
/// exactly this regression.
fn try_verify(key: &VerifyingKey, pae_bytes: &[u8], sig_bytes: &[u8]) -> bool {
    match key {
        VerifyingKey::P256(vk) => match P256Signature::from_der(sig_bytes) {
            Ok(sig) => vk.verify(pae_bytes, &sig).is_ok(),
            Err(_) => false,
        },
        #[cfg(feature = "ed25519")]
        VerifyingKey::Ed25519(vk) => {
            // Ed25519 sigs are exactly 64 bytes; `from_slice`
            // returns an error on any other length. We do NOT
            // accept DER here — RFC 8032 has no DER form.
            use ed25519_dalek::Verifier as _;
            match ed25519_dalek::Signature::from_slice(sig_bytes) {
                Ok(sig) => vk.verify(pae_bytes, &sig).is_ok(),
                Err(_) => false,
            }
        }
        #[cfg(feature = "ecdsa-p384")]
        VerifyingKey::P384(vk) => {
            use p384::ecdsa::signature::Verifier as _;
            match p384::ecdsa::Signature::from_der(sig_bytes) {
                Ok(sig) => vk.verify(pae_bytes, &sig).is_ok(),
                Err(_) => false,
            }
        }
        #[cfg(feature = "secp256k1")]
        VerifyingKey::K256(vk) => {
            use k256::ecdsa::signature::Verifier as _;
            match k256::ecdsa::Signature::from_der(sig_bytes) {
                Ok(sig) => vk.verify(pae_bytes, &sig).is_ok(),
                Err(_) => false,
            }
        }
    }
}

/// Sign `payload` with the given [`Signer`] and return a
/// [`spec::Bundle`].
///
/// Steps:
///
/// 1. Build a DSSE envelope with the supplied `payload_type` and
///    `payload`. Compute its PAE via [`spec::pae`].
/// 2. Hand the PAE to the signer; attach the returned signature
///    bytes (and the signer's `key_id`, if any) to the envelope.
/// 3. If `rekor` is `Some`, build a `hashedrekord` body whose
///    `data.hash.value` is `SHA-256(payload)` and submit it. Embed
///    the resulting [`rekor::LogEntry`] in the bundle's
///    `tlog_entries` so verifiers can re-check the inclusion proof.
/// 4. Wrap the envelope + verification material into a
///    [`spec::Bundle`] tagged `media_type =
///    application/vnd.dev.sigstore.bundle+json;version=0.3`.
///
/// Errors surface via [`SignError`].
pub fn sign_blob(
    payload: &[u8],
    payload_type: &str,
    signer: &dyn Signer,
    rekor: Option<&dyn RekorClient>,
) -> Result<Bundle, SignError> {
    // 1. DSSE envelope + PAE bytes.
    let pae_bytes = spec::pae(payload_type.as_bytes(), payload);

    // 2. Sign the PAE.
    let sig_bytes = signer
        .sign(&pae_bytes)
        .map_err(|e| SignError::Signer(e.to_string()))?;
    let key_id = signer.key_id();

    let envelope = Envelope {
        payload_type: payload_type.to_string(),
        payload: payload.to_vec(),
        signatures: vec![DsseSignature {
            keyid: key_id.clone(),
            sig: sig_bytes.clone(),
        }],
    };

    // 3. Optional Rekor submission. v0 sign_blob has no Fulcio
    //    cert in scope, so the rekor entry's publicKey is empty;
    //    real Rekor rejects this. Static-key flows that need
    //    transparency should use a MockRekorClient or move to a
    //    real-pubkey-binding API in v0.5. The keyless flow
    //    (sign_blob_keyless) drives the cert-PEM-bearing path.
    let tlog_entries = if let Some(client) = rekor {
        let entry = build_hashed_rekord(payload, &sig_bytes, Vec::new());
        let log_entry = client.submit(&entry)?;
        vec![log_entry_to_tlog_entry(&log_entry, "hashedrekord")]
    } else {
        Vec::new()
    };

    // 4. Bundle.
    Ok(Bundle {
        media_type: SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE.to_string(),
        verification_material: VerificationMaterial {
            // Cert chain is a v0.5 concern (Fulcio keyless).
            certificate: None,
            tlog_entries,
            timestamp_verification_data: None,
        },
        content: BundleContent::DsseEnvelope(envelope),
    })
}

/// Sign `payload` with the given [`Signer`] and emit a keyless
/// [`spec::Bundle`] carrying the supplied Fulcio-issued cert chain.
///
/// This is the producer counterpart of [`verify_blob_keyless`]: that
/// verifier expects the bundle's `verification_material.certificate`
/// to contain the chain whose leaf carries the public part of the
/// key the DSSE signature was produced with. [`sign_blob`] hardcodes
/// that field to `None` (cert chains are a "v0.5 concern" there);
/// `sign_blob_keyless` closes the loop so a Fulcio-keyed signer can
/// emit a bundle the keyless verifier accepts end-to-end.
///
/// Inputs:
///
/// * `payload` / `payload_type` / `signer` / `rekor` — same shape and
///   meaning as [`sign_blob`]. The DSSE + PAE + Rekor flow is
///   identical; only the cert-chain attachment is new.
/// * `cert_chain_der` — DER-encoded cert chain, **leaf at index 0**,
///   intermediates following. Same shape as the input
///   [`verify_blob_keyless`] reads out of the bundle. The function
///   does NOT cryptographically validate that the leaf's
///   SubjectPublicKeyInfo matches the signer's verifying key — that
///   coupling is the caller's responsibility (typically: the caller
///   generated the keypair, requested a Fulcio cert for it, and
///   passes both into this call). Surfacing a "leaf-vs-key drift"
///   error would require a parser this crate doesn't currently host
///   for v0.
///
/// Errors:
///
/// * [`SignError::EmptyCertChain`] — `cert_chain_der.is_empty()`.
///   Rejected upfront so we never emit a bundle whose
///   `certificate.certificates` is an empty `Vec` — that bundle
///   would be structurally valid wire-wise but the keyless verifier
///   would reject it as [`VerifyError::EmptyCertChain`] anyway.
///   Mirroring the verifier's typed surface here means producer +
///   verifier agree on one error name for one failure mode.
/// * [`SignError::Signer`] / [`SignError::RekorSubmit`] /
///   [`SignError::BundleEncode`] — inherited from [`sign_blob`]; same
///   construction sites, same meanings.
pub fn sign_blob_keyless(
    payload: &[u8],
    payload_type: &str,
    signer: &dyn Signer,
    cert_chain_der: &[Vec<u8>],
    rekor: Option<&dyn RekorClient>,
) -> Result<Bundle, SignError> {
    // 1. Reject empty chains BEFORE doing any signing work — no point
    //    consuming a Rekor submission slot for a bundle we're going
    //    to fail to assemble. Mirrors `verify_blob_keyless`'s
    //    `EmptyCertChain` exit on the consumer side so the
    //    producer/verifier loop reports the same failure name on the
    //    same condition.
    if cert_chain_der.is_empty() {
        return Err(SignError::EmptyCertChain);
    }

    // 2. PAE + sign. Same flow as sign_blob; inlined here so the
    //    keyless rekor submission can dispatch to the dsse schema
    //    (DSSE-content bundles ALWAYS need the dsse rekor schema —
    //    submitting them via hashedrekord makes production Rekor
    //    reject the entry with `invalid signature when validating
    //    ASN.1 encoded signature` because hashedrekord verifies
    //    signature against `SHA-256(payload)` while DSSE signs the
    //    PAE bytes; see issue #39).
    let pae_bytes = spec::pae(payload_type.as_bytes(), payload);
    let sig_bytes = signer
        .sign(&pae_bytes)
        .map_err(|e| SignError::Signer(e.to_string()))?;
    let key_id = signer.key_id();
    let envelope = Envelope {
        payload_type: payload_type.to_string(),
        payload: payload.to_vec(),
        signatures: vec![DsseSignature {
            keyid: key_id.clone(),
            sig: sig_bytes.clone(),
        }],
    };

    // 3. Optional Rekor submission via the `dsse` schema. The leaf
    //    cert (DER, index 0 of the chain) becomes the entry's sole
    //    `verifier` — Rekor PEM-wraps it on receipt and verifies
    //    each envelope signature against the recomputed PAE.
    let tlog_entries = if let Some(client) = rekor {
        let entry = build_dsse_rekord(&envelope, &cert_chain_der[0])?;
        let log_entry = client.submit_dsse(&entry)?;
        vec![log_entry_to_tlog_entry(&log_entry, "dsse")]
    } else {
        Vec::new()
    };

    // 5. Bundle with the cert chain attached.
    Ok(Bundle {
        media_type: SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE.to_string(),
        verification_material: VerificationMaterial {
            certificate: Some(SpecCertificate {
                certificates: cert_chain_der.to_vec(),
            }),
            tlog_entries,
            timestamp_verification_data: None,
        },
        content: BundleContent::DsseEnvelope(envelope),
    })
}

/// Verify a [`spec::Bundle`] previously produced by [`sign_blob`]
/// (or a third-party Sigstore signer with the same wire shape).
///
/// Inputs:
///
/// * `bundle` — the artifact to verify.
/// * `trusted_keys` — list of P-256 verifying keys the caller
///   accepts. v0 uses raw key material; v0.5 will derive these
///   from a Fulcio-validated cert chain. At least ONE key must
///   validate at least ONE of the envelope's signatures.
/// * `rekor` — optional [`rekor::RekorClient`]; when present,
///   every `tlog_entry` in the bundle has its inclusion proof
///   re-verified.
///
/// Returns `Ok(())` on success; otherwise a [`VerifyError`]
/// pinpointing what failed.
pub fn verify_blob(
    bundle: &Bundle,
    trusted_keys: &[VerifyingKey],
    rekor: Option<&dyn RekorClient>,
) -> Result<(), VerifyError> {
    // 1. Pull the DSSE envelope; reject the message-signature arm.
    let envelope = match &bundle.content {
        BundleContent::DsseEnvelope(env) => env,
        BundleContent::MessageSignature(_) => return Err(VerifyError::EnvelopeMissing),
    };

    // 2. Re-derive PAE bytes and verify signatures.
    let pae_bytes = envelope.pae();

    // The DSSE spec permits multiple signatures per envelope; v0
    // policy is "at least one signature must validate against a
    // trusted key". A signature whose `keyid` doesn't match any
    // key still gets tried against every key — DSSE keyids are
    // hints, not auth bindings, and a verifier holding the right
    // key still verifies even if the keyid was wrong.
    //
    // Algorithm dispatch: each `(sig, key)` pair routes through
    // [`try_verify`], which picks the right sig-shape parser per
    // `VerifyingKey` variant. A signature whose bytes don't parse
    // as ANY trusted key's algorithm shape is treated the same as
    // a parse-but-doesn't-verify outcome — both surface as
    // `SignatureInvalid` with `keyid` echoing the last failing
    // entry.
    let mut last_failing_keyid: Option<String> = None;
    let mut any_valid = false;
    'outer: for sig in &envelope.signatures {
        for key in trusted_keys {
            if try_verify(key, &pae_bytes, &sig.sig) {
                any_valid = true;
                break 'outer;
            }
        }
        last_failing_keyid = sig.keyid.clone();
    }

    if !any_valid {
        return Err(VerifyError::SignatureInvalid {
            keyid: last_failing_keyid,
        });
    }

    // 3. Optional Rekor inclusion-proof check.
    if let Some(client) = rekor {
        // Caller asked for transparency. If the bundle has no
        // tlog entries we surface NoTlogEntry — silently
        // succeeding here would let an unwitnessed bundle pass a
        // transparency-required policy check.
        if bundle.verification_material.tlog_entries.is_empty() {
            return Err(VerifyError::NoTlogEntry);
        }

        // The `client` parameter is unused for v0 verification —
        // the inclusion proof IS in the bundle (RFC 6962 paths +
        // the root the proof terminates at). We re-run the
        // verifier against the bundle's own root. Online
        // freshness checks ("is this still the published root?")
        // are a v0.5 concern; the SPI accepts the client today
        // so the API doesn't break when we wire that in.
        let _ = client;
        for tlog in &bundle.verification_material.tlog_entries {
            verify_tlog_entry(tlog)?;
        }
    }

    Ok(())
}

/// Re-run the RFC 6962 inclusion-proof check on a single
/// `TlogEntry` from a [`spec::Bundle`]. The proof is verified
/// against the bundle's own root — same as
/// `LogEntry::verify_self_consistent` in the rekor crate.
fn verify_tlog_entry(tlog: &TlogEntry) -> Result<(), VerifyError> {
    let proof = tlog
        .inclusion_proof
        .as_ref()
        .ok_or(VerifyError::NoTlogEntry)?;

    // The bundle's wire shape carries `i64`; the rekor verifier
    // wants `u64`. Negative values would be a malformed bundle;
    // surface them as a typed proof error.
    let log_index: u64 = u64::try_from(proof.log_index).map_err(|_| {
        VerifyError::RekorVerify(rekor::RekorError::IndexOutOfRange {
            index: 0,
            tree_size: 0,
        })
    })?;
    let tree_size: u64 = u64::try_from(proof.tree_size).map_err(|_| {
        VerifyError::RekorVerify(rekor::RekorError::IndexOutOfRange {
            index: 0,
            tree_size: 0,
        })
    })?;

    // Convert the `Vec<Vec<u8>>` proof hashes to `[u8; 32]`. A
    // hash that isn't 32 bytes is a malformed proof.
    let mut path: Vec<[u8; 32]> = Vec::with_capacity(proof.hashes.len());
    for h in &proof.hashes {
        let arr: [u8; 32] = h.as_slice().try_into().map_err(|_| {
            VerifyError::RekorVerify(rekor::RekorError::PathLengthMismatch {
                expected: 0,
                got: h.len(),
            })
        })?;
        path.push(arr);
    }

    let root: [u8; 32] = proof.root_hash.as_slice().try_into().map_err(|_| {
        VerifyError::RekorVerify(rekor::RekorError::PathLengthMismatch {
            expected: 32,
            got: proof.root_hash.len(),
        })
    })?;

    // The bundle does NOT carry the leaf hash directly — it's
    // implied by the canonicalised entry body. For v0 (single-
    // leaf log) the root IS the leaf hash, so we reuse the root
    // as the leaf input. Multi-leaf logs land alongside the real
    // HTTP client when we have a body to canonicalise.
    let leaf = root;

    rekor::verify_inclusion(&leaf, log_index, tree_size, &path, &root)?;
    Ok(())
}

/// Build the `hashedrekord` body for a (payload, signature) pair.
///
/// Rekor never sees the raw payload — only its SHA-256 digest.
///
/// `pubkey_pem_for_rekor` carries the public key Rekor pins to the
/// entry. It's encoded as PEM bytes (Rekor base64s the value on its
/// side at the JSON wire). Empty bytes mean "no public key" — used
/// only by callers driving `sign_blob` in a static-key flow with a
/// MockRekorClient (real Rekor rejects empty pubkeys with
/// `invalid public key: failure decoding PEM`). The keyless flow
/// (`sign_blob_keyless`) populates this with the leaf cert PEM.
fn build_hashed_rekord(
    payload: &[u8],
    sig_bytes: &[u8],
    pubkey_pem_for_rekor: Vec<u8>,
) -> HashedRekord {
    let digest = Sha256::digest(payload);
    HashedRekord {
        signature: rekor::Signature {
            content: sig_bytes.to_vec(),
            public_key: PublicKey {
                content: pubkey_pem_for_rekor,
            },
        },
        data: rekor::Data {
            hash: HashedRekordHash {
                algorithm: "sha256".to_string(),
                value: hex_lower(&digest),
            },
        },
    }
}

/// Build the `dsse` rekor entry for a DSSE envelope + leaf cert.
///
/// Used by [`sign_blob_keyless`] (DSSE-content bundles always need
/// the dsse schema; submitting them via hashedrekord makes
/// production Rekor reject the entry with `invalid signature when
/// validating ASN.1 encoded signature` because hashedrekord
/// verifies `signature == ECDSA(SHA-256(payload))` while DSSE signs
/// the PAE bytes — see issue #39).
///
/// `leaf_der` is the DER-encoded leaf certificate; we PEM-wrap it
/// here because the dsse schema's `verifiers` field expects PEM
/// bytes (base64-encoded on the wire by the rekor crate). The
/// entry that gets logged is `(envelope-as-string, [base64(PEM(leaf))])`.
fn build_dsse_rekord(envelope: &Envelope, leaf_der: &[u8]) -> Result<DsseRekord, SignError> {
    let envelope_bytes = envelope.encode_json()?;
    let leaf_pem = pem::encode(&pem::Pem::new("CERTIFICATE", leaf_der.to_vec()));
    Ok(DsseRekord {
        envelope_bytes,
        verifiers_pem: vec![leaf_pem.into_bytes()],
    })
}

/// Translate a `rekor::LogEntry` into the [`spec::TlogEntry`] wire
/// shape the bundle carries.
///
/// `kind` is the rekor schema name (`"hashedrekord"` for
/// MessageSignature-content bundles, `"dsse"` for DSSE-content
/// bundles). Verifiers gate on this field — a tlog entry tagged
/// with the wrong kind would be re-checked under the wrong
/// signature-verification model and silently fail. See issue #39.
///
/// Type-width drift: the rekor crate uses `u64` for indices /
/// tree sizes; the spec crate uses `i64` (matching the protobuf
/// wire shape). Casting through `as i64` is safe for any value
/// returned by the v0 mock (single-leaf log, log_index = 0,
/// tree_size = 1).
fn log_entry_to_tlog_entry(entry: &LogEntry, kind: &str) -> TlogEntry {
    TlogEntry {
        log_index: entry.log_index as i64,
        log_id: HashOutput {
            algorithm: "SHA2_256".to_string(),
            // Mock has no log_id of its own; use the leaf hash
            // as a stable identifier so the field round-trips.
            digest: entry.leaf_hash.to_vec(),
        },
        kind_version: KindVersion {
            kind: kind.to_string(),
            version: "0.0.1".to_string(),
        },
        // The mock has no integration timestamp; v0.5 will populate
        // this from the real Rekor response. Zero is a valid
        // sentinel — verifiers don't gate on it in v0.
        integrated_time: 0,
        // No SET in v0 — the mock doesn't sign, and the real
        // server's promise is wired in v0.5.
        inclusion_promise: None,
        inclusion_proof: Some(InclusionProof {
            log_index: entry.log_index as i64,
            root_hash: entry.root_hash.to_vec(),
            tree_size: entry.tree_size as i64,
            hashes: entry.inclusion_proof.iter().map(|h| h.to_vec()).collect(),
            // Empty checkpoint envelope — the real signed
            // checkpoint comes from the v0.5 HTTP client. Holding
            // an empty placeholder keeps the wire shape valid.
            checkpoint: Checkpoint {
                envelope: String::new(),
            },
        }),
    }
}

/// Hex-encode a byte slice as lowercase ASCII. Used for
/// `hashedrekord.data.hash.value`, which Rekor's schema requires
/// in lowercase hex form.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Result of [`verify_attestation`] — the load-bearing pieces of a
/// successfully-verified in-toto Statement.
///
/// Returned (instead of just `Ok(())`) so callers don't have to
/// re-decode the DSSE payload to act on the predicate. Cosign's
/// `cosign verify-attestation` follows the same shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// Subjects the Statement makes claims about. Order is preserved
    /// from the wire form — predicate types like SLSA Provenance can
    /// reference subjects by index.
    pub subjects: Vec<Subject>,

    /// `predicateType` URI from the verified Statement. Verifiers
    /// usually already know this (they just supplied
    /// `expected_predicate_type`) but returning it here keeps the
    /// caller's error-path code simple — they can log or echo it
    /// without reparsing.
    pub predicate_type: String,

    /// Predicate body. Opaque per this crate; per-predicate-type
    /// crates (SLSA Provenance, SPDX, custom) parse it.
    pub predicate: serde_json::Value,
}

/// Build an in-toto Statement v1 about `(subject_name,
/// subject_digest_algo, subject_digest_hex)` with the given
/// `predicate_type` + `predicate`, wrap it in a DSSE envelope tagged
/// `application/vnd.in-toto+json`, sign with `signer`, and return
/// the resulting [`spec::Bundle`].
///
/// This is the attestation analogue of [`sign_blob`]. It exists so
/// callers don't have to hand-roll the Statement → JSON → DSSE →
/// Bundle wrapping; they hand in the semantic pieces (what is the
/// subject, what predicate are you asserting) and get back a
/// verifiable bundle.
///
/// Single-subject by design: 99% of attestations name exactly one
/// subject. Multi-subject attestations (multi-arch manifest lists,
/// SBOMs covering several artifacts) can build the `Statement`
/// directly and call [`sign_blob`] with `IN_TOTO_PAYLOAD_TYPE`.
///
/// Errors surface via [`SignError`] — `StatementEncode` for
/// Statement-JSON failures, the same variants as `sign_blob`
/// otherwise.
pub fn attest(
    subject_name: &str,
    subject_digest_algo: &str,
    subject_digest_hex: &str,
    predicate_type: &str,
    predicate: serde_json::Value,
    signer: &dyn Signer,
    rekor: Option<&dyn RekorClient>,
) -> Result<Bundle, SignError> {
    let mut digest = BTreeMap::new();
    digest.insert(
        subject_digest_algo.to_string(),
        subject_digest_hex.to_string(),
    );
    let stmt = Statement {
        _type: IN_TOTO_STATEMENT_V1_TYPE.to_string(),
        subject: vec![Subject {
            name: subject_name.to_string(),
            digest,
        }],
        predicate_type: predicate_type.to_string(),
        predicate,
    };
    // `?` lifts `StatementEncodeError` via the `From` impl on
    // `SignError`. A failure here means the predicate Value was
    // un-serialisable — extremely rare in practice, but typed.
    let payload = stmt.encode_json()?;
    sign_blob(&payload, IN_TOTO_PAYLOAD_TYPE, signer, rekor)
}

/// Verify a [`spec::Bundle`] previously produced by [`attest`] (or
/// any Sigstore signer that follows the same wire shape).
///
/// Steps, in order:
///
/// 1. Run [`verify_blob`] — establishes the DSSE signature is valid
///    against `trusted_keys` and (if `rekor` is `Some`) that every
///    embedded `tlog_entry`'s inclusion proof verifies.
/// 2. Reject if the envelope's `payload_type` isn't
///    [`IN_TOTO_PAYLOAD_TYPE`] — the bundle has a valid signature
///    but it's NOT an attestation; it's some other DSSE payload.
/// 3. Decode the envelope's `payload` as an in-toto Statement v1
///    (the spec crate enforces `_type` matches).
/// 4. Reject if `expected_predicate_type` doesn't match the
///    Statement's `predicateType`.
/// 5. If `expected_subject_digest = Some((algo, hex))`, scan every
///    subject in the Statement for a `digest` entry mapping
///    `algo → hex`. Accept if ANY subject matches. This mirrors
///    cosign's "match any subject" rule: an attestation that names
///    multiple artifacts is still valid for the artifact you care
///    about as long as that artifact appears once.
///
/// `expected_subject_digest = None` skips step 5 — useful when the
/// caller is enumerating subjects (e.g. listing every artifact
/// covered by an SBOM) instead of pinning one.
///
/// v0 takes raw `VerifyingKey`s. Keyless verification (Fulcio cert
/// chain → ephemeral key) composes one layer up: derive the keys
/// from the chain, then call this function.
pub fn verify_attestation(
    bundle: &Bundle,
    trusted_keys: &[VerifyingKey],
    expected_predicate_type: &str,
    expected_subject_digest: Option<(&str, &str)>,
    rekor: Option<&dyn RekorClient>,
) -> Result<VerifiedAttestation, VerifyError> {
    // 1. Signature + (optional) tlog inclusion. Fail fast — no
    //    point decoding the payload of a bundle whose signature
    //    didn't validate.
    verify_blob(bundle, trusted_keys, rekor)?;

    // 2. Pull the DSSE envelope. `verify_blob` already rejected the
    //    `MessageSignature` arm, so this match is total in practice
    //    — but we re-check to keep the borrow local and the error
    //    path explicit.
    let envelope = match &bundle.content {
        BundleContent::DsseEnvelope(env) => env,
        BundleContent::MessageSignature(_) => return Err(VerifyError::EnvelopeMissing),
    };

    if envelope.payload_type != IN_TOTO_PAYLOAD_TYPE {
        return Err(VerifyError::WrongPayloadType {
            expected: IN_TOTO_PAYLOAD_TYPE.to_string(),
            found: envelope.payload_type.clone(),
        });
    }

    // 3. Decode the in-toto Statement. `?` lifts
    //    `StatementDecodeError` via `From`.
    let statement = Statement::decode_json(&envelope.payload)?;

    // 4. Predicate-type gate. Done as a string compare — predicate
    //    types are URIs, so case + trailing slashes matter. We
    //    don't normalise; cosign doesn't either.
    if statement.predicate_type != expected_predicate_type {
        return Err(VerifyError::WrongPredicateType {
            expected: expected_predicate_type.to_string(),
            found: statement.predicate_type,
        });
    }

    // 5. Subject-digest gate (optional). Cosign-style "match any
    //    subject" semantics: accept if ANY subject in the Statement
    //    carries a `digest[algo] == hex` entry. A multi-subject
    //    attestation covering [A, B, C] is still valid for B.
    if let Some((algo, hex)) = expected_subject_digest {
        let any_match = statement
            .subject
            .iter()
            .any(|s| s.digest.get(algo).map(String::as_str) == Some(hex));
        if !any_match {
            return Err(VerifyError::SubjectMismatch {
                expected_digest: format!("{algo}:{hex}"),
            });
        }
    }

    Ok(VerifiedAttestation {
        subjects: statement.subject,
        predicate_type: statement.predicate_type,
        predicate: statement.predicate,
    })
}

// ---------------------------------------------------------------
// OCI artifact signing — issue #6
// ---------------------------------------------------------------

/// Outputs of [`sign_oci`].
///
/// The caller pushes `bundle_bytes` as a blob and
/// `referrer_manifest` as a manifest at the registry. The
/// digests are returned alongside so the caller doesn't re-hash
/// to address either resource.
#[derive(Debug, Clone)]
pub struct OciSignArtifacts {
    /// The DSSE-wrapped Sigstore bundle, in-memory.
    pub bundle: Bundle,
    /// `bundle.encode_json()` — exactly what the layer blob carries.
    pub bundle_bytes: Vec<u8>,
    /// `sha256:<hex>` of `bundle_bytes`. Matches `layers[0].digest`.
    pub bundle_digest: String,
    /// The OCI 1.1 referrer manifest JSON.
    pub referrer_manifest: Vec<u8>,
    /// `sha256:<hex>` of `referrer_manifest`.
    pub referrer_manifest_digest: String,
    /// Manifest media type — always
    /// `application/vnd.oci.image.manifest.v1+json` in v0.
    pub referrer_manifest_media_type: String,
}

/// Outputs of [`verify_oci`].
///
/// Returns the subject descriptor extracted from the manifest so
/// the caller can route policy on it ("does this match the
/// artifact I just pulled?").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOci {
    pub subject_digest: String,
    pub subject_media_type: String,
    pub subject_size: u64,
}

/// Sign an OCI artifact identified by its manifest digest +
/// media type + size.
///
/// PAE-payload contract: the bytes signed are the subject
/// digest as a UTF-8 string (e.g. `sha256:abc...`). This matches
/// what cosign emits for container-image signatures and is the
/// caller-friendly contract: the verifier doesn't need the
/// artifact bytes, only its digest.
///
/// Logic:
///
/// 1. Hand `subject_digest`'s UTF-8 bytes to [`sign_blob`] with
///    payload type `text/plain`. This produces a Sigstore bundle.
/// 2. Encode the bundle to JSON and hash it — the layer blob.
/// 3. Build the OCI 1.1 referrer manifest pointing at
///    `subject_digest` and carrying the bundle layer.
/// 4. Hash the manifest bytes for the caller to address it.
pub fn sign_oci(
    subject_digest: &str,
    subject_media_type: &str,
    subject_size: u64,
    signer: &dyn Signer,
    rekor: Option<&dyn RekorClient>,
) -> Result<OciSignArtifacts, SignError> {
    // 1. Sign the digest string. cosign also signs the digest
    //    string (not the artifact bytes) — that's what makes OCI
    //    signing work for arbitrarily large images.
    let bundle = sign_blob(subject_digest.as_bytes(), "text/plain", signer, rekor)?;

    // 2. Serialise the bundle once — both for the layer blob
    //    digest AND the artifacts the caller pushes. Encoding
    //    twice would risk byte-level drift if `Bundle::encode_json`
    //    becomes non-deterministic.
    let bundle_bytes = bundle.encode_json()?;
    let bundle_digest = oci::sha256_digest_string(&bundle_bytes);
    let bundle_size = bundle_bytes.len() as u64;

    // 3. Wrap the bundle in an OCI 1.1 referrer manifest.
    //    `build_referrer_manifest_for_bundle_bytes` skips the
    //    re-encode of the bundle — we already have the digest.
    let (referrer_manifest, referrer_manifest_media_type) =
        oci::build_referrer_manifest_for_bundle_bytes(
            &bundle_digest,
            bundle_size,
            subject_digest,
            subject_media_type,
            subject_size,
        )
        .map_err(SignError::Oci)?;

    let referrer_manifest_digest = oci::sha256_digest_string(&referrer_manifest);

    Ok(OciSignArtifacts {
        bundle,
        bundle_bytes,
        bundle_digest,
        referrer_manifest,
        referrer_manifest_digest,
        referrer_manifest_media_type,
    })
}

/// Verify an OCI 1.1 referrer manifest produced by [`sign_oci`].
///
/// Inputs:
///
/// * `referrer_manifest` — manifest bytes (caller fetched from
///   the registry).
/// * `bundle` — the bundle blob the manifest's `layers[0]` points
///   at (caller fetched the layer blob, decoded it via
///   [`spec::Bundle::decode_json`]).
/// * `trusted_keys` — same shape as [`verify_blob`].
/// * `rekor` — same shape as [`verify_blob`].
///
/// Steps:
///
/// 1. Parse the manifest, validating shape (schemaVersion,
///    artifactType, layer count).
/// 2. Re-encode the bundle, hash it, and check the manifest's
///    layer digest matches.
/// 3. Run [`verify_blob`] over the bundle.
/// 4. Cross-check: the bundle's signed payload is the subject
///    digest string. The verifier confirms this matches the
///    manifest's `subject.digest`. Any drift means the manifest
///    was repointed at a different artifact than the one the
///    bundle signed over.
///
/// Returns a [`VerifiedOci`] carrying the subject the verifier
/// SHOULD then validate against the artifact it actually pulled.
pub fn verify_oci(
    referrer_manifest: &[u8],
    bundle: &Bundle,
    trusted_keys: &[VerifyingKey],
    rekor: Option<&dyn RekorClient>,
) -> Result<VerifiedOci, VerifyError> {
    // 1. Parse + shape-validate the manifest.
    let parsed = oci::parse_referrer_manifest(referrer_manifest).map_err(VerifyError::Oci)?;

    // 2. Layer digest MUST match the bundle bytes the caller
    //    passed. We re-encode here — the caller may have decoded
    //    + re-encoded the bundle, but if `Bundle::encode_json`
    //    is deterministic the digest matches.
    let bundle_bytes = bundle.encode_json()?;
    let computed_digest = oci::sha256_digest_string(&bundle_bytes);
    if parsed.layer.digest != computed_digest {
        return Err(VerifyError::OciLayerMismatch {
            manifest_layer_digest: parsed.layer.digest,
            computed_bundle_digest: computed_digest,
        });
    }

    // 3. Cryptographic verification of the bundle.
    verify_blob(bundle, trusted_keys, rekor)?;

    // 4. Bundle's signed payload MUST equal the manifest subject
    //    digest. Otherwise the manifest could be re-pointed at a
    //    different artifact than the one this bundle attests to.
    if let BundleContent::DsseEnvelope(env) = &bundle.content {
        if env.payload != parsed.subject.digest.as_bytes() {
            return Err(VerifyError::OciLayerMismatch {
                manifest_layer_digest: parsed.subject.digest.clone(),
                computed_bundle_digest: String::from_utf8_lossy(&env.payload).to_string(),
            });
        }
    }
    // BundleContent::MessageSignature would have been rejected by
    // `verify_blob` already (EnvelopeMissing).

    Ok(VerifiedOci {
        subject_digest: parsed.subject.digest,
        subject_media_type: parsed.subject.media_type,
        subject_size: parsed.subject.size,
    })
}

// ───────────────────────────────────────────────────────────────────
// Keyless verification (issue #5). v0 takes the trust roots from the
// caller directly; v1 will drive them out of a TUF-validated trust
// bundle (see issues #3, #4). The function lives here rather than in
// `cert_chain.rs` because it composes the chain walk with the DSSE
// verify and SAN policy — three concerns the chain module deliberately
// does NOT know about.
// ───────────────────────────────────────────────────────────────────

/// Verify a Sigstore-keyless [`spec::Bundle`] against caller-supplied
/// trust anchors, using the system clock for cert validity checks.
///
/// Convenience wrapper around [`verify_blob_keyless_with_clock`] with
/// `clock = &SystemClock`. Production callers want this; tests and
/// air-gapped deploys that need a deterministic time source go
/// through the explicit-clock variant.
///
/// See [`verify_blob_keyless_with_clock`] for the full pipeline,
/// error surface, and rationale for each gate.
pub fn verify_blob_keyless(
    bundle: &Bundle,
    trust_anchors_der: &[Vec<u8>],
    expected_san: Option<&str>,
    rekor: Option<&dyn RekorClient>,
) -> Result<(), VerifyError> {
    verify_blob_keyless_with_clock(
        bundle,
        trust_anchors_der,
        expected_san,
        rekor,
        &spec::SystemClock,
    )
}

/// Verify a Sigstore-keyless [`spec::Bundle`] against caller-supplied
/// trust anchors, using a caller-supplied [`spec::Clock`] for cert
/// validity-window checks.
///
/// Pipeline:
///
/// 1. Pull `bundle.verification_material.certificate.certificates` —
///    a `Vec<Vec<u8>>` of DER-encoded certs, leaf at index 0. If it's
///    `None` or empty, fail with [`VerifyError::EmptyCertChain`].
/// 2. Hand the chain + `trust_anchors_der` to
///    [`cert_chain::verify_chain`]. The chain is accepted iff every
///    intra-chain signature verifies AND the topmost cert terminates
///    at a trust anchor (either the same DER, or signed by one).
///    On success this returns the leaf's `VerifyingKey`.
/// 3. **Validity window enforcement (issue #26).** Read each cert's
///    `notBefore` and `notAfter` and compare them against
///    `clock.now_unix_secs()`. Any cert with `now >= notAfter`
///    surfaces as [`VerifyError::CertExpired`]; any cert with
///    `now < notBefore` surfaces as [`VerifyError::CertNotYetValid`].
///    The check applies to EVERY cert in the chain — a chain whose
///    leaf is fresh but whose intermediate has expired must reject,
///    otherwise an attacker who held the chain's intermediate could
///    issue replays after the intermediate's stated lifetime.
/// 4. If `expected_san` is `Some`, extract SAN entries from the leaf
///    via [`cert_chain::extract_san`] and require an EXACT-string
///    match against one of them. v0 does not pattern-match.
/// 5. Dispatch the rest of verification to the existing [`verify_blob`]
///    logic, using the leaf's verifying key as the (single) trusted
///    key. This re-uses the DSSE-only / Rekor-optional posture from
///    the v0 verifier so we don't duplicate signature-shape logic.
///
/// # Errors
///
/// * [`VerifyError::EmptyCertChain`] — bundle has no cert chain.
/// * [`VerifyError::ChainBroken`] — chain walk rejected the chain.
/// * [`VerifyError::CertExpired`] — a cert's `notAfter` is at or
///   before `clock.now_unix_secs()`.
/// * [`VerifyError::CertNotYetValid`] — a cert's `notBefore` is
///   strictly after `clock.now_unix_secs()`.
/// * [`VerifyError::SanMismatch`] — `expected_san` not found in leaf.
/// * [`VerifyError::SignatureInvalid`] / [`VerifyError::EnvelopeMissing`] /
///   [`VerifyError::NoTlogEntry`] / [`VerifyError::RekorVerify`] —
///   inherited from [`verify_blob`].
///
/// # Open issues for v1
///
/// * SAN pattern matching (issuer-prefix matching, regex on URIs,
///   etc.) — v0 is exact-string only.
/// * SCT / Rekor inclusion-time-vs-cert-validity binding.
pub fn verify_blob_keyless_with_clock(
    bundle: &Bundle,
    trust_anchors_der: &[Vec<u8>],
    expected_san: Option<&str>,
    rekor: Option<&dyn RekorClient>,
    clock: &dyn spec::Clock,
) -> Result<(), VerifyError> {
    // 1. Pull the cert chain out of the bundle. The wire shape uses
    //    `Option<Certificate>` where `Certificate.certificates` is a
    //    `Vec<Vec<u8>>` — an Option that's `Some` but inner is empty
    //    is malformed but possible; treat it as the same failure as
    //    `None`.
    let chain_der: &[Vec<u8>] = match &bundle.verification_material.certificate {
        Some(cert) if !cert.certificates.is_empty() => &cert.certificates,
        _ => return Err(VerifyError::EmptyCertChain),
    };

    // 2. Walk the chain → leaf VerifyingKey. ChainError flows up via
    //    `From` impl on VerifyError::ChainBroken.
    let leaf_vk = cert_chain::verify_chain(chain_der, trust_anchors_der)?;

    // 3. Enforce notBefore/notAfter on EVERY cert in the chain. We
    //    compare ALL certs, not just the leaf, because Fulcio's
    //    intermediate has its own validity window (typically ~10
    //    years). An expired intermediate is a real failure mode that
    //    the cryptographic chain check would otherwise accept.
    //
    //    Order: we check the validity window AFTER the chain walk
    //    succeeds. A chain that doesn't cryptographically link is
    //    rejected for the stronger reason first; expiry is the
    //    second-line gate.
    let now = clock.now_unix_secs();
    for cert_der in chain_der {
        let (not_before, not_after) = cert_chain::cert_validity_window(cert_der)?;
        if now < not_before {
            return Err(VerifyError::CertNotYetValid { not_before });
        }
        if now >= not_after {
            return Err(VerifyError::CertExpired { not_after });
        }
    }

    // 4. SAN policy check. The leaf is at index 0 by Sigstore wire
    //    convention; `verify_chain` already validated that index
    //    decodes, so `extract_san` should only fail if the SAN
    //    extension itself is malformed (vanishingly rare for a cert
    //    that already verified, but typed surface is in place).
    if let Some(expected) = expected_san {
        let actual = cert_chain::extract_san(&chain_der[0])?;
        if !actual.iter().any(|entry| entry == expected) {
            return Err(VerifyError::SanMismatch {
                expected: expected.to_string(),
                actual,
            });
        }
    }

    // 5. Hand off to the existing v0 verifier, using the leaf's key
    //    as the single trusted key. `verify_blob` enforces:
    //      - DSSE envelope variant (not message-signature),
    //      - at least one envelope signature validates against the
    //        leaf's key,
    //      - if `rekor` is Some, every tlog entry's inclusion proof
    //        re-verifies against its claimed root.
    //
    //    The cert chain's leaf VK is always P-256 in v0 (Fulcio
    //    issues P-256 leaves); the wrap into `VerifyingKey::P256`
    //    is a typed lift, not a re-key. When Fulcio adds non-P-256
    //    leaf algorithms (issue tracked separately), this site
    //    grows a match — the chain walk would surface the leaf's
    //    algorithm via a typed `cert_chain::LeafKey` enum.
    verify_blob(bundle, &[VerifyingKey::P256(leaf_vk)], rekor)
}

#[cfg(test)]
mod keyless_tests {
    use super::*;
    use crate::cert_chain::ChainError;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
        SanType, PKCS_ECDSA_P256_SHA256,
    };
    use signature::Signer as _;
    use spec::{Certificate as SpecCertificate, FixedClock};

    /// Three-level synthetic chain bundled with the leaf's signing
    /// key, so the caller can sign a real bundle whose DSSE
    /// signature actually verifies under the cert chain's leaf.
    struct KeylessFixture {
        /// Leaf (index 0), intermediate (index 1) DER bytes.
        chain_der: Vec<Vec<u8>>,
        /// Root DER — passed to `verify_blob_keyless` as a trust
        /// anchor.
        root_der: Vec<u8>,
        /// Real P-256 signing key whose public part is in the leaf
        /// cert. Used to actually sign DSSE PAE bytes.
        leaf_signing_key: SigningKey,
        /// Email SAN burned into the leaf — for the SAN-policy test.
        leaf_email: String,
    }

    /// Validity-window override for [`build_keyless_fixture_with_validity`],
    /// expressed as `(year, month, day)` triplets so the test module
    /// doesn't have to name `time::OffsetDateTime` directly. `None` =
    /// use rcgen's permissive default (1975-01-01 to 4096-01-01),
    /// which keeps pre-#26 tests passing under `SystemClock` without
    /// wall-clock-dependent fixtures.
    #[derive(Clone, Copy)]
    struct ValidityOverride {
        leaf_not_before: Option<(i32, u8, u8)>,
        leaf_not_after: Option<(i32, u8, u8)>,
        intermediate_not_before: Option<(i32, u8, u8)>,
        intermediate_not_after: Option<(i32, u8, u8)>,
    }

    impl ValidityOverride {
        const fn none() -> Self {
            Self {
                leaf_not_before: None,
                leaf_not_after: None,
                intermediate_not_before: None,
                intermediate_not_after: None,
            }
        }
    }

    impl KeylessFixture {
        /// Default fixture: every cert uses rcgen's 1975 → 4096 default
        /// window, which is wide enough that `SystemClock` always lands
        /// inside the validity range. Existing tests that don't care
        /// about expiry call this and get the pre-#26 behaviour.
        fn build() -> Self {
            build_keyless_fixture_with_validity(ValidityOverride::none())
        }

        /// Variant whose leaf has `notAfter` strictly before
        /// [`KEYLESS_FIXED_NOW`] (the timestamp the cert-expiry tests
        /// pin via `FixedClock`). Intermediate validity is left at the
        /// permissive default so the failure attributes to the leaf.
        ///
        /// Bug class this fixture exists for: a verifier that ignores
        /// `notAfter` lets a stolen Fulcio leaf cert replay forever.
        fn build_with_expired_leaf() -> Self {
            // Leaf: 2020-01-01 → 2020-12-31. KEYLESS_FIXED_NOW is in
            // 2024 — well after notAfter.
            build_keyless_fixture_with_validity(ValidityOverride {
                leaf_not_before: Some((2020, 1, 1)),
                leaf_not_after: Some((2020, 12, 31)),
                intermediate_not_before: None,
                intermediate_not_after: None,
            })
        }

        /// Variant whose intermediate has `notAfter` strictly before
        /// [`KEYLESS_FIXED_NOW`], but whose leaf is still inside its
        /// (permissive) default window.
        ///
        /// Bug class: a verifier that only checks the leaf misses
        /// expiry on the intermediate. An attacker who held an
        /// expired intermediate could use it to fingerprint chains
        /// that should have been rotated.
        fn build_with_expired_intermediate() -> Self {
            build_keyless_fixture_with_validity(ValidityOverride {
                leaf_not_before: None,
                leaf_not_after: None,
                intermediate_not_before: Some((2020, 1, 1)),
                intermediate_not_after: Some((2020, 12, 31)),
            })
        }

        /// Variant whose leaf has `notBefore` strictly after
        /// [`KEYLESS_FIXED_NOW`] — simulating a producer with a
        /// fast-skewed clock.
        ///
        /// Bug class: a verifier that ignores `notBefore` would
        /// accept a cert minted in some host's future, which from
        /// every other host's POV is unverifiable. The clock-skew
        /// must surface as a typed rejection.
        fn build_with_not_yet_valid_leaf() -> Self {
            // Leaf: 2099-01-01 → 2099-12-31. KEYLESS_FIXED_NOW is in
            // 2024 — well before notBefore.
            build_keyless_fixture_with_validity(ValidityOverride {
                leaf_not_before: Some((2099, 1, 1)),
                leaf_not_after: Some((2099, 12, 31)),
                intermediate_not_before: None,
                intermediate_not_after: None,
            })
        }
    }

    /// Pinned "now" for cert-expiry tests: 2024-06-15T00:00:00Z =
    /// 1 718 409 600 Unix seconds. Falls between every test fixture's
    /// expired window (2020) and not-yet-valid window (2099) so the
    /// same FixedClock value works for both directions.
    const KEYLESS_FIXED_NOW: i64 = 1_718_409_600;

    /// Parameterised builder. `validity` lets callers pin a leaf or
    /// intermediate window; `None` falls back to rcgen's wide default.
    /// The root cert is always left at the default — a chain whose
    /// root has expired is a much rarer (and noisier) failure mode
    /// that we don't need a test fixture for in this slice.
    fn build_keyless_fixture_with_validity(validity: ValidityOverride) -> KeylessFixture {
        let root_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root kp");
        let mut root_params = CertificateParams::new(Vec::<String>::new()).expect("root params");
        root_params
            .distinguished_name
            .push(DnType::CommonName, "keyless-root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root_cert = root_params.self_signed(&root_kp).expect("root self-sign");
        let root_der = root_cert.der().to_vec();

        let intermediate_kp =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("intermediate kp");
        let mut intermediate_params =
            CertificateParams::new(Vec::<String>::new()).expect("intermediate params");
        intermediate_params
            .distinguished_name
            .push(DnType::CommonName, "keyless-intermediate");
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        intermediate_params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        if let Some((y, m, d)) = validity.intermediate_not_before {
            intermediate_params.not_before = date_time_ymd(y, m, d);
        }
        if let Some((y, m, d)) = validity.intermediate_not_after {
            intermediate_params.not_after = date_time_ymd(y, m, d);
        }
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_kp, &root_cert, &root_kp)
            .expect("intermediate sign");
        let intermediate_der = intermediate_cert.der().to_vec();

        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf kp");
        // Re-import the leaf keypair as a p256 SigningKey so we can
        // produce DSSE signatures verifiable under the leaf cert's
        // SubjectPublicKeyInfo. rcgen's KeyPair holds PKCS#8 DER.
        let leaf_pkcs8_der = leaf_kp.serialize_der();
        let leaf_signing_key =
            SigningKey::from_pkcs8_der(&leaf_pkcs8_der).expect("leaf PKCS#8 → p256 SigningKey");

        let leaf_email = "keyless-test@example.com".to_string();
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "keyless-leaf");
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.subject_alt_names = vec![SanType::Rfc822Name(
            leaf_email.clone().try_into().expect("email IA5"),
        )];
        if let Some((y, m, d)) = validity.leaf_not_before {
            leaf_params.not_before = date_time_ymd(y, m, d);
        }
        if let Some((y, m, d)) = validity.leaf_not_after {
            leaf_params.not_after = date_time_ymd(y, m, d);
        }
        let leaf_cert = leaf_params
            .signed_by(&leaf_kp, &intermediate_cert, &intermediate_kp)
            .expect("leaf sign");
        let leaf_der = leaf_cert.der().to_vec();

        KeylessFixture {
            chain_der: vec![leaf_der, intermediate_der],
            root_der,
            leaf_signing_key,
            leaf_email,
        }
    }

    /// Backward-compat shim for tests written against the original
    /// no-arg builder. New tests SHOULD call `KeylessFixture::build()`
    /// or one of the validity-pinned variants directly.
    fn build_keyless_fixture() -> KeylessFixture {
        KeylessFixture::build()
    }

    /// Build a bundle whose `verification_material.certificate`
    /// holds the synthetic chain and whose DSSE envelope is signed
    /// by the leaf's signing key. The simplest path: sign with an
    /// `EcdsaP256Signer` wrapping the leaf key, then patch the
    /// resulting bundle to attach the chain.
    fn sign_with_chain(payload: &[u8], fx: &KeylessFixture) -> Bundle {
        // Produce the bundle via the v0 sign path so PAE / signature
        // shape is byte-identical to what `verify_blob` expects.
        // Cloning the SigningKey isn't allowed, so re-import.
        let signing_key_clone =
            SigningKey::from_bytes(&fx.leaf_signing_key.to_bytes()).expect("re-import leaf key");
        let signer = EcdsaP256Signer::new(signing_key_clone, Some("leaf".into()));
        let mut bundle = sign_blob(payload, "text/plain", &signer, None).expect("sign_blob");

        // Patch in the synthetic cert chain.
        bundle.verification_material.certificate = Some(SpecCertificate {
            certificates: fx.chain_der.clone(),
        });
        bundle
    }

    /// Bug it catches: a verifier that never wires the leaf VK into
    /// the DSSE check (e.g. trusted_keys = [] with no leaf bound)
    /// would silently fail every keyless verification. Or a verifier
    /// that wires the WRONG key (intermediate, root) would pass
    /// signatures it shouldn't be able to. Sign with the real leaf
    /// key, verify must succeed.
    #[test]
    fn test_verify_blob_keyless_round_trips_through_real_chain() {
        let fx = build_keyless_fixture();
        let bundle = sign_with_chain(b"keyless payload", &fx);

        verify_blob_keyless(&bundle, std::slice::from_ref(&fx.root_der), None, None)
            .expect("real keyless chain must verify");
    }

    /// Bug it catches: a verifier that ignored `expected_san` and
    /// returned Ok regardless. Pass a SAN that DOESN'T match — must
    /// reject with `SanMismatch`.
    #[test]
    fn test_verify_blob_keyless_rejects_san_mismatch() {
        let fx = build_keyless_fixture();
        let bundle = sign_with_chain(b"keyless payload", &fx);

        let err = verify_blob_keyless(
            &bundle,
            std::slice::from_ref(&fx.root_der),
            Some("not-the-real-email@evil.example"),
            None,
        )
        .expect_err("SAN mismatch must reject");

        match err {
            VerifyError::SanMismatch { expected, actual } => {
                assert_eq!(expected, "not-the-real-email@evil.example");
                assert!(
                    actual.iter().any(|e| e == &fx.leaf_email),
                    "actual SAN list must include the leaf's email — got {actual:?}"
                );
            }
            other => panic!("expected SanMismatch, got {other:?}"),
        }
    }

    /// Bug it catches: a verifier that accepted a chain even when
    /// the trust anchors don't include the issuer of the chain's
    /// topmost cert. Build a real bundle, pass an UNRELATED root.
    /// Must reject with `ChainBroken(RootNotTrusted)`.
    #[test]
    fn test_verify_blob_keyless_rejects_unrelated_trust_anchor() {
        let fx = build_keyless_fixture();
        let unrelated = build_keyless_fixture();
        let bundle = sign_with_chain(b"keyless payload", &fx);

        let err = verify_blob_keyless(&bundle, &[unrelated.root_der], None, None)
            .expect_err("unrelated anchor must reject");

        match err {
            VerifyError::ChainBroken(ChainError::RootNotTrusted { .. }) => {}
            other => panic!("expected ChainBroken(RootNotTrusted), got {other:?}"),
        }
    }

    /// Bug it catches: a verifier that didn't error on a bundle
    /// missing the cert chain entirely (e.g. a v0 non-keyless
    /// bundle being fed to the keyless path). Must surface
    /// `EmptyCertChain` distinctly so caller can route on it.
    #[test]
    fn test_verify_blob_keyless_rejects_bundle_with_no_certificate() {
        let fx = build_keyless_fixture();
        // Same fixture, same payload — but DON'T patch in the chain.
        // The bundle leaves `verification_material.certificate = None`.
        let signing_key_clone =
            SigningKey::from_bytes(&fx.leaf_signing_key.to_bytes()).expect("re-import leaf key");
        let signer = EcdsaP256Signer::new(signing_key_clone, None);
        let bundle = sign_blob(b"no-chain payload", "text/plain", &signer, None).unwrap();
        assert!(bundle.verification_material.certificate.is_none());

        let err = verify_blob_keyless(&bundle, &[fx.root_der], None, None)
            .expect_err("missing chain must reject");
        assert!(
            matches!(err, VerifyError::EmptyCertChain),
            "expected EmptyCertChain, got {err:?}"
        );
    }

    /// Bug it catches: a verifier that walks the chain successfully
    /// but skips the DSSE-against-leaf-key step — i.e. it returned
    /// Ok the moment the chain validated, regardless of whether the
    /// envelope's signature actually came from the leaf's private
    /// key. We sign the envelope with a DIFFERENT keypair, attach
    /// the legitimate chain, and require rejection.
    #[test]
    fn test_verify_blob_keyless_rejects_signature_from_wrong_key() {
        let fx = build_keyless_fixture();

        // Sign with a fresh, unrelated signing key.
        let unrelated_signer = EcdsaP256Signer::new(
            SigningKey::from_bytes(&[0x33u8; 32].into()).expect("scalar"),
            None,
        );
        let mut bundle =
            sign_blob(b"sneaky payload", "text/plain", &unrelated_signer, None).unwrap();
        // Stitch the legitimate chain in. If the verifier short-
        // circuits on chain success, this will pass — and that's
        // exactly the bug we want to catch.
        bundle.verification_material.certificate = Some(SpecCertificate {
            certificates: fx.chain_der.clone(),
        });

        let err = verify_blob_keyless(&bundle, &[fx.root_der], None, None)
            .expect_err("wrong-key DSSE must reject");
        assert!(
            matches!(err, VerifyError::SignatureInvalid { .. }),
            "expected SignatureInvalid, got {err:?}"
        );
    }

    /// Sanity check on the helper: a `Signature` import that fails
    /// would silently produce wrong test fixtures. Pin it.
    #[test]
    fn test_keyless_fixture_leaf_signs_verifiably() {
        let fx = build_keyless_fixture();
        let msg = b"sanity";
        let sig: Signature = fx.leaf_signing_key.sign(msg);
        // Re-extract the verifying key the same way verify_chain
        // does, and confirm it agrees with the signature we just
        // produced.
        let leaf_vk = cert_chain::verify_chain(&fx.chain_der, std::slice::from_ref(&fx.root_der))
            .expect("chain verify");
        leaf_vk
            .verify(msg, &sig)
            .expect("signature from leaf signing key must verify under leaf VK");
    }

    // ─── issue #26: cert validity-window enforcement ────────────────

    /// Bug it catches: a verifier that ignores `notAfter` lets a
    /// stolen Fulcio leaf cert replay forever — even after the
    /// stated lifetime expired and the cert was rotated. We mint a
    /// leaf whose `notAfter` is in 2020, pin "now" to 2024, and
    /// require [`VerifyError::CertExpired`].
    #[test]
    fn test_verify_blob_keyless_with_expired_leaf_returns_cert_expired() {
        let fx = KeylessFixture::build_with_expired_leaf();
        let bundle = sign_with_chain(b"replay payload", &fx);

        let err = verify_blob_keyless_with_clock(
            &bundle,
            std::slice::from_ref(&fx.root_der),
            None,
            None,
            &FixedClock(KEYLESS_FIXED_NOW),
        )
        .expect_err("expired leaf must reject");

        match err {
            VerifyError::CertExpired { not_after } => {
                // Leaf was minted with notAfter = 2020-12-31. The
                // exact Unix-seconds value is implementation-detail
                // of rcgen + x509-cert; we assert it's strictly
                // before our pinned now.
                assert!(
                    not_after < KEYLESS_FIXED_NOW,
                    "CertExpired.not_after = {not_after} must be < now = {KEYLESS_FIXED_NOW}"
                );
                // And specifically inside calendar year 2020 to pin
                // we got the LEAF's notAfter (not, say, the root's
                // default 4096-01-01 which would be huge).
                // 2020-01-01 = 1577836800; 2021-01-01 = 1609459200.
                assert!(
                    (1_577_836_800..1_609_459_200).contains(&not_after),
                    "CertExpired.not_after = {not_after} expected inside 2020"
                );
            }
            other => panic!("expected CertExpired, got {other:?}"),
        }
    }

    /// Bug it catches: a verifier that only checks the leaf's
    /// validity window misses chain-wide expiry. An expired
    /// intermediate is just as security-relevant as an expired leaf
    /// — both indicate "this material should have been rotated".
    #[test]
    fn test_verify_blob_keyless_with_expired_intermediate_returns_cert_expired() {
        let fx = KeylessFixture::build_with_expired_intermediate();
        let bundle = sign_with_chain(b"intermediate-expiry payload", &fx);

        let err = verify_blob_keyless_with_clock(
            &bundle,
            std::slice::from_ref(&fx.root_der),
            None,
            None,
            &FixedClock(KEYLESS_FIXED_NOW),
        )
        .expect_err("expired intermediate must reject");

        match err {
            VerifyError::CertExpired { not_after } => {
                // Intermediate was minted with notAfter = 2020-12-31.
                assert!(
                    (1_577_836_800..1_609_459_200).contains(&not_after),
                    "CertExpired.not_after = {not_after} expected inside 2020 \
                     (intermediate's notAfter); a value outside that range \
                     suggests the verifier checked a different cert in the chain"
                );
            }
            other => panic!("expected CertExpired, got {other:?}"),
        }
    }

    /// Bug it catches: a verifier that ignores `notBefore`. A
    /// producer running on a fast-skewed host can mint certs that
    /// are valid only in the future; without a `notBefore` gate,
    /// every other host in the world would accept them as fresh.
    /// The clock-skew failure mode must surface as a typed rejection.
    #[test]
    fn test_verify_blob_keyless_with_not_yet_valid_leaf_returns_cert_not_yet_valid() {
        let fx = KeylessFixture::build_with_not_yet_valid_leaf();
        let bundle = sign_with_chain(b"future-skew payload", &fx);

        let err = verify_blob_keyless_with_clock(
            &bundle,
            std::slice::from_ref(&fx.root_der),
            None,
            None,
            &FixedClock(KEYLESS_FIXED_NOW),
        )
        .expect_err("not-yet-valid leaf must reject");

        match err {
            VerifyError::CertNotYetValid { not_before } => {
                // Leaf was minted with notBefore = 2099-01-01.
                // 2099-01-01 = 4 070 908 800 Unix seconds.
                // 2100-01-01 = 4 102 444 800.
                assert!(
                    (4_070_908_800..4_102_444_800).contains(&not_before),
                    "CertNotYetValid.not_before = {not_before} expected inside 2099"
                );
                assert!(
                    not_before > KEYLESS_FIXED_NOW,
                    "CertNotYetValid.not_before = {not_before} must be > now = {KEYLESS_FIXED_NOW}"
                );
            }
            other => panic!("expected CertNotYetValid, got {other:?}"),
        }
    }

    /// Smoke-test that the gate doesn't reject valid certs. Use the
    /// default fixture (rcgen 1975 → 4096 default window) which
    /// always covers `KEYLESS_FIXED_NOW` (2024). If this fails the
    /// clock check is overzealous — e.g. swapping `<` and `<=` or
    /// comparing the wrong field.
    #[test]
    fn test_verify_blob_keyless_with_clock_inside_window_succeeds() {
        let fx = build_keyless_fixture();
        let bundle = sign_with_chain(b"in-window payload", &fx);

        verify_blob_keyless_with_clock(
            &bundle,
            std::slice::from_ref(&fx.root_der),
            None,
            None,
            &FixedClock(KEYLESS_FIXED_NOW),
        )
        .expect("default-validity chain must verify under FixedClock(2024)");
    }

    /// Bug it catches: a `verify_blob_keyless_with_clock` impl that
    /// silently falls back to `SystemTime::now()` instead of
    /// consulting the supplied `&dyn Clock`. We pin the clock to
    /// year-2150 (well beyond rcgen's default `notAfter` of
    /// 4096-01-01... wait — 4096 IS post-2150). So instead we pin to
    /// FAR-future after rcgen's 4096 default expiry: 4096-06-01 =
    /// 67 116 614 400 Unix seconds. With this clock the default
    /// fixture's leaf (notAfter = 4096-01-01) is expired, and the
    /// only way the verifier learns that is by consulting our clock
    /// — proving the parameter is wired.
    #[test]
    fn test_verify_blob_keyless_with_clock_consults_injected_clock_not_system_time() {
        let fx = build_keyless_fixture();
        let bundle = sign_with_chain(b"clock-injection payload", &fx);

        // 4096-06-01 — past every rcgen default `notAfter`.
        // Computed inline: from 1970-01-01 to 4096-06-01 is 4096-1970
        // = 2126 years; rough seconds ≈ 67 100 000 000. We use
        // 67_116_614_400, but the EXACT value is not load-bearing —
        // any value strictly past 4096-01-01 (which is approximately
        // 67 100 803 200) suffices.
        let post_default_expiry: i64 = 67_116_614_400;

        let err = verify_blob_keyless_with_clock(
            &bundle,
            std::slice::from_ref(&fx.root_der),
            None,
            None,
            &FixedClock(post_default_expiry),
        )
        .expect_err(
            "FixedClock pinned past rcgen default notAfter must reject; \
             if this passes the verifier ignored our clock and used SystemTime::now()",
        );

        assert!(
            matches!(err, VerifyError::CertExpired { .. }),
            "expected CertExpired (proving the injected clock was consulted), got {err:?}"
        );
    }

    /// Bug it catches: a `verify_blob_keyless` (no-clock variant)
    /// that DOESN'T enforce expiry at all — would reduce to the
    /// pre-#26 behaviour. We rely on `SystemClock` here; the
    /// fixture's leaf has notAfter = 4096-01-01, well after any
    /// realistic CI clock, so this MUST succeed. A regression where
    /// `verify_blob_keyless` swaps to a hardcoded "now = 0" or
    /// similar would cause every cert with notBefore > 0 to surface
    /// `CertNotYetValid`.
    #[test]
    fn test_verify_blob_keyless_default_clock_under_system_clock_succeeds() {
        let fx = build_keyless_fixture();
        let bundle = sign_with_chain(b"system-clock payload", &fx);

        verify_blob_keyless(&bundle, std::slice::from_ref(&fx.root_der), None, None)
            .expect("default fixture must verify under SystemClock");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use rekor::MockRekorClient;

    /// Canned signature bytes used by the mock-signer round trip.
    /// Length is realistic for a DER-encoded ECDSA-P256 signature
    /// (~70 bytes) but the contents are arbitrary.
    fn canned_signature() -> Vec<u8> {
        vec![0xAB; 70]
    }

    /// MockSigner pair where verification is byte-equality on the
    /// canned signature. Lets us exercise the bundle-shape glue
    /// without a real key.
    struct CannedKeyVerifier {
        canned: Vec<u8>,
    }

    impl CannedKeyVerifier {
        fn matches(&self, sig: &[u8]) -> bool {
            sig == self.canned.as_slice()
        }
    }

    /// Sign a payload with the mock signer, check the bundle is
    /// well-shaped, and verify by comparing the embedded signature
    /// to the canned bytes.
    ///
    /// Bug it catches: any drift in the DSSE PAE shape (different
    /// payload_type bytes, missing space, wrong length encoding)
    /// would mean the signer hashes over different bytes than the
    /// verifier — the byte-equality check on the signature still
    /// passes for the mock, but the canonical PAE bytes are
    /// pinned here so we'd see the regression in the assertion
    /// on `envelope.pae()`.
    #[test]
    fn test_sign_blob_with_mock_signer_round_trips_through_verify() {
        let signer = MockSigner::new(canned_signature(), Some("k1".into()));
        let payload = b"hello world";
        let payload_type = "text/plain";

        let bundle = sign_blob(payload, payload_type, &signer, None).unwrap();

        // Bundle shape.
        assert_eq!(bundle.media_type, SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE);
        let envelope = match &bundle.content {
            BundleContent::DsseEnvelope(e) => e,
            _ => panic!("expected DSSE envelope content"),
        };
        assert_eq!(envelope.payload_type, payload_type);
        assert_eq!(envelope.payload, payload);
        assert_eq!(envelope.signatures.len(), 1);
        assert_eq!(envelope.signatures[0].keyid.as_deref(), Some("k1"));
        assert_eq!(envelope.signatures[0].sig, canned_signature());

        // PAE bytes match the canonical DSSE encoding.
        let expected_pae = b"DSSEv1 10 text/plain 11 hello world";
        assert_eq!(envelope.pae(), expected_pae);

        // "Verify" by comparing the canned signature.
        let verifier = CannedKeyVerifier {
            canned: canned_signature(),
        };
        assert!(verifier.matches(&envelope.signatures[0].sig));

        // Round-trip through bundle JSON to make sure the wire
        // shape we produce is decodable.
        let bytes = bundle.encode_json().unwrap();
        let decoded = Bundle::decode_json(&bytes).unwrap();
        assert_eq!(decoded, bundle);
    }

    /// Sign with a real `EcdsaP256Signer` and verify with the
    /// matching `VerifyingKey`.
    ///
    /// Bug it catches: any drift in PAE bytes between sign and
    /// verify (e.g. forgetting to UTF-8-encode `payload_type`,
    /// using `to_string()` length instead of byte length on a
    /// multibyte payload type) would surface as a verification
    /// failure even though no bytes were tampered with.
    #[test]
    fn test_sign_blob_with_ecdsa_signer_real_signature() {
        // Deterministic keypair so the test isn't flaky.
        let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());

        let signer = EcdsaP256Signer::new(sk, Some("test-key".into()));
        let payload = b"production-grade payload bytes \xF0\x9F\x9A\x80";
        let payload_type = "application/vnd.dev.sigstore.bundle+json;version=0.3";

        let bundle = sign_blob(payload, payload_type, &signer, None).unwrap();
        verify_blob(&bundle, &[vk], None).expect("real signature must verify");
    }

    /// Mutating the payload after signing breaks verification:
    /// the verifier re-derives the PAE from the (modified)
    /// payload and the signature no longer matches.
    ///
    /// Bug it catches: a verifier that signed over the JSON
    /// envelope text (instead of the PAE) would NOT detect this
    /// tamper because the envelope body itself wasn't mutated.
    #[test]
    fn test_verify_blob_rejects_tampered_payload() {
        let mut rng = ChaCha20Rng::from_seed([0x11; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        let mut bundle = sign_blob(b"original payload", "text/plain", &signer, None).unwrap();

        // Mutate the payload bytes after signing.
        if let BundleContent::DsseEnvelope(env) = &mut bundle.content {
            env.payload = b"tampered payload".to_vec();
        } else {
            unreachable!();
        }

        let err = verify_blob(&bundle, &[vk], None).unwrap_err();
        assert!(
            matches!(err, VerifyError::SignatureInvalid { .. }),
            "expected SignatureInvalid, got {err:?}"
        );
    }

    /// Flipping a single bit in the signature breaks verification.
    ///
    /// Bug it catches: a verifier that returned `Ok(())` whenever
    /// the DER parse succeeded (without actually checking the
    /// signature) would silently accept this tamper.
    #[test]
    fn test_verify_blob_rejects_wrong_signature() {
        let mut rng = ChaCha20Rng::from_seed([0x22; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, Some("bit-flip".into()));

        let mut bundle = sign_blob(b"the payload", "text/plain", &signer, None).unwrap();

        if let BundleContent::DsseEnvelope(env) = &mut bundle.content {
            // Flip a low-significance byte deep in the DER. Picks
            // a position that's not in the ASN.1 length headers,
            // so the `from_der` parse still succeeds and we hit
            // the cryptographic check, not the parser path.
            let last = env.signatures[0].sig.len() - 1;
            env.signatures[0].sig[last] ^= 0x01;
        } else {
            unreachable!();
        }

        let err = verify_blob(&bundle, &[vk], None).unwrap_err();
        match err {
            VerifyError::SignatureInvalid { keyid } => {
                assert_eq!(keyid.as_deref(), Some("bit-flip"));
            }
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    /// `sign_blob` with a Rekor client embeds exactly one
    /// `tlog_entries` entry and the embedded inclusion proof
    /// reconstructs against the bundle's root.
    ///
    /// Bug it catches: a sign path that ignored the rekor client
    /// (forgot to call `.submit`) would emit an empty
    /// `tlog_entries`. A sign path that attached the entry but
    /// dropped the proof bytes would emit a non-verifiable
    /// inclusion proof.
    #[test]
    fn test_sign_blob_with_rekor_client_attaches_tlog_entry() {
        let signer = MockSigner::new(canned_signature(), None);
        let client = MockRekorClient::new();

        let bundle = sign_blob(b"witnessed payload", "text/plain", &signer, Some(&client)).unwrap();

        assert_eq!(bundle.verification_material.tlog_entries.len(), 1);
        let tlog = &bundle.verification_material.tlog_entries[0];
        assert_eq!(tlog.log_index, 0);
        assert_eq!(tlog.kind_version.kind, "hashedrekord");
        let proof = tlog.inclusion_proof.as_ref().unwrap();
        assert_eq!(proof.log_index, 0);
        assert_eq!(proof.tree_size, 1);
        assert!(proof.hashes.is_empty(), "single-leaf log → empty path");
    }

    /// `verify_blob` with a Rekor client and an embedded inclusion
    /// proof routes through `rekor::verify_inclusion` and
    /// succeeds for a valid proof.
    ///
    /// Bug it catches: a verifier that "skipped" Rekor when no
    /// real HTTP was wired would pass even if the proof inside
    /// the bundle was garbage. We synthesise a real proof via
    /// the mock and re-verify it explicitly.
    #[test]
    fn test_verify_blob_with_rekor_verifies_inclusion_proof() {
        let mut rng = ChaCha20Rng::from_seed([0x33; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);
        let client = MockRekorClient::new();

        let bundle =
            sign_blob(b"transparency please", "text/plain", &signer, Some(&client)).unwrap();

        verify_blob(&bundle, &[vk], Some(&client)).expect("inclusion proof must verify");
    }

    /// `verify_blob` without a Rekor client succeeds even when
    /// the bundle has tlog entries — absence of the client means
    /// "I don't need transparency this time".
    ///
    /// Bug it catches: a verifier that auto-ran proof verification
    /// whenever `tlog_entries` was non-empty would force every
    /// caller to ship a Rekor client even for offline-trust
    /// flows. Policy decides; the SPI doesn't.
    #[test]
    fn test_verify_blob_without_rekor_client_skips_proof_check() {
        let mut rng = ChaCha20Rng::from_seed([0x44; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);
        let client = MockRekorClient::new();

        let bundle = sign_blob(b"data", "text/plain", &signer, Some(&client)).unwrap();
        assert_eq!(bundle.verification_material.tlog_entries.len(), 1);

        // No rekor client passed → proof check is intentionally
        // skipped. Signature still verifies.
        verify_blob(&bundle, &[vk], None).expect("offline verify should succeed");
    }

    /// `verify_blob` with a Rekor client but NO tlog entries
    /// surfaces `NoTlogEntry` — caller asked for transparency,
    /// bundle has none.
    ///
    /// Bug it catches: a verifier that silently passed in this
    /// case lets an unwitnessed bundle satisfy a transparency-
    /// required policy.
    #[test]
    fn test_verify_blob_with_rekor_client_and_no_tlog_returns_no_tlog_entry() {
        let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);
        let client = MockRekorClient::new();

        let bundle = sign_blob(b"unwitnessed", "text/plain", &signer, None).unwrap();
        assert!(bundle.verification_material.tlog_entries.is_empty());

        let err = verify_blob(&bundle, &[vk], Some(&client)).unwrap_err();
        assert!(matches!(err, VerifyError::NoTlogEntry));
    }

    /// `verify_blob` rejects a bundle whose content is the
    /// `MessageSignature` arm — v0 is DSSE-only.
    #[test]
    fn test_verify_blob_rejects_message_signature_bundle() {
        let bundle = Bundle {
            media_type: SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE.to_string(),
            verification_material: VerificationMaterial {
                certificate: None,
                tlog_entries: vec![],
                timestamp_verification_data: None,
            },
            content: BundleContent::MessageSignature(spec::MessageSignature {
                message_digest: HashOutput {
                    algorithm: "SHA2_256".into(),
                    digest: vec![0u8; 32],
                },
                signature: vec![0u8; 70],
            }),
        };
        let err = verify_blob(&bundle, &[], None).unwrap_err();
        assert!(matches!(err, VerifyError::EnvelopeMissing));
    }

    /// Multibyte payload type round-trips through PAE → sign →
    /// verify. Pinned because PAE byte-vs-char-count drift is
    /// the most common DSSE bug.
    ///
    /// Bug it catches: a builder that used `payload_type.len()`
    /// in chars (impossible in Rust but trivial in JS ports) or
    /// any byte-vs-char drift would diverge between sign and
    /// verify on this input.
    #[test]
    fn test_sign_blob_with_multibyte_payload_type_round_trips() {
        let mut rng = ChaCha20Rng::from_seed([0x66; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        // Mostly-ASCII media type but with a non-ASCII byte to
        // catch any UTF-8-vs-char-count drift.
        let payload_type = "application/vnd.example+json; charset=café";
        let payload = b"\x00\x01\x02\xff";

        let bundle = sign_blob(payload, payload_type, &signer, None).unwrap();
        verify_blob(&bundle, &[vk], None).unwrap();
    }

    /// Two independently-constructed `EcdsaP256Signer`s with the
    /// SAME seeded key produce signatures that BOTH verify against
    /// the shared verifying key — keyid is just a hint, not a
    /// security boundary.
    #[test]
    fn test_verify_blob_succeeds_with_correct_key_even_when_keyid_differs() {
        let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, Some("the-signer-said-this".into()));

        let bundle = sign_blob(b"hi", "x/y", &signer, None).unwrap();
        // Verifier doesn't know about keyids; it just tries the
        // key. Should still succeed.
        verify_blob(&bundle, &[vk], None).unwrap();
    }

    // -----------------------------------------------------------
    // OCI artifact signing tests — issue #6
    // -----------------------------------------------------------

    /// `sign_oci` produces a layer descriptor whose digest equals
    /// the SHA-256 of the bundle bytes the caller will push.
    ///
    /// Bug it catches: a sign path that hashed the bundle BEFORE
    /// the rekor `tlog_entries` were attached (hashing the
    /// pre-rekor bundle instead of the final one) would emit a
    /// layer digest that no registry blob could ever match.
    #[test]
    fn test_sign_oci_produces_consistent_layer_digest() {
        let mut rng = ChaCha20Rng::from_seed([0x88; 32]);
        let sk = SigningKey::random(&mut rng);
        let signer = EcdsaP256Signer::new(sk, Some("oci-test".into()));

        let subject_digest =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let artifacts = sign_oci(
            subject_digest,
            "application/vnd.oci.image.manifest.v1+json",
            4096,
            &signer,
            None,
        )
        .unwrap();

        // bundle_bytes hashes to bundle_digest.
        let recomputed = oci::sha256_digest_string(&artifacts.bundle_bytes);
        assert_eq!(recomputed, artifacts.bundle_digest);

        // Manifest's layer descriptor carries that exact digest.
        let parsed = oci::parse_referrer_manifest(&artifacts.referrer_manifest).unwrap();
        assert_eq!(parsed.layer.digest, artifacts.bundle_digest);
        assert_eq!(parsed.layer.size, artifacts.bundle_bytes.len() as u64);

        // referrer_manifest_digest hashes the manifest bytes.
        let recomputed_manifest = oci::sha256_digest_string(&artifacts.referrer_manifest);
        assert_eq!(recomputed_manifest, artifacts.referrer_manifest_digest);
    }

    /// Tampering the bundle after signing causes `verify_oci` to
    /// reject with `OciLayerMismatch` — the layer descriptor
    /// pinned in the manifest no longer matches.
    ///
    /// Bug it catches: a verifier that ran `verify_blob` first
    /// (and bailed on signature failure) would mask the layer-
    /// digest check entirely. We tamper a byte that doesn't break
    /// the bundle's signature so the layer-digest path is the
    /// only thing standing between the verifier and a wrong-
    /// blob acceptance.
    #[test]
    fn test_verify_oci_rejects_layer_digest_mismatch() {
        let mut rng = ChaCha20Rng::from_seed([0x99; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        let subject_digest =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let artifacts = sign_oci(
            subject_digest,
            "application/vnd.oci.image.manifest.v1+json",
            500,
            &signer,
            None,
        )
        .unwrap();

        // Decode the bundle, mutate the keyid (a non-signed
        // metadata field — the cryptographic signature still
        // verifies, but the encoded bytes change). This isolates
        // the layer-digest check from the cryptographic check.
        let mut tampered_bundle = Bundle::decode_json(&artifacts.bundle_bytes).unwrap();
        if let BundleContent::DsseEnvelope(env) = &mut tampered_bundle.content {
            env.signatures[0].keyid = Some("tampered-keyid".to_string());
        } else {
            unreachable!();
        }

        let err =
            verify_oci(&artifacts.referrer_manifest, &tampered_bundle, &[vk], None).unwrap_err();
        assert!(
            matches!(err, VerifyError::OciLayerMismatch { .. }),
            "expected OciLayerMismatch, got {err:?}"
        );
    }

    /// `verify_oci` rejects a manifest whose `artifactType` is
    /// not the Sigstore bundle media type. Routes through the
    /// `Oci(WrongArtifactType)` chain.
    #[test]
    fn test_verify_oci_rejects_wrong_artifact_type() {
        // Hand-build a manifest with the wrong artifactType but
        // an otherwise-correct shape, then drive verify_oci.
        let mut rng = ChaCha20Rng::from_seed([0xAA; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        let subject_digest =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let artifacts = sign_oci(
            subject_digest,
            "application/vnd.oci.image.manifest.v1+json",
            512,
            &signer,
            None,
        )
        .unwrap();

        // Mutate the artifactType in-place via a JSON round trip.
        let mut json: serde_json::Value =
            serde_json::from_slice(&artifacts.referrer_manifest).unwrap();
        json["artifactType"] = serde_json::Value::String("application/wrong+json".to_string());
        let bad_manifest = serde_json::to_vec(&json).unwrap();

        let bundle = Bundle::decode_json(&artifacts.bundle_bytes).unwrap();
        let err = verify_oci(&bad_manifest, &bundle, &[vk], None).unwrap_err();
        match err {
            VerifyError::Oci(OciError::WrongArtifactType { found, .. }) => {
                assert_eq!(found, "application/wrong+json");
            }
            other => panic!("expected Oci(WrongArtifactType), got {other:?}"),
        }
    }

    /// `sign_oci` followed by `verify_oci` succeeds with a real
    /// ECDSA keypair — the full happy path.
    ///
    /// Bug it catches: any drift in the PAE-payload contract
    /// (e.g. signing the digest as bytes vs. as a UTF-8 string,
    /// or stripping the `sha256:` prefix on one side only) would
    /// surface as a verification failure. The cross-check between
    /// `subject.digest` and the bundle's payload would also fail
    /// if either side rewrote the digest format.
    #[test]
    fn test_sign_oci_then_verify_oci_round_trips() {
        let mut rng = ChaCha20Rng::from_seed([0xBB; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, Some("rt-key".into()));

        let subject_digest =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let subject_media_type = "application/vnd.oci.image.manifest.v1+json";
        let subject_size = 7777u64;

        let artifacts = sign_oci(
            subject_digest,
            subject_media_type,
            subject_size,
            &signer,
            None,
        )
        .unwrap();

        // Caller would push artifacts.bundle_bytes as a layer
        // and artifacts.referrer_manifest as a manifest. Verifier
        // pulls them back and re-verifies.
        let pulled_bundle = Bundle::decode_json(&artifacts.bundle_bytes).unwrap();
        let verified =
            verify_oci(&artifacts.referrer_manifest, &pulled_bundle, &[vk], None).unwrap();

        assert_eq!(verified.subject_digest, subject_digest);
        assert_eq!(verified.subject_media_type, subject_media_type);
        assert_eq!(verified.subject_size, subject_size);
    }

    /// `sign_oci` with a Rekor client populates the bundle's
    /// `tlog_entries`, the manifest still parses correctly, and
    /// `verify_oci` with a Rekor client also succeeds.
    ///
    /// Bug it catches: a sign path that re-encoded the bundle
    /// BEFORE attaching tlog entries would land a layer digest
    /// whose preimage doesn't include the tlog. The verifier's
    /// re-encode would then mismatch, surfacing as a
    /// `OciLayerMismatch`.
    #[test]
    fn test_sign_oci_with_rekor_attaches_tlog_entry() {
        let mut rng = ChaCha20Rng::from_seed([0xCC; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);
        let client = MockRekorClient::new();

        let subject_digest =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let artifacts = sign_oci(
            subject_digest,
            "application/vnd.oci.image.manifest.v1+json",
            128,
            &signer,
            Some(&client),
        )
        .unwrap();

        // Bundle has exactly one tlog entry.
        assert_eq!(artifacts.bundle.verification_material.tlog_entries.len(), 1);

        // Round trip with rekor verification.
        let pulled_bundle = Bundle::decode_json(&artifacts.bundle_bytes).unwrap();
        assert_eq!(pulled_bundle.verification_material.tlog_entries.len(), 1);
        let verified = verify_oci(
            &artifacts.referrer_manifest,
            &pulled_bundle,
            &[vk],
            Some(&client),
        )
        .unwrap();
        assert_eq!(verified.subject_digest, subject_digest);
    }

    // ── Attestation API (issue #7) ───────────────────────────────

    /// Constants reused across the attestation tests to keep the
    /// "what the test asserts" close to the assertion. Hex is
    /// lowercase 64 chars (sha256-shaped) but unrelated to the
    /// bytes signed — Statement validation doesn't recompute it.
    const PREDICATE_TYPE_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";
    const PREDICATE_TYPE_SPDX: &str = "https://spdx.dev/Document";
    const SUBJECT_NAME: &str = "pkg:oci/example@sha256:abc";
    const DIGEST_X: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const DIGEST_Y: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// `attest` round-trips through `verify_attestation`: build a
    /// Statement, sign with a real ECDSA key, verify with the
    /// matching public key — predicate body and subject come back
    /// intact.
    ///
    /// Bug it catches: any drift between the encoder used by
    /// `attest` and the decoder used by `verify_attestation` (e.g.
    /// `predicateType` casing, subject digest map ordering) would
    /// surface as a Statement-decode failure or a predicate-Value
    /// mismatch on the returned struct.
    #[test]
    fn test_attest_then_verify_attestation_round_trips() {
        let mut rng = ChaCha20Rng::from_seed([0xA0; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, Some("attest-key".into()));

        let predicate = serde_json::json!({ "foo": "bar" });
        let bundle = attest(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            PREDICATE_TYPE_PROVENANCE_V1,
            predicate.clone(),
            &signer,
            None,
        )
        .unwrap();

        // Bundle wraps the in-toto payload type, not text/plain.
        if let BundleContent::DsseEnvelope(env) = &bundle.content {
            assert_eq!(env.payload_type, IN_TOTO_PAYLOAD_TYPE);
        } else {
            panic!("expected DSSE envelope content");
        }

        let verified = verify_attestation(
            &bundle,
            &[vk],
            PREDICATE_TYPE_PROVENANCE_V1,
            Some(("sha256", DIGEST_X)),
            None,
        )
        .unwrap();

        assert_eq!(verified.predicate_type, PREDICATE_TYPE_PROVENANCE_V1);
        assert_eq!(verified.predicate, predicate);
        assert_eq!(verified.subjects.len(), 1);
        assert_eq!(verified.subjects[0].name, SUBJECT_NAME);
        assert_eq!(
            verified.subjects[0].digest.get("sha256"),
            Some(&DIGEST_X.to_string())
        );
    }

    /// Verifier expecting predicate type B refuses an attestation
    /// signed with predicate type A — even when the signature is
    /// otherwise valid.
    ///
    /// Bug it catches: a verifier that ignored
    /// `expected_predicate_type` (or compared the wrong field, e.g.
    /// `payload_type` instead of `predicateType`) would happily
    /// accept an SPDX SBOM where a SLSA Provenance was required.
    #[test]
    fn test_verify_attestation_rejects_wrong_predicate_type() {
        let mut rng = ChaCha20Rng::from_seed([0xA1; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        let bundle = attest(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            PREDICATE_TYPE_PROVENANCE_V1,
            serde_json::json!({}),
            &signer,
            None,
        )
        .unwrap();

        let err = verify_attestation(&bundle, &[vk], PREDICATE_TYPE_SPDX, None, None).unwrap_err();
        match err {
            VerifyError::WrongPredicateType { expected, found } => {
                assert_eq!(expected, PREDICATE_TYPE_SPDX);
                assert_eq!(found, PREDICATE_TYPE_PROVENANCE_V1);
            }
            other => panic!("expected WrongPredicateType, got {other:?}"),
        }
    }

    /// Verifier expecting digest Y on the subject refuses an
    /// attestation that names digest X.
    ///
    /// Bug it catches: a verifier that always accepted the first
    /// subject without comparing its digest to the expected value
    /// would let an attacker swap in an attestation about a
    /// different artifact and still pass policy.
    #[test]
    fn test_verify_attestation_rejects_subject_digest_mismatch() {
        let mut rng = ChaCha20Rng::from_seed([0xA2; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        let bundle = attest(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            PREDICATE_TYPE_PROVENANCE_V1,
            serde_json::json!({}),
            &signer,
            None,
        )
        .unwrap();

        let err = verify_attestation(
            &bundle,
            &[vk],
            PREDICATE_TYPE_PROVENANCE_V1,
            Some(("sha256", DIGEST_Y)),
            None,
        )
        .unwrap_err();
        match err {
            VerifyError::SubjectMismatch { expected_digest } => {
                assert_eq!(expected_digest, format!("sha256:{DIGEST_Y}"));
            }
            other => panic!("expected SubjectMismatch, got {other:?}"),
        }
    }

    /// Passing `None` for `expected_subject_digest` skips the
    /// subject check entirely — useful when the caller is
    /// enumerating subjects rather than pinning one.
    ///
    /// Bug it catches: a verifier that defaulted "no expectation"
    /// to "must match nothing" (returning `SubjectMismatch` on a
    /// `None` input) would force every caller to pass a digest
    /// even when they just want to read the predicate body.
    #[test]
    fn test_verify_attestation_with_subject_check_disabled() {
        let mut rng = ChaCha20Rng::from_seed([0xA3; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        let bundle = attest(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            PREDICATE_TYPE_PROVENANCE_V1,
            serde_json::json!({ "ok": true }),
            &signer,
            None,
        )
        .unwrap();

        let verified = verify_attestation(&bundle, &[vk], PREDICATE_TYPE_PROVENANCE_V1, None, None)
            .expect("None subject_digest must skip the check");
        assert_eq!(verified.subjects.len(), 1);
        assert_eq!(verified.predicate, serde_json::json!({ "ok": true }));
    }

    /// `verify_attestation` rejects a bundle whose DSSE
    /// `payload_type` is NOT `application/vnd.in-toto+json` — the
    /// signature is valid but the payload isn't an attestation.
    ///
    /// Bug it catches: a verifier that decoded the payload as a
    /// Statement without first checking the wrapper type would
    /// mis-categorise a non-attestation blob with attestation-
    /// shaped JSON content (or fail with a confusing decode error
    /// instead of a clear "wrong payload type" signal).
    #[test]
    fn test_verify_attestation_rejects_payload_type_mismatch() {
        let mut rng = ChaCha20Rng::from_seed([0xA4; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        // Sign a non-attestation blob.
        let bundle = sign_blob(b"hello world", "text/plain", &signer, None).unwrap();

        let err = verify_attestation(&bundle, &[vk], PREDICATE_TYPE_PROVENANCE_V1, None, None)
            .unwrap_err();
        match err {
            VerifyError::WrongPayloadType { expected, found } => {
                assert_eq!(expected, IN_TOTO_PAYLOAD_TYPE);
                assert_eq!(found, "text/plain");
            }
            other => panic!("expected WrongPayloadType, got {other:?}"),
        }
    }

    /// `attest` with a Rekor client embeds a single `tlog_entries`
    /// entry whose inclusion proof verifies — same behaviour as
    /// `sign_blob`'s rekor path, but exercised end-to-end through
    /// the attestation verifier.
    ///
    /// Bug it catches: an `attest` implementation that called
    /// `sign_blob` with the wrong rekor argument (e.g. always
    /// `None`, or shadowed by a local `let rekor = None`) would
    /// emit an unwitnessed bundle even when the caller asked for
    /// transparency.
    #[test]
    fn test_attest_with_rekor_attaches_tlog_entry() {
        let mut rng = ChaCha20Rng::from_seed([0xA5; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);
        let client = MockRekorClient::new();

        let bundle = attest(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            PREDICATE_TYPE_PROVENANCE_V1,
            serde_json::json!({ "witnessed": true }),
            &signer,
            Some(&client),
        )
        .unwrap();

        assert_eq!(bundle.verification_material.tlog_entries.len(), 1);
        let tlog = &bundle.verification_material.tlog_entries[0];
        assert_eq!(tlog.kind_version.kind, "hashedrekord");

        // Full verification exercises sig + proof + Statement
        // decode + predicate-type + subject-digest.
        verify_attestation(
            &bundle,
            &[vk],
            PREDICATE_TYPE_PROVENANCE_V1,
            Some(("sha256", DIGEST_X)),
            Some(&client),
        )
        .expect("attestation with rekor must verify end-to-end");
    }

    // ── Keyless signing (issue #16, Phase A) ─────────────────────
    //
    // The producer counterpart of `verify_blob_keyless`. These tests
    // assert the wire shape of `sign_blob_keyless` (the cert chain
    // really lands in `verification_material.certificate`), the
    // negative path (empty chain rejected as a typed error), and the
    // round-trip through `verify_blob_keyless` so we know the
    // producer + verifier loop closes end-to-end.

    use p256::ecdsa::SigningKey as KeylessSigningKey;
    use p256::pkcs8::DecodePrivateKey as _;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
        PKCS_ECDSA_P256_SHA256,
    };

    /// Three-level synthetic chain bundled with the leaf's signing
    /// key. Mirrors `keyless_tests::build_keyless_fixture` but lives
    /// in this module so the producer-side tests don't reach across
    /// `#[cfg(test)]` module boundaries.
    struct KeylessSignFixture {
        chain_der: Vec<Vec<u8>>,
        root_der: Vec<u8>,
        leaf_signing_key: KeylessSigningKey,
    }

    /// Build a real Fulcio-shaped chain (root → intermediate → leaf)
    /// where the leaf's SubjectPublicKeyInfo holds a P-256 key whose
    /// private half we retain so the caller can produce a DSSE
    /// signature that the leaf actually attests to.
    fn build_keyless_sign_fixture() -> KeylessSignFixture {
        let root_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root kp");
        let mut root_params = CertificateParams::new(Vec::<String>::new()).expect("root params");
        root_params
            .distinguished_name
            .push(DnType::CommonName, "sign-blob-keyless-root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root_cert = root_params.self_signed(&root_kp).expect("root self-sign");
        let root_der = root_cert.der().to_vec();

        let intermediate_kp =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("intermediate kp");
        let mut intermediate_params =
            CertificateParams::new(Vec::<String>::new()).expect("intermediate params");
        intermediate_params
            .distinguished_name
            .push(DnType::CommonName, "sign-blob-keyless-intermediate");
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        intermediate_params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_kp, &root_cert, &root_kp)
            .expect("intermediate sign");
        let intermediate_der = intermediate_cert.der().to_vec();

        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf kp");
        // rcgen keeps the leaf private half as PKCS#8 DER; re-import
        // as a `p256::ecdsa::SigningKey` so the producer-side signer
        // we feed `sign_blob_keyless` produces signatures verifiable
        // against the leaf cert's SPKI.
        let leaf_pkcs8_der = leaf_kp.serialize_der();
        let leaf_signing_key = KeylessSigningKey::from_pkcs8_der(&leaf_pkcs8_der)
            .expect("leaf PKCS#8 → p256 SigningKey");

        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "sign-blob-keyless-leaf");
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.subject_alt_names = vec![SanType::Rfc822Name(
            "sign-blob-keyless@example.com"
                .to_string()
                .try_into()
                .expect("email IA5"),
        )];
        let leaf_cert = leaf_params
            .signed_by(&leaf_kp, &intermediate_cert, &intermediate_kp)
            .expect("leaf sign");
        let leaf_der = leaf_cert.der().to_vec();

        KeylessSignFixture {
            chain_der: vec![leaf_der, intermediate_der],
            root_der,
            leaf_signing_key,
        }
    }

    /// Bug it catches: a producer that "succeeds" in attaching a
    /// cert chain but actually leaves
    /// `verification_material.certificate = None` (e.g. forgets the
    /// mutate step, or builds a fresh `VerificationMaterial` and
    /// drops the chain on the floor). The keyless verifier would
    /// then reject every bundle this producer emits with
    /// `EmptyCertChain` even though the input chain was non-empty.
    #[test]
    fn test_sign_blob_keyless_attaches_cert_chain_to_bundle() {
        let signer = MockSigner::new(canned_signature(), Some("k1".into()));
        let chain: Vec<Vec<u8>> = vec![
            b"leaf-der-bytes".to_vec(),
            b"intermediate-der-bytes".to_vec(),
        ];

        let bundle = sign_blob_keyless(b"payload", "text/plain", &signer, &chain, None).unwrap();

        // Bundle MUST carry the chain we passed in, in source order
        // (leaf at index 0). Anything else means the producer
        // re-ordered or dropped certs.
        let cert = bundle
            .verification_material
            .certificate
            .as_ref()
            .expect("cert chain must be Some");
        assert_eq!(cert.certificates, chain, "chain must round-trip exactly");

        // Wire shape stays a DSSE envelope — keyless attaches a cert
        // chain, it does NOT change the content arm.
        match &bundle.content {
            BundleContent::DsseEnvelope(env) => {
                assert_eq!(env.payload_type, "text/plain");
                assert_eq!(env.payload, b"payload");
            }
            other => panic!("expected DsseEnvelope, got {other:?}"),
        }
        assert_eq!(bundle.media_type, SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE);
    }

    /// Bug it catches: a producer that silently emitted a
    /// structurally-valid bundle whose `certificate.certificates` is
    /// an empty `Vec`. The keyless verifier WOULD eventually reject
    /// it with `EmptyCertChain`, but only after the bundle was
    /// pushed to a registry / sent over the wire / submitted to
    /// Rekor. Catching it at the producer boundary saves a Rekor
    /// submission slot AND surfaces the same typed error name on
    /// both sides of the loop.
    #[test]
    fn test_sign_blob_keyless_rejects_empty_chain() {
        let signer = MockSigner::new(canned_signature(), None);
        let empty: &[Vec<u8>] = &[];

        let err = sign_blob_keyless(b"payload", "text/plain", &signer, empty, None)
            .expect_err("empty cert chain MUST surface a typed error before any signing happens");
        assert!(
            matches!(err, SignError::EmptyCertChain),
            "expected SignError::EmptyCertChain, got {err:?}"
        );
    }

    /// Bug it catches: any drift between producer and verifier wire
    /// shapes — chain ordering, cert byte preservation, DSSE
    /// signature derivation under the leaf key — would fail this
    /// round-trip even though both halves "look right" in isolation.
    /// This is the load-bearing end-to-end smoke that justified
    /// adding the function in the first place: closing the loop
    /// `verify_blob_keyless` left open.
    #[test]
    fn test_sign_blob_keyless_round_trips_through_verify_blob_keyless() {
        let fx = build_keyless_sign_fixture();

        // Re-import the leaf key so the signer owns its own copy.
        // SigningKey is not Clone, so we go through to_bytes →
        // from_bytes — same path keyless_tests uses.
        let leaf_signing_key_clone = KeylessSigningKey::from_bytes(&fx.leaf_signing_key.to_bytes())
            .expect("re-import leaf key");
        let signer = EcdsaP256Signer::new(leaf_signing_key_clone, Some("leaf".into()));

        let payload = b"keyless producer round-trip";
        let bundle = sign_blob_keyless(payload, "text/plain", &signer, &fx.chain_der, None)
            .expect("sign_blob_keyless");

        // Independent verification: the bundle this producer emitted
        // satisfies the keyless verifier when handed the same root
        // anchor that signed the chain.
        verify_blob_keyless(&bundle, std::slice::from_ref(&fx.root_der), None, None)
            .expect("keyless producer + verifier must close the loop");
    }

    /// Bug it catches: a `sign_blob_keyless` impl that constructed
    /// its own bundle from scratch (instead of delegating to
    /// `sign_blob`) and "forgot" to thread the rekor argument. The
    /// resulting bundle would carry the cert chain but no tlog
    /// entries — silently downgrading transparency for every
    /// keyless caller.
    #[test]
    fn test_sign_blob_keyless_with_rekor_attaches_tlog_entry() {
        let signer = MockSigner::new(canned_signature(), None);
        let client = MockRekorClient::new();
        let chain: Vec<Vec<u8>> = vec![b"leaf-der".to_vec()];

        let bundle = sign_blob_keyless(
            b"witnessed keyless payload",
            "text/plain",
            &signer,
            &chain,
            Some(&client),
        )
        .unwrap();

        // tlog entry mirrors what `sign_blob` emits — the keyless
        // path adds a chain on top of, not instead of, transparency.
        // Schema is `dsse` (NOT hashedrekord): DSSE-content bundles
        // ALWAYS use the dsse rekor schema; submitting them via
        // hashedrekord makes production Rekor reject the entry with
        // `invalid signature when validating ASN.1 encoded signature`
        // because hashedrekord verifies `signature == ECDSA(SHA-256(payload))`
        // while DSSE signs the PAE bytes. See issue #39.
        assert_eq!(bundle.verification_material.tlog_entries.len(), 1);
        let tlog = &bundle.verification_material.tlog_entries[0];
        assert_eq!(tlog.log_index, 0);
        assert_eq!(tlog.kind_version.kind, "dsse");
        let proof = tlog.inclusion_proof.as_ref().unwrap();
        assert_eq!(proof.tree_size, 1);

        // Cert chain is still there alongside the tlog.
        let cert = bundle
            .verification_material
            .certificate
            .as_ref()
            .expect("chain must coexist with tlog");
        assert_eq!(cert.certificates, chain);
    }

    /// Bug it catches: a `sign_blob_keyless` that ignored its
    /// `payload_type` argument and hardcoded `text/plain` (or
    /// `application/vnd.in-toto+json`) into the envelope. A keyless
    /// in-toto attestation would then arrive with the wrong wrapper
    /// type — `verify_attestation`'s `WrongPayloadType` gate would
    /// reject it. Pin a non-trivial value here to catch the
    /// regression directly.
    #[test]
    fn test_sign_blob_keyless_payload_type_round_trips() {
        let signer = MockSigner::new(canned_signature(), None);
        let chain: Vec<Vec<u8>> = vec![b"leaf-der".to_vec()];
        let payload_type = "application/vnd.in-toto+json";

        let bundle =
            sign_blob_keyless(b"{\"_type\":\"...\"}", payload_type, &signer, &chain, None).unwrap();

        match &bundle.content {
            BundleContent::DsseEnvelope(env) => {
                assert_eq!(env.payload_type, payload_type);
            }
            other => panic!("expected DsseEnvelope, got {other:?}"),
        }
    }

    /// `sign_blob_keyless` MUST dispatch to `submit_dsse` (the dsse
    /// rekor schema) and NOT to `submit` (the hashedrekord schema).
    ///
    /// Bug it catches: a regression that flips the dispatch back to
    /// `submit` (the hashedrekord path) would silently re-introduce
    /// the bug fixed by issue #39. Production Rekor would resume
    /// rejecting DSSE-content bundles with `invalid signature when
    /// validating ASN.1 encoded signature` — but the bug wouldn't
    /// surface in any unit test that uses a permissive mock client,
    /// because mocks don't enforce signature semantics. This test
    /// pins the dispatch by recording WHICH method the producer
    /// called, irrespective of the mock's tolerance.
    #[test]
    fn test_sign_blob_keyless_dispatches_to_dsse_schema() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct DispatchRecordingClient {
            submit_calls: AtomicUsize,
            submit_dsse_calls: AtomicUsize,
        }
        impl rekor::RekorClient for DispatchRecordingClient {
            fn submit(
                &self,
                _entry: &rekor::HashedRekord,
            ) -> Result<rekor::LogEntry, rekor::RekorError> {
                self.submit_calls.fetch_add(1, Ordering::SeqCst);
                // Return a mock-shape log entry; the test asserts on
                // dispatch counts, not on the entry contents.
                Ok(rekor::LogEntry {
                    uuid: "submit-canary".into(),
                    log_index: 0,
                    tree_size: 1,
                    leaf_hash: [0u8; 32],
                    inclusion_proof: Vec::new(),
                    root_hash: [0u8; 32],
                    body: Vec::new(),
                })
            }
            fn submit_dsse(
                &self,
                _entry: &rekor::DsseRekord,
            ) -> Result<rekor::LogEntry, rekor::RekorError> {
                self.submit_dsse_calls.fetch_add(1, Ordering::SeqCst);
                Ok(rekor::LogEntry {
                    uuid: "submit-dsse-canary".into(),
                    log_index: 0,
                    tree_size: 1,
                    leaf_hash: [0u8; 32],
                    inclusion_proof: Vec::new(),
                    root_hash: [0u8; 32],
                    body: Vec::new(),
                })
            }
        }

        let client = DispatchRecordingClient {
            submit_calls: AtomicUsize::new(0),
            submit_dsse_calls: AtomicUsize::new(0),
        };
        let signer = MockSigner::new(canned_signature(), None);
        let chain: Vec<Vec<u8>> = vec![b"leaf-der".to_vec()];

        let _bundle = sign_blob_keyless(
            b"witnessed payload",
            "text/plain",
            &signer,
            &chain,
            Some(&client),
        )
        .expect("sign_blob_keyless");

        assert_eq!(
            client.submit_dsse_calls.load(Ordering::SeqCst),
            1,
            "sign_blob_keyless must call submit_dsse exactly once"
        );
        assert_eq!(
            client.submit_calls.load(Ordering::SeqCst),
            0,
            "sign_blob_keyless MUST NOT call submit (hashedrekord schema is wrong for DSSE bundles; see issue #39)"
        );
    }

    /// `build_dsse_rekord` produces a [`rekor::DsseRekord`] whose
    /// envelope_bytes round-trip through [`spec::Envelope::decode_json`]
    /// and whose verifier list pins the leaf cert as PEM. Catches
    /// regressions where the envelope-encoder drift breaks the
    /// rekor entry shape silently (e.g. a refactor that base64s the
    /// envelope ahead of time, or that wraps the leaf in DER instead
    /// of PEM).
    #[test]
    fn test_build_dsse_rekord_pins_envelope_and_leaf_pem() {
        let envelope = Envelope {
            payload_type: "text/plain".to_string(),
            payload: b"hello".to_vec(),
            signatures: vec![DsseSignature {
                keyid: None,
                sig: vec![0xAA, 0xBB],
            }],
        };
        let leaf_der = b"this-is-not-real-der-but-tests-the-pem-wrapping".to_vec();

        let entry = build_dsse_rekord(&envelope, &leaf_der).expect("build_dsse_rekord");

        // Envelope round-trips back through the spec decoder.
        let round_tripped =
            spec::Envelope::decode_json(&entry.envelope_bytes).expect("decode envelope");
        assert_eq!(round_tripped, envelope);

        // Single verifier; PEM-wrapped CERTIFICATE block carrying
        // exactly the DER bytes we passed in.
        assert_eq!(entry.verifiers_pem.len(), 1);
        let pem_str = std::str::from_utf8(&entry.verifiers_pem[0]).expect("PEM is UTF-8");
        assert!(pem_str.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem_str.contains("-----END CERTIFICATE-----"));
        let parsed = pem::parse(pem_str).expect("parsable PEM");
        assert_eq!(parsed.tag(), "CERTIFICATE");
        assert_eq!(parsed.contents(), leaf_der);
    }
}

// =====================================================================
// Multi-algorithm signer / verifier tests (issue #12).
//
// One module per algorithm, each gated behind the same feature flag
// that pulls the algorithm's RustCrypto crate in. Each module pins
// THREE properties:
//
// * Constructor + `key_id()` smoke — the signer holds the optional
//   key_id verbatim and surfaces it through the trait method.
//   Catches regressions where `Signer::key_id` returned `None`
//   unconditionally, or returned a clone of a different field.
//
// * Round-trip — `sign_blob` with the algorithm's signer, then
//   `verify_blob` with `VerifyingKey::<Algo>(...)` succeeds. Catches
//   sig-shape regressions (e.g. an Ed25519 signer that returned DER,
//   or a P-384 signer that returned raw r||s).
//
// * Cross-algorithm rejection — sign with algorithm A, hand the
//   bundle to a verifier wired with `VerifyingKey::<B>(...)`, expect
//   `SignatureInvalid`. THIS is the load-bearing test: it catches a
//   regression in `try_verify`'s match dispatch where a wrong arm
//   would silently accept a signature meant for a different
//   algorithm — the worst possible failure mode for a multi-algo
//   verifier.
//
// Tests live OUTSIDE the existing `mod tests` so the `cfg(feature)`
// gates are clean (each module only compiles when its feature is
// enabled — no nested `cfg` inside an unrelated module).
// =====================================================================

#[cfg(all(test, feature = "ed25519"))]
mod ed25519_tests {
    use super::*;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    /// Deterministic signing key. Ed25519 derives a 32-byte
    /// secret-scalar seed, hashes it through SHA-512 to get the
    /// real signing scalar — a fixed seed is enough for round-trip
    /// tests without dragging a real RNG into the suite.
    fn ed25519_signing_key() -> Ed25519SigningKey {
        let mut rng = ChaCha20Rng::from_seed([0xE0; 32]);
        Ed25519SigningKey::generate(&mut rng)
    }

    /// Bug it catches: an `Ed25519Signer::new` impl that swapped
    /// the `key_id` argument for some other field (e.g. derived a
    /// hex-encoded public key) would surface here as a non-equal
    /// `key_id()` return. Also catches `Signer::key_id` regressions
    /// where the trait method returned `None` unconditionally.
    #[test]
    fn test_ed25519_signer_constructor_and_key_id_round_trip() {
        let key = ed25519_signing_key();
        let signer = Ed25519Signer::new(key, Some("ed-key-1".into()));
        assert_eq!(signer.key_id(), Some("ed-key-1".into()));

        // Re-construct with no key_id to pin the negative case.
        let key2 = ed25519_signing_key();
        let signer_anon = Ed25519Signer::new(key2, None);
        assert_eq!(signer_anon.key_id(), None);
    }

    /// Bug it catches: an Ed25519 signer that returned DER-encoded
    /// bytes (instead of raw 64-byte `r||s`) would fail
    /// `Signature::from_slice`'s strict-length check on the
    /// verifier side. Symmetric: a verifier dispatching Ed25519 to
    /// `Signature::from_der` would never accept a real Ed25519
    /// signature. Round-trip nails both regressions.
    #[test]
    fn test_ed25519_sign_blob_round_trips_through_verify_blob() {
        let key = ed25519_signing_key();
        let vk = VerifyingKey::Ed25519(key.verifying_key());
        let signer = Ed25519Signer::new(key, Some("ed-rt".into()));

        let bundle = sign_blob(b"ed25519 payload", "text/plain", &signer, None).unwrap();
        verify_blob(&bundle, &[vk], None).expect("ed25519 round-trip must verify");
    }

    /// Bug it catches: a regression in the `try_verify` match where
    /// `VerifyingKey::Ed25519` accidentally tried to parse the
    /// signature bytes as DER (or routed to the P-256 arm). The
    /// signer signs Ed25519, the verifier holds a P-256 key —
    /// expectation is `SignatureInvalid`. A test that "passes" here
    /// when it shouldn't would mean the dispatch is mis-routing
    /// algorithms at runtime — the single worst bug a multi-algo
    /// verifier can ship.
    #[test]
    fn test_ed25519_signed_bundle_rejected_by_p256_verifier() {
        let key = ed25519_signing_key();
        let signer = Ed25519Signer::new(key, Some("ed-x".into()));

        let bundle = sign_blob(b"cross-reject", "text/plain", &signer, None).unwrap();

        // Build an unrelated P-256 verifying key. The signer used
        // Ed25519, so this MUST reject.
        let mut rng = ChaCha20Rng::from_seed([0xE1; 32]);
        let p256_sk = p256::ecdsa::SigningKey::random(&mut rng);
        let p256_vk = VerifyingKey::P256(*p256_sk.verifying_key());

        let err = verify_blob(&bundle, &[p256_vk], None)
            .expect_err("ed25519-signed bundle MUST NOT verify under a P-256 trusted key");
        assert!(
            matches!(err, VerifyError::SignatureInvalid { .. }),
            "expected SignatureInvalid, got {err:?}"
        );
    }
}

#[cfg(all(test, feature = "ecdsa-p384"))]
mod p384_tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn p384_signing_key() -> p384::ecdsa::SigningKey {
        let mut rng = ChaCha20Rng::from_seed([0xF0; 32]);
        p384::ecdsa::SigningKey::random(&mut rng)
    }

    /// Bug it catches: same class as the P-256 / Ed25519
    /// constructor smoke — a `key_id` plumbed through wrongly
    /// would surface here. Distinct test per algorithm because
    /// the construction site is per-type (separate impls).
    #[test]
    fn test_p384_signer_constructor_and_key_id_round_trip() {
        let key = p384_signing_key();
        let signer = EcdsaP384Signer::new(key, Some("p384-key-1".into()));
        assert_eq!(signer.key_id(), Some("p384-key-1".into()));

        let key2 = p384_signing_key();
        let signer_anon = EcdsaP384Signer::new(key2, None);
        assert_eq!(signer_anon.key_id(), None);
    }

    /// Bug it catches: a P-384 signer that ran SHA-256 (P-256's
    /// digest) instead of SHA-384 would mis-hash the PAE — the
    /// verifier side runs SHA-384 internally, so the signature
    /// would never reconstruct. Round-trip is the load-bearing
    /// signal that the curve / digest pair is correctly wired.
    #[test]
    fn test_p384_sign_blob_round_trips_through_verify_blob() {
        let key = p384_signing_key();
        let vk = VerifyingKey::P384(*key.verifying_key());
        let signer = EcdsaP384Signer::new(key, Some("p384-rt".into()));

        let bundle = sign_blob(b"p384 payload", "text/plain", &signer, None).unwrap();
        verify_blob(&bundle, &[vk], None).expect("p384 round-trip must verify");
    }

    /// Bug it catches: a `try_verify` regression that routed
    /// `VerifyingKey::P384` through the P-256 arm would happen to
    /// accept some signatures (DER decode succeeds) but verify
    /// against the WRONG curve. Sign with P-384, verify with a
    /// P-256 trusted key — must reject as `SignatureInvalid`.
    #[test]
    fn test_p384_signed_bundle_rejected_by_p256_verifier() {
        let key = p384_signing_key();
        let signer = EcdsaP384Signer::new(key, Some("p384-x".into()));

        let bundle = sign_blob(b"cross-reject", "text/plain", &signer, None).unwrap();

        let mut rng = ChaCha20Rng::from_seed([0xF1; 32]);
        let p256_sk = p256::ecdsa::SigningKey::random(&mut rng);
        let p256_vk = VerifyingKey::P256(*p256_sk.verifying_key());

        let err = verify_blob(&bundle, &[p256_vk], None)
            .expect_err("p384-signed bundle MUST NOT verify under a P-256 trusted key");
        assert!(
            matches!(err, VerifyError::SignatureInvalid { .. }),
            "expected SignatureInvalid, got {err:?}"
        );
    }
}

#[cfg(all(test, feature = "secp256k1"))]
mod k256_tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn k256_signing_key() -> k256::ecdsa::SigningKey {
        let mut rng = ChaCha20Rng::from_seed([0x6C; 32]);
        k256::ecdsa::SigningKey::random(&mut rng)
    }

    /// Bug it catches: a `Secp256k1Signer::new` whose `key_id`
    /// plumbing got silently dropped (e.g. constructor took the
    /// argument but didn't store it). Same shape as the other
    /// algorithms' constructor smokes, repeated because the
    /// construction site is per-type.
    #[test]
    fn test_secp256k1_signer_constructor_and_key_id_round_trip() {
        let key = k256_signing_key();
        let signer = Secp256k1Signer::new(key, Some("k256-key-1".into()));
        assert_eq!(signer.key_id(), Some("k256-key-1".into()));

        let key2 = k256_signing_key();
        let signer_anon = Secp256k1Signer::new(key2, None);
        assert_eq!(signer_anon.key_id(), None);
    }

    /// Bug it catches: secp256k1 and P-256 both run SHA-256 over
    /// the input AND emit DER signatures of the same shape — so
    /// a verifier that mixed up the curve at the math layer
    /// (verifying secp256k1 sigs against a P-256 base point) would
    /// silently fail every signature even though the wire bytes
    /// look identical to the P-256 path. The round-trip pins the
    /// curve binding correctly.
    #[test]
    fn test_secp256k1_sign_blob_round_trips_through_verify_blob() {
        let key = k256_signing_key();
        let vk = VerifyingKey::K256(*key.verifying_key());
        let signer = Secp256k1Signer::new(key, Some("k256-rt".into()));

        let bundle = sign_blob(b"secp256k1 payload", "text/plain", &signer, None).unwrap();
        verify_blob(&bundle, &[vk], None).expect("secp256k1 round-trip must verify");
    }

    /// Bug it catches: this is the most insidious cross-rejection
    /// case in the suite — secp256k1 and P-256 share their
    /// SHA-256 digest AND DER signature wire shape. A `try_verify`
    /// regression that routed `VerifyingKey::K256` through the
    /// P-256 arm would happily DER-decode the signature and then
    /// run the verify against the wrong base point. Most signatures
    /// would still fail (different curve), but the "happens to
    /// validate" failure mode is non-zero. Pinning rejection here
    /// keeps the dispatch honest.
    #[test]
    fn test_secp256k1_signed_bundle_rejected_by_p256_verifier() {
        let key = k256_signing_key();
        let signer = Secp256k1Signer::new(key, Some("k256-x".into()));

        let bundle = sign_blob(b"cross-reject", "text/plain", &signer, None).unwrap();

        let mut rng = ChaCha20Rng::from_seed([0x6D; 32]);
        let p256_sk = p256::ecdsa::SigningKey::random(&mut rng);
        let p256_vk = VerifyingKey::P256(*p256_sk.verifying_key());

        let err = verify_blob(&bundle, &[p256_vk], None)
            .expect_err("secp256k1-signed bundle MUST NOT verify under a P-256 trusted key");
        assert!(
            matches!(err, VerifyError::SignatureInvalid { .. }),
            "expected SignatureInvalid, got {err:?}"
        );
    }
}
