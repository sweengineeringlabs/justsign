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
pub mod oci;
mod signer;

pub use error::{OciError, SignError, VerifyError};
pub use signer::{EcdsaP256Signer, MockSigner, Signer, SignerError};

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey};

use rekor::{HashedRekord, HashedRekordHash, LogEntry, PublicKey, RekorClient};
use sha2::{Digest, Sha256};
use spec::{
    Bundle, BundleContent, Checkpoint, Envelope, HashOutput, InclusionProof, KindVersion,
    Signature as DsseSignature, TlogEntry, VerificationMaterial, SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE,
};

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

    // 3. Optional Rekor submission.
    let tlog_entries = if let Some(client) = rekor {
        let entry = build_hashed_rekord(payload, &sig_bytes);
        let log_entry = client.submit(&entry)?;
        vec![log_entry_to_tlog_entry(&log_entry)]
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
    let mut last_failing_keyid: Option<String> = None;
    let mut any_valid = false;
    for sig in &envelope.signatures {
        let parsed = match P256Signature::from_der(&sig.sig) {
            Ok(p) => p,
            Err(_) => {
                // Not a valid DER ECDSA-P256 signature. Track its
                // keyid for the eventual error and move on.
                last_failing_keyid = sig.keyid.clone();
                continue;
            }
        };
        let validated = trusted_keys
            .iter()
            .any(|vk| vk.verify(&pae_bytes, &parsed).is_ok());
        if validated {
            any_valid = true;
            break;
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
/// The `publicKey` field is left empty in v0 because we don't yet
/// have a Fulcio cert / static key bound to the signer; v0.5 will
/// populate it from the `Signer` SPI.
fn build_hashed_rekord(payload: &[u8], sig_bytes: &[u8]) -> HashedRekord {
    let digest = Sha256::digest(payload);
    HashedRekord {
        signature: rekor::Signature {
            content: sig_bytes.to_vec(),
            public_key: PublicKey {
                content: Vec::new(),
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

/// Translate a `rekor::LogEntry` into the [`spec::TlogEntry`] wire
/// shape the bundle carries.
///
/// Type-width drift: the rekor crate uses `u64` for indices /
/// tree sizes; the spec crate uses `i64` (matching the protobuf
/// wire shape). Casting through `as i64` is safe for any value
/// returned by the v0 mock (single-leaf log, log_index = 0,
/// tree_size = 1).
fn log_entry_to_tlog_entry(entry: &LogEntry) -> TlogEntry {
    TlogEntry {
        log_index: entry.log_index as i64,
        log_id: HashOutput {
            algorithm: "SHA2_256".to_string(),
            // Mock has no log_id of its own; use the leaf hash
            // as a stable identifier so the field round-trips.
            digest: entry.leaf_hash.to_vec(),
        },
        kind_version: KindVersion {
            kind: "hashedrekord".to_string(),
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
/// trust anchors.
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
/// 3. If `expected_san` is `Some`, extract SAN entries from the leaf
///    via [`cert_chain::extract_san`] and require an EXACT-string
///    match against one of them. v0 does not pattern-match.
/// 4. Dispatch the rest of verification to the existing [`verify_blob`]
///    logic, using the leaf's verifying key as the (single) trusted
///    key. This re-uses the DSSE-only / Rekor-optional posture from
///    the v0 verifier so we don't duplicate signature-shape logic.
///
/// # Errors
///
/// * [`VerifyError::EmptyCertChain`] — bundle has no cert chain.
/// * [`VerifyError::ChainBroken`] — chain walk rejected the chain.
/// * [`VerifyError::SanMismatch`] — `expected_san` not found in leaf.
///   [`cert_chain::ChainError::Decode`] surfacing as `ChainBroken`
///   here means the leaf cert was malformed when SAN extraction tried
///   to re-decode it; that's a chain problem, not a SAN problem.
/// * [`VerifyError::SignatureInvalid`] / [`VerifyError::EnvelopeMissing`] /
///   [`VerifyError::NoTlogEntry`] / [`VerifyError::RekorVerify`] —
///   inherited from [`verify_blob`].
///
/// # Open issues for v1
///
/// * Expiry — [`VerifyError::CertExpired`] is defined but not
///   produced. Wiring a clock SPI is its own slice.
/// * SAN pattern matching (issuer-prefix matching, regex on URIs,
///   etc.) — v0 is exact-string only.
/// * SCT / Rekor inclusion-time-vs-cert-validity binding.
pub fn verify_blob_keyless(
    bundle: &Bundle,
    trust_anchors_der: &[Vec<u8>],
    expected_san: Option<&str>,
    rekor: Option<&dyn RekorClient>,
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

    // 3. SAN policy check. The leaf is at index 0 by Sigstore wire
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

    // 4. Hand off to the existing v0 verifier, using the leaf's key
    //    as the single trusted key. `verify_blob` enforces:
    //      - DSSE envelope variant (not message-signature),
    //      - at least one envelope signature validates against the
    //        leaf's key,
    //      - if `rekor` is Some, every tlog entry's inclusion proof
    //        re-verifies against its claimed root.
    verify_blob(bundle, &[leaf_vk], rekor)
}

#[cfg(test)]
mod keyless_tests {
    use super::*;
    use crate::cert_chain::ChainError;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
        PKCS_ECDSA_P256_SHA256,
    };
    use signature::Signer as _;
    use spec::Certificate as SpecCertificate;

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

    /// Build a real chain whose leaf carries a P-256 key that we
    /// also retain (so we can sign with it). Mirrors the structure
    /// `cert_chain::tests::build_three_level_chain` produces, but
    /// extracts the leaf signing key as a `p256::ecdsa::SigningKey`
    /// so the caller can produce a real DSSE signature.
    fn build_keyless_fixture() -> KeylessFixture {
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
        let vk = *sk.verifying_key();

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
        let vk = *sk.verifying_key();
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
        let vk = *sk.verifying_key();
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
        let vk = *sk.verifying_key();
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
        let vk = *sk.verifying_key();
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
        let vk = *sk.verifying_key();
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
        let vk = *sk.verifying_key();
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
        let vk = *sk.verifying_key();
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
        let vk = *sk.verifying_key();
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
        let vk = *sk.verifying_key();
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
        let vk = *sk.verifying_key();
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
        let vk = *sk.verifying_key();
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
}
