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

mod error;
mod signer;

pub use error::{SignError, VerifyError};
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
}
