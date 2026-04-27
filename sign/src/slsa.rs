//! SLSA Provenance v1 attestation — convenience wrappers.
//!
//! Thin layer over [`crate::attest`] / [`crate::verify_attestation`]:
//! the spec crate already carries the typed predicate shape
//! ([`spec::SlsaProvenanceV1`]), so this module's job is just to
//! route a typed predicate through the v0 attestation surface
//! without the caller hand-rolling the `predicateType` URI or the
//! `serde_json::Value` round-trip.
//!
//! Surface:
//!
//! * [`sign_slsa_provenance`] — sign convenience.
//! * [`verify_slsa_provenance`] — verify convenience, returns the
//!   typed predicate alongside the verified subjects.
//! * [`VerifiedSlsaProvenance`] — output of `verify_slsa_provenance`,
//!   symmetric to [`crate::VerifiedAttestation`] but typed on the
//!   SLSA predicate.
//!
//! The `SLSA_PROVENANCE_V1_PREDICATE_TYPE` constant is re-exported
//! here so callers don't have to reach into the spec crate just to
//! pass the predicate-type URI through.

use rekor::RekorClient;
use spec::{Bundle, Subject};

use spec::SlsaProvenanceV1;
pub use spec::SLSA_PROVENANCE_V1_PREDICATE_TYPE;

use p256::ecdsa::VerifyingKey;

use crate::{attest, verify_attestation, SignError, Signer, VerifyError};

/// Result of [`verify_slsa_provenance`] — the typed predicate plus
/// the subjects the Statement names.
///
/// Symmetric to [`crate::VerifiedAttestation`] but with a parsed
/// [`SlsaProvenanceV1`] in place of the opaque `serde_json::Value`,
/// so callers can act on `build_definition` / `run_details` without
/// re-parsing.
///
/// `predicate_type` is intentionally NOT carried here: by definition
/// of this function, it equals [`SLSA_PROVENANCE_V1_PREDICATE_TYPE`]
/// — there's no value in returning a constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSlsaProvenance {
    /// Subjects the Statement makes claims about. Order is preserved
    /// from the wire form, matching [`crate::VerifiedAttestation`].
    pub subjects: Vec<Subject>,

    /// Decoded SLSA Provenance v1 predicate.
    pub provenance: SlsaProvenanceV1,
}

/// Build a SLSA Provenance v1 attestation about
/// `(subject_name, subject_digest_algo, subject_digest_hex)` and
/// sign it.
///
/// Wraps [`crate::attest`]:
///
/// 1. Serialise `provenance` to a `serde_json::Value`.
/// 2. Hand it to `attest` with `predicate_type =
///    "https://slsa.dev/provenance/v1"`.
/// 3. Return the resulting [`spec::Bundle`].
///
/// Errors surface via [`SignError`] — same surface as `attest`.
///
/// On the predicate-encode step: serialising a `SlsaProvenanceV1`
/// to a `Value` via the derived `Serialize` impl cannot fail under
/// any safe construction (`serde_json::to_value` only errors when a
/// custom `Serialize` impl is broken or contains a non-UTF-8
/// `String`, neither of which the spec crate's safe API permits).
/// We surface the error anyway via `SignError::StatementEncode` so
/// the caller's error-routing code stays uniform — and so a future
/// change that DOES introduce a fallible field (e.g. a custom
/// timestamp serializer) doesn't silently start panicking.
pub fn sign_slsa_provenance(
    subject_name: &str,
    subject_digest_algo: &str,
    subject_digest_hex: &str,
    provenance: &SlsaProvenanceV1,
    signer: &dyn Signer,
    rekor: Option<&dyn RekorClient>,
) -> Result<Bundle, SignError> {
    // Encode the typed predicate to a `serde_json::Value`. Failure
    // here would mean the predicate's safe-API invariants were
    // violated; we surface it via the existing `StatementEncode`
    // variant rather than panicking, so the error path stays typed
    // for the caller.
    let predicate_value = provenance.encode_json().map_err(|e| {
        // `serde_json::Error` lifts into `StatementEncodeError::Json`
        // via `#[from]`, and `StatementEncodeError` lifts into
        // `SignError::StatementEncode` via `#[from]`. Build it the
        // same way `Statement::encode_json` does.
        SignError::StatementEncode(spec::StatementEncodeError::Json(e))
    })?;

    attest(
        subject_name,
        subject_digest_algo,
        subject_digest_hex,
        SLSA_PROVENANCE_V1_PREDICATE_TYPE,
        predicate_value,
        signer,
        rekor,
    )
}

/// Verify a Sigstore [`spec::Bundle`] previously produced by
/// [`sign_slsa_provenance`] (or any compatible signer).
///
/// Pipeline:
///
/// 1. Run [`crate::verify_attestation`] with
///    `expected_predicate_type =
///    "https://slsa.dev/provenance/v1"`. This enforces, in order:
///    DSSE signature against `trusted_keys`, optional Rekor
///    inclusion proof, in-toto Statement decode, predicate-type
///    match, and (if `expected_subject_digest = Some`) subject-
///    digest match.
/// 2. Decode the returned `serde_json::Value` predicate into a
///    typed [`SlsaProvenanceV1`].
///
/// Step 2 only runs after step 1 succeeds, so a malformed predicate
/// inside a wrong-key bundle surfaces as `SignatureInvalid` —
/// fail-fast on the cheaper check.
///
/// Errors:
///
/// * Anything [`crate::verify_attestation`] surfaces — including
///   [`VerifyError::WrongPredicateType`] when the bundle's
///   predicate isn't SLSA-v1.
/// * [`VerifyError::StatementDecode`] when the predicate body is
///   shaped wrong for SLSA-v1 (missing `buildDefinition`,
///   `runDetails`, etc.) — held under the existing
///   `StatementDecode` variant since `serde_json::Error` lifts via
///   `StatementDecodeError::Json` and the spec crate already
///   exposes that lift.
pub fn verify_slsa_provenance(
    bundle: &Bundle,
    trusted_keys: &[VerifyingKey],
    expected_subject_digest: Option<(&str, &str)>,
    rekor: Option<&dyn RekorClient>,
) -> Result<VerifiedSlsaProvenance, VerifyError> {
    let verified = verify_attestation(
        bundle,
        trusted_keys,
        SLSA_PROVENANCE_V1_PREDICATE_TYPE,
        expected_subject_digest,
        rekor,
    )?;

    // Decode the predicate `Value` into the typed shape. A
    // malformed body (missing `runDetails`, wrong field type, etc.)
    // surfaces via `StatementDecode` — we route it through the
    // existing variant rather than minting a new one because the
    // failure category is the same: "Statement payload decoded but
    // its inner shape is wrong for the predicate type we expected".
    let provenance: SlsaProvenanceV1 = serde_json::from_value(verified.predicate)
        .map_err(|e| VerifyError::StatementDecode(spec::StatementDecodeError::Json(e)))?;

    Ok(VerifiedSlsaProvenance {
        subjects: verified.subjects,
        provenance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sign_blob, EcdsaP256Signer, IN_TOTO_PAYLOAD_TYPE};
    use p256::ecdsa::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use rekor::MockRekorClient;
    use serde_json::json;
    use spec::{
        BuildDefinition, BuildMetadata, Builder, BundleContent, ResourceDescriptor, RunDetails,
        Statement, Subject as SpecSubject, IN_TOTO_STATEMENT_V1_TYPE,
    };
    use std::collections::BTreeMap;

    /// Sample subject identifiers reused across tests — the digest
    /// is sha256-shaped (64 lowercase hex chars) but unrelated to
    /// the bytes signed; Statement validation does not recompute it.
    const SUBJECT_NAME: &str = "pkg:oci/example@sha256:abc";
    const SUBJECT_DIGEST_ALGO: &str = "sha256";
    const SUBJECT_DIGEST_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_DIGEST_HEX: &str =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// Build a representative SLSA Provenance v1 predicate (every
    /// field populated at least once) for round-trip tests.
    fn sample_provenance() -> SlsaProvenanceV1 {
        let mut digest = BTreeMap::new();
        digest.insert("gitCommit".to_string(), "deadbeef".to_string());
        let mut version = BTreeMap::new();
        version.insert("runner".to_string(), "2.317.0".to_string());

        SlsaProvenanceV1 {
            build_definition: BuildDefinition {
                build_type: "https://example.com/build/v1".to_string(),
                external_parameters: json!({ "ref": "refs/heads/main" }),
                internal_parameters: Some(json!({ "runner_pool": "ubuntu-22.04" })),
                resolved_dependencies: vec![ResourceDescriptor {
                    name: Some("source".to_string()),
                    uri: Some("git+https://github.com/example/repo".to_string()),
                    digest,
                    content: None,
                    download_location: None,
                    media_type: None,
                    annotations: None,
                }],
            },
            run_details: RunDetails {
                builder: Builder {
                    id: "https://github.com/actions/runner".to_string(),
                    version,
                    builder_dependencies: vec![],
                },
                metadata: Some(BuildMetadata {
                    invocation_id: Some("inv-1".to_string()),
                    started_on: Some("2024-01-01T00:00:00Z".to_string()),
                    finished_on: Some("2024-01-01T00:05:00Z".to_string()),
                }),
                byproducts: vec![],
            },
        }
    }

    /// `sign_slsa_provenance` followed by `verify_slsa_provenance`
    /// reconstructs the exact predicate and subject the signer
    /// supplied — including every nested ResourceDescriptor /
    /// BuildMetadata field.
    ///
    /// Bug it catches: any drift between the encoder used by
    /// `sign_slsa_provenance` (serialise → attest) and the decoder
    /// used by `verify_slsa_provenance` (verify_attestation → from_value)
    /// — e.g. a missing `rename_all = "camelCase"` on an inner
    /// SLSA struct — would surface as a Statement-decode error or
    /// an inequality on the returned `provenance`.
    #[test]
    fn test_sign_then_verify_slsa_provenance_round_trips_typed_predicate() {
        let mut rng = ChaCha20Rng::from_seed([0xB0; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = *sk.verifying_key();
        let signer = EcdsaP256Signer::new(sk, Some("slsa-key".into()));

        let original = sample_provenance();

        let bundle = sign_slsa_provenance(
            SUBJECT_NAME,
            SUBJECT_DIGEST_ALGO,
            SUBJECT_DIGEST_HEX,
            &original,
            &signer,
            None,
        )
        .unwrap();

        // Bundle wraps an in-toto payload, not text/plain.
        if let BundleContent::DsseEnvelope(env) = &bundle.content {
            assert_eq!(env.payload_type, IN_TOTO_PAYLOAD_TYPE);
        } else {
            panic!("expected DSSE envelope content");
        }

        let verified = verify_slsa_provenance(
            &bundle,
            &[vk],
            Some((SUBJECT_DIGEST_ALGO, SUBJECT_DIGEST_HEX)),
            None,
        )
        .unwrap();

        assert_eq!(verified.provenance, original);
        assert_eq!(verified.subjects.len(), 1);
        assert_eq!(verified.subjects[0].name, SUBJECT_NAME);
        assert_eq!(
            verified.subjects[0].digest.get(SUBJECT_DIGEST_ALGO),
            Some(&SUBJECT_DIGEST_HEX.to_string())
        );
    }

    /// Verifying a NON-SLSA attestation (predicate type SPDX, but
    /// otherwise valid) with `verify_slsa_provenance` surfaces
    /// `WrongPredicateType` — even when the signature, payload type,
    /// and subject all match.
    ///
    /// Bug it catches: a `verify_slsa_provenance` that forgot to
    /// wire the `expected_predicate_type` constant through (e.g.
    /// passed an empty string, or accidentally allowed any
    /// predicate type) would happily return success on an SPDX SBOM
    /// where a SLSA Provenance was required.
    #[test]
    fn test_verify_slsa_provenance_rejects_non_slsa_predicate_type() {
        let mut rng = ChaCha20Rng::from_seed([0xB1; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = *sk.verifying_key();
        let signer = EcdsaP256Signer::new(sk, None);

        // Sign with an SPDX-typed predicate via the lower-level
        // `attest`. Same DSSE wrapping, different predicateType.
        let bundle = attest(
            SUBJECT_NAME,
            SUBJECT_DIGEST_ALGO,
            SUBJECT_DIGEST_HEX,
            "https://spdx.dev/Document",
            json!({ "spdxVersion": "SPDX-2.3" }),
            &signer,
            None,
        )
        .unwrap();

        let err = verify_slsa_provenance(&bundle, &[vk], None, None).unwrap_err();
        match err {
            VerifyError::WrongPredicateType { expected, found } => {
                assert_eq!(expected, SLSA_PROVENANCE_V1_PREDICATE_TYPE);
                assert_eq!(found, "https://spdx.dev/Document");
            }
            other => panic!("expected WrongPredicateType, got {other:?}"),
        }
    }

    /// `verify_slsa_provenance` on a bundle whose DSSE signature
    /// doesn't validate against any trusted key surfaces
    /// `SignatureInvalid` — fail-fast BEFORE any predicate decode.
    ///
    /// Bug it catches: a `verify_slsa_provenance` that decoded the
    /// predicate first (and only later checked the signature) would
    /// emit a misleading "predicate decode" error on an
    /// untrusted-but-otherwise-shaped-correctly bundle. Worse, an
    /// implementation that NEVER ran the signature check would
    /// silently accept attacker-supplied SLSA predicates.
    #[test]
    fn test_verify_slsa_provenance_rejects_bundle_with_invalid_signature() {
        let mut rng_signer = ChaCha20Rng::from_seed([0xB2; 32]);
        let signer_sk = SigningKey::random(&mut rng_signer);
        let signer = EcdsaP256Signer::new(signer_sk, None);

        // Trusted key is COMPLETELY unrelated to the signing key —
        // signature MUST fail to verify under it.
        let mut rng_trust = ChaCha20Rng::from_seed([0xB3; 32]);
        let trust_sk = SigningKey::random(&mut rng_trust);
        let trust_vk = *trust_sk.verifying_key();

        let bundle = sign_slsa_provenance(
            SUBJECT_NAME,
            SUBJECT_DIGEST_ALGO,
            SUBJECT_DIGEST_HEX,
            &sample_provenance(),
            &signer,
            None,
        )
        .unwrap();

        let err = verify_slsa_provenance(&bundle, &[trust_vk], None, None).unwrap_err();
        assert!(
            matches!(err, VerifyError::SignatureInvalid { .. }),
            "expected SignatureInvalid, got {err:?}"
        );
    }

    /// A Statement whose `predicateType` IS
    /// `https://slsa.dev/provenance/v1` but whose `predicate` body
    /// is NOT shaped like SLSA Provenance v1 (e.g. random JSON)
    /// surfaces `StatementDecode` from `verify_slsa_provenance`.
    ///
    /// Bug it catches: a `verify_slsa_provenance` that handed the
    /// predicate `Value` back to the caller without typed decoding
    /// would force every consumer to re-decode it themselves —
    /// missing the point of the typed wrapper. A wrapper that
    /// `unwrap()`ed the decode would panic on a real
    /// non-SLSA-shaped predicate (an attacker-injected payload that
    /// claims SLSA but isn't), turning a typed verification error
    /// into a process kill.
    #[test]
    fn test_verify_slsa_provenance_rejects_malformed_predicate_body() {
        // Hand-build a Statement with the SLSA predicate-type URI
        // but a junk predicate body, sign the resulting payload via
        // `sign_blob` so the DSSE signature is valid.
        let mut rng = ChaCha20Rng::from_seed([0xB4; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = *sk.verifying_key();
        let signer = EcdsaP256Signer::new(sk, None);

        let mut digest = BTreeMap::new();
        digest.insert(
            SUBJECT_DIGEST_ALGO.to_string(),
            SUBJECT_DIGEST_HEX.to_string(),
        );
        let stmt = Statement {
            _type: IN_TOTO_STATEMENT_V1_TYPE.to_string(),
            subject: vec![SpecSubject {
                name: SUBJECT_NAME.to_string(),
                digest,
            }],
            predicate_type: SLSA_PROVENANCE_V1_PREDICATE_TYPE.to_string(),
            // Predicate is valid JSON but missing `buildDefinition`
            // and `runDetails` — fails SLSA structural shape check.
            predicate: json!({ "totally": "wrong shape" }),
        };
        let payload = stmt.encode_json().unwrap();

        let bundle = sign_blob(&payload, IN_TOTO_PAYLOAD_TYPE, &signer, None).unwrap();

        let err = verify_slsa_provenance(&bundle, &[vk], None, None).unwrap_err();
        assert!(
            matches!(err, VerifyError::StatementDecode(_)),
            "expected StatementDecode for malformed SLSA predicate body, got {err:?}"
        );
    }

    /// `verify_slsa_provenance` with `expected_subject_digest =
    /// Some(...)` REJECTS a bundle whose subject digest doesn't
    /// match, and ACCEPTS the same bundle with `None` (i.e. caller
    /// not pinning a subject).
    ///
    /// Bug it catches: a wrapper that ignored
    /// `expected_subject_digest` (e.g. always passed `None` through
    /// to `verify_attestation`) would silently let an attacker
    /// reuse a SLSA bundle attesting artifact A as proof for
    /// artifact B. A wrapper that defaulted `None` to a "must match
    /// nothing" semantic (returning `SubjectMismatch` even when
    /// the caller passed `None`) would force callers to always pin
    /// a digest.
    #[test]
    fn test_verify_slsa_provenance_subject_digest_gate_routes_correctly() {
        let mut rng = ChaCha20Rng::from_seed([0xB5; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = *sk.verifying_key();
        let signer = EcdsaP256Signer::new(sk, None);

        let bundle = sign_slsa_provenance(
            SUBJECT_NAME,
            SUBJECT_DIGEST_ALGO,
            SUBJECT_DIGEST_HEX,
            &sample_provenance(),
            &signer,
            None,
        )
        .unwrap();

        // Pinning the wrong digest must reject.
        let err = verify_slsa_provenance(
            &bundle,
            &[vk],
            Some((SUBJECT_DIGEST_ALGO, OTHER_DIGEST_HEX)),
            None,
        )
        .unwrap_err();
        match err {
            VerifyError::SubjectMismatch { expected_digest } => {
                assert_eq!(
                    expected_digest,
                    format!("{SUBJECT_DIGEST_ALGO}:{OTHER_DIGEST_HEX}")
                );
            }
            other => panic!("expected SubjectMismatch, got {other:?}"),
        }

        // Passing `None` for the expected digest must skip the
        // subject check entirely.
        let verified = verify_slsa_provenance(&bundle, &[vk], None, None)
            .expect("None subject_digest must skip the subject check");
        assert_eq!(verified.subjects.len(), 1);
        assert_eq!(verified.provenance, sample_provenance());
    }

    /// `sign_slsa_provenance` with a Rekor client embeds exactly
    /// one `tlog_entries` entry, and the matching
    /// `verify_slsa_provenance` re-runs the inclusion proof
    /// successfully.
    ///
    /// Bug it catches: a `sign_slsa_provenance` that dropped the
    /// rekor argument on the way through (e.g. shadowed by a local
    /// `let rekor = None;`) would emit an unwitnessed bundle even
    /// when the caller asked for transparency. A
    /// `verify_slsa_provenance` that dropped its rekor argument
    /// would silently skip the inclusion-proof check.
    #[test]
    fn test_sign_and_verify_slsa_provenance_with_rekor_witnesses_end_to_end() {
        let mut rng = ChaCha20Rng::from_seed([0xB6; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = *sk.verifying_key();
        let signer = EcdsaP256Signer::new(sk, None);
        let client = MockRekorClient::new();

        let bundle = sign_slsa_provenance(
            SUBJECT_NAME,
            SUBJECT_DIGEST_ALGO,
            SUBJECT_DIGEST_HEX,
            &sample_provenance(),
            &signer,
            Some(&client),
        )
        .unwrap();

        assert_eq!(bundle.verification_material.tlog_entries.len(), 1);
        assert_eq!(
            bundle.verification_material.tlog_entries[0]
                .kind_version
                .kind,
            "hashedrekord"
        );

        let verified = verify_slsa_provenance(
            &bundle,
            &[vk],
            Some((SUBJECT_DIGEST_ALGO, SUBJECT_DIGEST_HEX)),
            Some(&client),
        )
        .expect("witnessed SLSA bundle must verify end-to-end");

        assert_eq!(verified.provenance, sample_provenance());
    }

    /// `verify_slsa_provenance` rejects a bundle whose DSSE
    /// `payload_type` is NOT `application/vnd.in-toto+json` —
    /// inheriting the `WrongPayloadType` gate from
    /// `verify_attestation`.
    ///
    /// Bug it catches: a wrapper that forwarded everything to
    /// `verify_attestation` correctly but ALSO accepted any
    /// payload type (e.g. by stripping the gate) would let a
    /// `text/plain` blob whose body happens to be SLSA-shaped JSON
    /// pass as a SLSA attestation — exactly the
    /// "attestation-by-shape" attack the typed payload-type field
    /// exists to prevent.
    #[test]
    fn test_verify_slsa_provenance_rejects_non_attestation_payload_type() {
        // Construct a bundle whose envelope holds SLSA-shaped JSON
        // but with payload_type = "text/plain". The DSSE signature
        // we synthesise here will be invalid bytes — but
        // `verify_attestation` runs `verify_blob` FIRST, so the
        // signature check would surface first. To isolate the
        // payload-type gate, we build a *signed* bundle over the
        // SLSA-shaped JSON but with `payload_type = "text/plain"`.
        let mut rng = ChaCha20Rng::from_seed([0xB7; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = *sk.verifying_key();
        let signer = EcdsaP256Signer::new(sk, None);

        let mut digest = BTreeMap::new();
        digest.insert(
            SUBJECT_DIGEST_ALGO.to_string(),
            SUBJECT_DIGEST_HEX.to_string(),
        );
        let stmt = Statement {
            _type: IN_TOTO_STATEMENT_V1_TYPE.to_string(),
            subject: vec![SpecSubject {
                name: SUBJECT_NAME.to_string(),
                digest,
            }],
            predicate_type: SLSA_PROVENANCE_V1_PREDICATE_TYPE.to_string(),
            predicate: sample_provenance().encode_json().unwrap(),
        };
        let payload = stmt.encode_json().unwrap();

        // Sign with the WRONG payload_type. `sign_blob` will produce
        // a valid DSSE signature over the (text/plain, payload) PAE.
        let bundle = sign_blob(&payload, "text/plain", &signer, None).unwrap();

        let err = verify_slsa_provenance(&bundle, &[vk], None, None).unwrap_err();
        match err {
            VerifyError::WrongPayloadType { expected, found } => {
                assert_eq!(expected, IN_TOTO_PAYLOAD_TYPE);
                assert_eq!(found, "text/plain");
            }
            other => panic!("expected WrongPayloadType, got {other:?}"),
        }
    }
}
