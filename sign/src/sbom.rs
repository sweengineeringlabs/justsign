//! SBOM attestation convenience wrappers.
//!
//! Thin layer over [`crate::attest`] / [`crate::verify_attestation`]
//! that pins the predicate-type for the two SBOM formats this crate
//! supports out of the box:
//!
//! * CycloneDX BOM v1.5 — [`spec::CYCLONEDX_BOM_V1_5_PREDICATE_TYPE`]
//! * SPDX Document v2.3 — [`spec::SPDX_DOCUMENT_V2_3_PREDICATE_TYPE`]
//!
//! ## Why opaque `serde_json::Value`?
//!
//! The CycloneDX and SPDX schemas are large, evolve on their own
//! release cadence, and have first-class typed crates upstream
//! (`cyclonedx-rs`, `spdx-rs`). Modelling them here would force a
//! breaking release of this crate every time those schemas drift,
//! and would re-implement validation logic that already lives in
//! the upstream crates. Instead, callers produce the SBOM document
//! externally — the body lands here as `serde_json::Value` and we
//! sign / verify it without parsing.
//!
//! ## Cross-type rejection
//!
//! [`verify_cyclonedx`] refuses any bundle whose predicate type is
//! NOT [`spec::CYCLONEDX_BOM_V1_5_PREDICATE_TYPE`] — including a
//! validly-signed SPDX bundle. [`verify_spdx`] is symmetric. A
//! caller that wants to accept either kind should call both
//! verifiers in sequence (or unwrap the bundle and use the lower-
//! level [`crate::verify_attestation`] directly).

use rekor::RekorClient;
use spec::Bundle;

use crate::{
    attest, verify_attestation, SignError, Signer, VerifiedAttestation, VerifyError, VerifyingKey,
    CYCLONEDX_BOM_V1_5_PREDICATE_TYPE, SPDX_DOCUMENT_V2_3_PREDICATE_TYPE,
};

/// Sign a CycloneDX BOM v1.5 SBOM as an in-toto attestation.
///
/// Builds an in-toto Statement v1 about
/// `(subject_name, subject_digest_algo, subject_digest_hex)` whose
/// `predicateType` is [`spec::CYCLONEDX_BOM_V1_5_PREDICATE_TYPE`] and
/// whose `predicate` body is the caller-supplied `sbom` JSON, then
/// signs it via [`crate::attest`].
///
/// The `sbom` value is treated as opaque: we do not validate that it
/// conforms to the CycloneDX 1.5 schema. Callers that need schema
/// validation should run it on the document BEFORE handing it in
/// (typically via `cyclonedx-rs` round-trip).
///
/// Errors surface via [`SignError`] — same construction sites as
/// [`crate::attest`].
pub fn sign_cyclonedx(
    subject_name: &str,
    subject_digest_algo: &str,
    subject_digest_hex: &str,
    sbom: serde_json::Value,
    signer: &dyn Signer,
    rekor: Option<&dyn RekorClient>,
) -> Result<Bundle, SignError> {
    attest(
        subject_name,
        subject_digest_algo,
        subject_digest_hex,
        CYCLONEDX_BOM_V1_5_PREDICATE_TYPE,
        sbom,
        signer,
        rekor,
    )
}

/// Sign an SPDX Document v2.3 SBOM as an in-toto attestation.
///
/// Builds an in-toto Statement v1 about
/// `(subject_name, subject_digest_algo, subject_digest_hex)` whose
/// `predicateType` is [`spec::SPDX_DOCUMENT_V2_3_PREDICATE_TYPE`] and
/// whose `predicate` body is the caller-supplied `sbom` JSON, then
/// signs it via [`crate::attest`].
///
/// The `sbom` value is treated as opaque: we do not validate that it
/// conforms to the SPDX 2.3 schema. Callers that need schema
/// validation should run it on the document BEFORE handing it in
/// (typically via `spdx-rs` round-trip).
///
/// Errors surface via [`SignError`] — same construction sites as
/// [`crate::attest`].
pub fn sign_spdx(
    subject_name: &str,
    subject_digest_algo: &str,
    subject_digest_hex: &str,
    sbom: serde_json::Value,
    signer: &dyn Signer,
    rekor: Option<&dyn RekorClient>,
) -> Result<Bundle, SignError> {
    attest(
        subject_name,
        subject_digest_algo,
        subject_digest_hex,
        SPDX_DOCUMENT_V2_3_PREDICATE_TYPE,
        sbom,
        signer,
        rekor,
    )
}

/// Verify a CycloneDX BOM v1.5 SBOM attestation produced by
/// [`sign_cyclonedx`] (or any Sigstore signer that follows the same
/// wire shape).
///
/// Pins the predicate-type to [`spec::CYCLONEDX_BOM_V1_5_PREDICATE_TYPE`]
/// — a bundle signed with a different predicate type is rejected with
/// [`VerifyError::WrongPredicateType`] even when its DSSE signature
/// validates. This is the load-bearing safety property: a CycloneDX
/// verifier MUST refuse an SPDX bundle (and vice versa).
///
/// All other behaviour (signature check, optional Rekor inclusion-
/// proof check, `expected_subject_digest = None` skipping subject
/// pinning) is inherited verbatim from [`crate::verify_attestation`].
///
/// On success the returned [`VerifiedAttestation`] carries the SBOM
/// JSON in its `predicate` field — opaque per this crate; callers
/// hand it to `cyclonedx-rs` to parse.
pub fn verify_cyclonedx(
    bundle: &Bundle,
    trusted_keys: &[VerifyingKey],
    expected_subject_digest: Option<(&str, &str)>,
    rekor: Option<&dyn RekorClient>,
) -> Result<VerifiedAttestation, VerifyError> {
    verify_attestation(
        bundle,
        trusted_keys,
        CYCLONEDX_BOM_V1_5_PREDICATE_TYPE,
        expected_subject_digest,
        rekor,
    )
}

/// Verify an SPDX Document v2.3 SBOM attestation produced by
/// [`sign_spdx`] (or any Sigstore signer that follows the same wire
/// shape).
///
/// Pins the predicate-type to [`spec::SPDX_DOCUMENT_V2_3_PREDICATE_TYPE`]
/// — a bundle signed with a different predicate type is rejected with
/// [`VerifyError::WrongPredicateType`] even when its DSSE signature
/// validates. This is the load-bearing safety property: an SPDX
/// verifier MUST refuse a CycloneDX bundle (and vice versa).
///
/// All other behaviour (signature check, optional Rekor inclusion-
/// proof check, `expected_subject_digest = None` skipping subject
/// pinning) is inherited verbatim from [`crate::verify_attestation`].
///
/// On success the returned [`VerifiedAttestation`] carries the SBOM
/// JSON in its `predicate` field — opaque per this crate; callers
/// hand it to `spdx-rs` to parse.
pub fn verify_spdx(
    bundle: &Bundle,
    trusted_keys: &[VerifyingKey],
    expected_subject_digest: Option<(&str, &str)>,
    rekor: Option<&dyn RekorClient>,
) -> Result<VerifiedAttestation, VerifyError> {
    verify_attestation(
        bundle,
        trusted_keys,
        SPDX_DOCUMENT_V2_3_PREDICATE_TYPE,
        expected_subject_digest,
        rekor,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EcdsaP256Signer;
    use p256::ecdsa::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use rekor::MockRekorClient;

    // Constants reused across the tests. Hex is lowercase 64 chars
    // (sha256-shaped) but unrelated to anything signed — Statement
    // validation does not recompute it.
    const SUBJECT_NAME: &str = "pkg:oci/example@sha256:abc";
    const DIGEST_X: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const DIGEST_Y: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// Minimal CycloneDX-shaped JSON. Schema fidelity isn't this
    /// crate's job — the body is opaque per the issue. We pick
    /// representative fields (`bomFormat`, `specVersion`,
    /// `components`) so the round-trip exercises nested objects and
    /// arrays, which are the most common JSON-shape regressions.
    fn sample_cyclonedx_bom() -> serde_json::Value {
        serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "example-lib",
                    "version": "1.2.3",
                    "purl": "pkg:cargo/example-lib@1.2.3"
                }
            ]
        })
    }

    /// Minimal SPDX-shaped JSON. Same opacity contract as the
    /// CycloneDX sample — we just need representative shape so the
    /// round-trip catches nested-structure drift.
    fn sample_spdx_document() -> serde_json::Value {
        serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "example-spdx-doc",
            "documentNamespace": "https://example.com/spdx/example-1",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package",
                    "name": "example-pkg",
                    "versionInfo": "1.2.3"
                }
            ]
        })
    }

    /// `sign_cyclonedx` followed by `verify_cyclonedx` round-trips
    /// the opaque SBOM body verbatim and surfaces it on
    /// `VerifiedAttestation::predicate`.
    ///
    /// Bug it catches: a wrapper that mistakenly wrapped the SBOM
    /// JSON in an outer envelope (e.g. `{ "bom": <sbom> }` instead
    /// of using the SBOM directly as the predicate body) would
    /// surface as a non-equal predicate Value here. Same for any
    /// re-encoding drift that re-ordered map keys without
    /// preserving JSON equality.
    #[test]
    fn test_sign_cyclonedx_then_verify_cyclonedx_round_trips() {
        let mut rng = ChaCha20Rng::from_seed([0xB0; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, Some("cyclonedx-key".into()));

        let sbom = sample_cyclonedx_bom();
        let bundle = sign_cyclonedx(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            sbom.clone(),
            &signer,
            None,
        )
        .expect("sign_cyclonedx must succeed for a real signer");

        let verified = verify_cyclonedx(&bundle, &[vk], Some(("sha256", DIGEST_X)), None).unwrap();

        assert_eq!(verified.predicate_type, CYCLONEDX_BOM_V1_5_PREDICATE_TYPE);
        assert_eq!(verified.predicate, sbom);
        assert_eq!(verified.subjects.len(), 1);
        assert_eq!(verified.subjects[0].name, SUBJECT_NAME);
        assert_eq!(
            verified.subjects[0].digest.get("sha256"),
            Some(&DIGEST_X.to_string())
        );
    }

    /// `sign_spdx` followed by `verify_spdx` round-trips the opaque
    /// SBOM body verbatim and surfaces it on
    /// `VerifiedAttestation::predicate`.
    ///
    /// Bug it catches: a wrapper that hard-coded the CycloneDX
    /// predicate URI in `sign_spdx` (copy-paste between the two
    /// functions) would land an SPDX body under a CycloneDX
    /// predicate type — `verify_spdx` would then reject it with
    /// `WrongPredicateType` even though the bytes are intact.
    #[test]
    fn test_sign_spdx_then_verify_spdx_round_trips() {
        let mut rng = ChaCha20Rng::from_seed([0xB1; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, Some("spdx-key".into()));

        let sbom = sample_spdx_document();
        let bundle = sign_spdx(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            sbom.clone(),
            &signer,
            None,
        )
        .expect("sign_spdx must succeed for a real signer");

        let verified = verify_spdx(&bundle, &[vk], Some(("sha256", DIGEST_X)), None).unwrap();

        assert_eq!(verified.predicate_type, SPDX_DOCUMENT_V2_3_PREDICATE_TYPE);
        assert_eq!(verified.predicate, sbom);
        assert_eq!(verified.subjects.len(), 1);
        assert_eq!(verified.subjects[0].name, SUBJECT_NAME);
    }

    /// `verify_cyclonedx` rejects a bundle signed via `sign_spdx`
    /// with `VerifyError::WrongPredicateType` — even though the
    /// signature is otherwise valid.
    ///
    /// Bug it catches: this is THE load-bearing safety property
    /// for the SBOM surface — a verifier that conflated CycloneDX
    /// and SPDX predicate types (e.g. accepted any SBOM-shaped
    /// predicate-type URI) would let an attacker substitute an
    /// SPDX document where a CycloneDX one was required, bypassing
    /// any policy that routes on predicate type.
    #[test]
    fn test_verify_cyclonedx_rejects_spdx_bundle() {
        let mut rng = ChaCha20Rng::from_seed([0xB2; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        let bundle = sign_spdx(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            sample_spdx_document(),
            &signer,
            None,
        )
        .unwrap();

        let err = verify_cyclonedx(&bundle, &[vk], None, None).unwrap_err();
        match err {
            VerifyError::WrongPredicateType { expected, found } => {
                assert_eq!(expected, CYCLONEDX_BOM_V1_5_PREDICATE_TYPE);
                assert_eq!(found, SPDX_DOCUMENT_V2_3_PREDICATE_TYPE);
            }
            other => panic!("expected WrongPredicateType, got {other:?}"),
        }
    }

    /// `verify_spdx` rejects a bundle signed via `sign_cyclonedx`
    /// with `VerifyError::WrongPredicateType` — symmetric to
    /// `test_verify_cyclonedx_rejects_spdx_bundle`.
    ///
    /// Bug it catches: same class as the CycloneDX-rejects-SPDX
    /// test, but specifically the case where the SPDX verifier was
    /// implemented but pointed at the wrong predicate-type
    /// constant (e.g. via copy-paste). Asymmetric coverage would
    /// leave one of the two cross-acceptance bugs undetected.
    #[test]
    fn test_verify_spdx_rejects_cyclonedx_bundle() {
        let mut rng = ChaCha20Rng::from_seed([0xB3; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        let bundle = sign_cyclonedx(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            sample_cyclonedx_bom(),
            &signer,
            None,
        )
        .unwrap();

        let err = verify_spdx(&bundle, &[vk], None, None).unwrap_err();
        match err {
            VerifyError::WrongPredicateType { expected, found } => {
                assert_eq!(expected, SPDX_DOCUMENT_V2_3_PREDICATE_TYPE);
                assert_eq!(found, CYCLONEDX_BOM_V1_5_PREDICATE_TYPE);
            }
            other => panic!("expected WrongPredicateType, got {other:?}"),
        }
    }

    /// `verify_cyclonedx` rejects a bundle whose subject digest
    /// doesn't match `Some((algo, hex))` with `SubjectMismatch`.
    ///
    /// Bug it catches: a wrapper that always passed `None` to the
    /// inner `verify_attestation` call (dropping the caller's
    /// subject pin) would let an attacker swap in a CycloneDX
    /// attestation about a different artifact and still pass
    /// policy. This is the same risk as the `attest`-level
    /// `test_verify_attestation_rejects_subject_digest_mismatch`,
    /// re-pinned at the SBOM wrapper layer because the wrappers
    /// are a separate construction site.
    #[test]
    fn test_verify_cyclonedx_rejects_subject_digest_mismatch() {
        let mut rng = ChaCha20Rng::from_seed([0xB4; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        let bundle = sign_cyclonedx(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            sample_cyclonedx_bom(),
            &signer,
            None,
        )
        .unwrap();

        let err = verify_cyclonedx(&bundle, &[vk], Some(("sha256", DIGEST_Y)), None).unwrap_err();
        match err {
            VerifyError::SubjectMismatch { expected_digest } => {
                assert_eq!(expected_digest, format!("sha256:{DIGEST_Y}"));
            }
            other => panic!("expected SubjectMismatch, got {other:?}"),
        }
    }

    /// `verify_cyclonedx` with `expected_subject_digest = None`
    /// skips the subject check — useful when the caller is
    /// enumerating subjects (e.g. listing every artifact an SBOM
    /// covers) instead of pinning one.
    ///
    /// Bug it catches: a wrapper that defaulted "no expectation"
    /// to "must match nothing" (passing `Some(("", ""))` instead
    /// of `None` through to `verify_attestation`) would force every
    /// caller to pass a digest even when they just want to read
    /// the SBOM body.
    #[test]
    fn test_verify_cyclonedx_with_subject_check_disabled() {
        let mut rng = ChaCha20Rng::from_seed([0xB5; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);

        let sbom = sample_cyclonedx_bom();
        let bundle = sign_cyclonedx(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            sbom.clone(),
            &signer,
            None,
        )
        .unwrap();

        let verified = verify_cyclonedx(&bundle, &[vk], None, None)
            .expect("None subject_digest must skip the check");
        assert_eq!(verified.predicate, sbom);
        assert_eq!(verified.subjects.len(), 1);
    }

    /// `verify_cyclonedx` rejects a bundle whose DSSE signature
    /// was produced with a key the verifier doesn't trust.
    ///
    /// Bug it catches: a wrapper that swallowed the signature-
    /// invalid error and re-raised as a predicate-type or subject
    /// error would mis-route caller policy — e.g. cause a retry
    /// loop on what is actually an authentication failure. We
    /// sign with key A, verify against key B, and require the
    /// exact `SignatureInvalid` variant.
    #[test]
    fn test_verify_cyclonedx_rejects_wrong_signature() {
        let mut rng_a = ChaCha20Rng::from_seed([0xB6; 32]);
        let sk_a = SigningKey::random(&mut rng_a);
        let signer_a = EcdsaP256Signer::new(sk_a, Some("key-a".into()));

        // Independent verifying key — the bundle was NOT signed
        // by its private counterpart.
        let mut rng_b = ChaCha20Rng::from_seed([0xB7; 32]);
        let sk_b = SigningKey::random(&mut rng_b);
        let vk_b = VerifyingKey::P256(*sk_b.verifying_key());

        let bundle = sign_cyclonedx(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            sample_cyclonedx_bom(),
            &signer_a,
            None,
        )
        .unwrap();

        let err = verify_cyclonedx(&bundle, &[vk_b], None, None).unwrap_err();
        match err {
            VerifyError::SignatureInvalid { keyid } => {
                assert_eq!(keyid.as_deref(), Some("key-a"));
            }
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    /// `sign_cyclonedx` with a Rekor client embeds exactly one
    /// `tlog_entries` entry whose inclusion proof verifies through
    /// the matching `verify_cyclonedx` call.
    ///
    /// Bug it catches: a wrapper that dropped the rekor argument
    /// (e.g. a `_rekor` parameter shadowed by a local `let rekor =
    /// None`) would emit an unwitnessed bundle even when the
    /// caller asked for transparency. Same risk as the
    /// `attest`-level rekor test, re-pinned at the SBOM wrapper
    /// layer because the wrappers thread the argument separately.
    #[test]
    fn test_sign_cyclonedx_with_rekor_attaches_tlog_entry() {
        let mut rng = ChaCha20Rng::from_seed([0xB8; 32]);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::P256(*sk.verifying_key());
        let signer = EcdsaP256Signer::new(sk, None);
        let client = MockRekorClient::new();

        let bundle = sign_cyclonedx(
            SUBJECT_NAME,
            "sha256",
            DIGEST_X,
            sample_cyclonedx_bom(),
            &signer,
            Some(&client),
        )
        .unwrap();

        assert_eq!(bundle.verification_material.tlog_entries.len(), 1);
        let tlog = &bundle.verification_material.tlog_entries[0];
        assert_eq!(tlog.kind_version.kind, "hashedrekord");

        // Full end-to-end: sig + proof + Statement decode +
        // predicate-type + subject-digest.
        verify_cyclonedx(&bundle, &[vk], Some(("sha256", DIGEST_X)), Some(&client))
            .expect("CycloneDX attestation with rekor must verify end-to-end");
    }
}
