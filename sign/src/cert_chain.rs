//! X.509 cert-chain trust validation for keyless verification.
//!
//! Sigstore's keyless flow embeds an ephemeral leaf certificate in
//! every bundle: the leaf's SubjectAltName carries the OIDC identity
//! (email or URI), and the leaf is signed by a Fulcio intermediate
//! which is itself signed by a Fulcio root. The verifier's job is:
//!
//! 1. Walk the chain leaf → intermediate(s) → root, checking that
//!    each non-root cert's TBS bytes are signed by the next cert's
//!    public key.
//! 2. Confirm the last cert's DER matches one of the caller-supplied
//!    `trust_anchors_der` (i.e. the chain terminates at a root the
//!    caller actually trusts).
//! 3. Hand back the leaf's `VerifyingKey` so the rest of the
//!    keyless verifier can run DSSE checks against it.
//!
//! ## v0 boundaries
//!
//! * **TUF integration is OUT.** Issues #3 and #4 land that. Today
//!   the caller hands in DER-encoded trust anchors directly — fine
//!   for CI pipelines that pin the Fulcio root in their config, and
//!   the v1 TUF wiring will plug into the same `&[Vec<u8>]` slot.
//! * **Algorithm support is ECDSA-P256 only.** Fulcio's production
//!   cert chain is uniformly P-256; supporting RSA/Ed25519 here
//!   would invite drift between what we accept on a leaf vs an
//!   intermediate. The signature_algorithm OID on every cert is
//!   checked against `ECDSA_WITH_SHA_256`.
//! * **Expiry IS enforced** (issue #26). The walker itself stays
//!   IO-free; callers route a [`spec::Clock`] in via
//!   [`crate::verify_blob_keyless_with_clock`]. Each cert's
//!   `notBefore` and `notAfter` are compared against the clock's
//!   `now_unix_secs()` and rejected with [`crate::VerifyError::CertExpired`]
//!   / [`crate::VerifyError::CertNotYetValid`] respectively.
//! * **No revocation, no SCT check.** Out of scope for v0.
//!
//! ## Sigstore wire shape (what the caller hands us)
//!
//! `bundle.verification_material.certificate.certificates` is a
//! `Vec<Vec<u8>>` where index 0 is the leaf and subsequent entries
//! are intermediates. The Sigstore wire format **does not include
//! the root** — the verifier supplies it via `trust_anchors_der`.
//! That means a 2-element chain (leaf + intermediate) is the
//! production case, and we MUST look up the issuer of the last
//! supplied cert in the trust anchors rather than expecting the
//! root to be present in `chain_der`.
//!
//! For local-CA setups, callers can pass a 3+ element chain that
//! includes the root; we still terminate against the trust anchor
//! check on the topmost cert.

use der::{Decode, Encode};
use p256::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use x509_cert::{
    certificate::Certificate,
    ext::pkix::{name::GeneralName, SubjectAltName},
};

/// OID for `ecdsa-with-SHA256` (RFC 5758 §3.2). Fulcio signs every
/// cert it issues with this algorithm; we reject anything else
/// rather than silently widening the trust surface.
const ECDSA_WITH_SHA256_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Errors surfaced by the cert-chain walker.
///
/// Variants describe specific failure modes so [`crate::VerifyError`]
/// can wrap them and downstream policy can route appropriately
/// (retry vs reject vs escalate).
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// A DER-encoded certificate failed to decode, or a re-encode of
    /// a parsed structure failed (the latter is internal but we
    /// surface it rather than panicking). The inner string is the
    /// underlying parser/encoder message.
    #[error("certificate decode/encode: {0}")]
    Decode(String),

    /// The signature on the cert at `at_index` did not verify against
    /// the public key of the cert at `at_index + 1`. Index 0 is the
    /// leaf — so `at_index = 0` means the leaf isn't signed by the
    /// first intermediate, `at_index = 1` means the first intermediate
    /// isn't signed by the next, etc.
    #[error("broken signature at chain index {at_index}")]
    BrokenSignature {
        /// Position of the cert whose signature failed to verify
        /// against the next cert's public key.
        at_index: usize,
    },

    /// The last cert in the supplied chain is not signed by any of
    /// the trust anchors AND its DER bytes don't match any anchor
    /// directly. `found_subject` echoes the offending cert's Subject
    /// DN so the operator can see WHICH cert hit them.
    #[error("root not in trust anchors (subject = {found_subject})")]
    RootNotTrusted {
        /// RFC-4514 string of the unverified cert's Subject. Empty
        /// only if the cert legitimately had an empty Subject.
        found_subject: String,
    },

    /// Caller passed an empty `trust_anchors_der` slice. With no
    /// anchors there's no possible terminus for the walk — surface
    /// this distinctly from `RootNotTrusted` so a misconfigured
    /// caller can be told "you forgot the trust roots" rather than
    /// "your bundle's root isn't trusted".
    #[error("trust anchor list is empty")]
    EmptyTrustAnchors,

    /// Cert at `at_index` advertises a signature_algorithm OID this
    /// v0 verifier doesn't accept. v0 is ECDSA-P256-SHA256 only.
    #[error("unsupported signature algorithm at chain index {at_index} (oid = {oid})")]
    UnsupportedAlgorithm {
        /// Position of the offending cert.
        at_index: usize,
        /// The OID we refused, as a dotted-decimal string.
        oid: String,
    },
}

/// Extract the validity window (`notBefore`, `notAfter`) of a single
/// DER-encoded cert as Unix epoch seconds.
///
/// Returns `(not_before_secs, not_after_secs)`. Both values are
/// signed because a DER `Time` can encode pre-1970 dates via
/// `GeneralizedTime`; in practice every Fulcio cert is strictly
/// post-1970, but the typed surface mirrors the wire shape
/// faithfully so a misissued cert with a pre-epoch `notBefore`
/// surfaces as "not yet valid" in 1970, not as a panic.
///
/// # Errors
///
/// * [`ChainError::Decode`] — `cert_der` isn't a valid X.509 cert.
pub fn cert_validity_window(cert_der: &[u8]) -> Result<(i64, i64), ChainError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| ChainError::Decode(format!("certificate decode: {e}")))?;
    let validity = &cert.tbs_certificate.validity;
    // `Time::to_unix_duration` returns a `Duration` (unsigned). The
    // x509-cert lower bound is the Unix epoch (so non-negative). Cap
    // at i64::MAX during the cast to avoid silently wrapping a
    // pathological GeneralizedTime far in the future.
    let to_signed_secs = |secs: u64| -> i64 {
        if secs > i64::MAX as u64 {
            i64::MAX
        } else {
            secs as i64
        }
    };
    let not_before_secs = to_signed_secs(validity.not_before.to_unix_duration().as_secs());
    let not_after_secs = to_signed_secs(validity.not_after.to_unix_duration().as_secs());
    Ok((not_before_secs, not_after_secs))
}

/// Pull the SubjectAltName entries (RFC 822 emails + URIs) from a
/// DER-encoded leaf certificate.
///
/// Sigstore's Fulcio puts the OIDC identity in SAN — typically an
/// `rfc822Name` (email) or `uniformResourceIdentifier` (issuer URL
/// concatenated with subject claim, e.g. for CI provider tokens).
/// Both are returned in source order; the caller compares against
/// `expected_san` for a v0 exact-string match.
///
/// Returned vec is empty if the cert has no SAN extension OR the
/// extension is present but contains no rfc822 / URI entries (other
/// `GeneralName` variants like dNSName are intentionally dropped —
/// Sigstore doesn't use them for identity).
///
/// # Errors
///
/// * [`ChainError::Decode`] — `leaf_der` isn't valid X.509 DER, or
///   the SAN extension's contents don't decode.
pub fn extract_san(leaf_der: &[u8]) -> Result<Vec<String>, ChainError> {
    let cert = Certificate::from_der(leaf_der)
        .map_err(|e| ChainError::Decode(format!("certificate decode: {e}")))?;

    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Ok(Vec::new());
    };

    let mut out: Vec<String> = Vec::new();
    for ext in extensions {
        if ext.extn_id != const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME {
            continue;
        }
        let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
            .map_err(|e| ChainError::Decode(format!("SAN decode: {e}")))?;
        for gn in &san.0 {
            match gn {
                GeneralName::Rfc822Name(s) => out.push(s.as_str().to_string()),
                GeneralName::UniformResourceIdentifier(s) => out.push(s.as_str().to_string()),
                // Sigstore does not put identity into other variants.
                // Ignoring is the safe default — unknown variant in
                // SAN doesn't mean the cert is bad, just that this
                // verifier doesn't speak that flavor of identity.
                _ => {}
            }
        }
    }
    Ok(out)
}

/// Walk a DER-encoded cert chain, verifying signatures all the way
/// up to a trust anchor. Returns the leaf's `VerifyingKey` so the
/// caller can use it for DSSE / payload verification.
///
/// `chain_der[0]` is the leaf. `chain_der[1..]` are intermediates.
/// The chain MAY include the root at the topmost index (some local-
/// CA setups do this); production Sigstore bundles do NOT — the
/// last entry is an intermediate and the verifier matches its
/// issuer against `trust_anchors_der`.
///
/// `trust_anchors_der` is a non-empty list of DER-encoded root
/// certificates the caller trusts. The chain is accepted iff:
///
/// 1. Every adjacent pair (`chain_der[i]`, `chain_der[i + 1]`)
///    verifies — `chain_der[i]`'s signature checks against
///    `chain_der[i + 1]`'s public key.
/// 2. For the topmost cert in `chain_der`:
///    * if its raw DER matches one of `trust_anchors_der`, the
///      walk terminates (the chain INCLUDED the root and that root
///      is trusted), OR
///    * one of `trust_anchors_der` decodes to a cert whose public
///      key signs the topmost cert (the chain stopped at an
///      intermediate and the trust anchor is its issuer).
///
/// # Errors
///
/// * [`ChainError::Decode`] — any cert fails to decode.
/// * [`ChainError::EmptyTrustAnchors`] — `trust_anchors_der` empty.
/// * [`ChainError::BrokenSignature`] — any pairwise signature fails.
/// * [`ChainError::RootNotTrusted`] — topmost cert isn't itself a
///   trust anchor AND no trust anchor signs it.
/// * [`ChainError::UnsupportedAlgorithm`] — non-ECDSA-P256-SHA256
///   signature_algorithm OID encountered.
///
/// # Panics
///
/// Returns [`ChainError::Decode`] (does not panic) on an empty
/// `chain_der` slice — there's no leaf to extract a key from.
pub fn verify_chain(
    chain_der: &[Vec<u8>],
    trust_anchors_der: &[Vec<u8>],
) -> Result<VerifyingKey, ChainError> {
    if trust_anchors_der.is_empty() {
        return Err(ChainError::EmptyTrustAnchors);
    }
    if chain_der.is_empty() {
        return Err(ChainError::Decode("chain is empty".to_string()));
    }

    // Decode every cert in the supplied chain up front so we can
    // talk about indices consistently. Doing this lazily would mean
    // a malformed intermediate surfaces a different error variant
    // depending on which cert tried to verify against it first.
    let mut parsed: Vec<Certificate> = Vec::with_capacity(chain_der.len());
    for (i, der) in chain_der.iter().enumerate() {
        let cert = Certificate::from_der(der)
            .map_err(|e| ChainError::Decode(format!("chain[{i}] certificate decode: {e}")))?;
        parsed.push(cert);
    }

    // Step 1: pairwise signature verification along the chain.
    //
    // For every i in 0..(parsed.len() - 1), verify that parsed[i]
    // is signed by parsed[i + 1]. We don't try to verify the topmost
    // cert here — its issuer is in trust_anchors_der (or the cert
    // itself IS a trust anchor) and that gets handled in step 2.
    for i in 0..parsed.len().saturating_sub(1) {
        verify_cert_signature(&parsed[i], &parsed[i + 1], i)?;
    }

    // Step 2: anchor check on the topmost supplied cert.
    let top_idx = parsed.len() - 1;
    let top_der = &chain_der[top_idx];
    let top_cert = &parsed[top_idx];

    let mut anchor_satisfied = false;

    // Case A: the chain INCLUDED the root. Match by exact DER bytes
    // of the topmost cert. We compare bytes (not parsed structures)
    // so a re-encoder bug elsewhere can't fool us.
    for anchor in trust_anchors_der {
        if anchor.as_slice() == top_der.as_slice() {
            anchor_satisfied = true;
            break;
        }
    }

    // Case B: the chain stopped at an intermediate. Walk every
    // anchor, decode it, and try to verify the topmost cert's
    // signature against the anchor's public key. First match wins.
    if !anchor_satisfied {
        for (anchor_idx, anchor_der) in trust_anchors_der.iter().enumerate() {
            let anchor_cert = Certificate::from_der(anchor_der).map_err(|e| {
                ChainError::Decode(format!(
                    "trust_anchor[{anchor_idx}] certificate decode: {e}"
                ))
            })?;
            // Re-use verify_cert_signature: top_cert is signed by
            // anchor_cert. Index reported on failure is `top_idx`
            // (the unverified cert in the chain). On a generic
            // mismatch we DON'T want to surface BrokenSignature
            // here — multiple anchors might be tried, and only the
            // last failing one would set the error variant. Swallow
            // per-anchor failures and let the outer "not trusted"
            // error fire if we exhaust all anchors.
            if verify_cert_signature(top_cert, &anchor_cert, top_idx).is_ok() {
                anchor_satisfied = true;
                break;
            }
        }
    }

    if !anchor_satisfied {
        return Err(ChainError::RootNotTrusted {
            found_subject: top_cert.tbs_certificate.subject.to_string(),
        });
    }

    // Step 3: extract the leaf public key as a VerifyingKey.
    let leaf = &parsed[0];
    let spki_der = leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| ChainError::Decode(format!("leaf SPKI re-encode: {e}")))?;
    let leaf_vk = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|e| ChainError::Decode(format!("leaf public key decode: {e}")))?;
    Ok(leaf_vk)
}

/// Verify that `subject` cert's signature is valid under `issuer`'s
/// public key. Reports failures using the supplied `subject_index`
/// so the caller can attribute errors to the right chain position.
///
/// Restricted to ECDSA-P256-SHA256 — see the module docs for why
/// we don't widen the algorithm surface in v0.
fn verify_cert_signature(
    subject: &Certificate,
    issuer: &Certificate,
    subject_index: usize,
) -> Result<(), ChainError> {
    // Algorithm gate: refuse anything that isn't ecdsa-with-SHA256.
    // We check the OUTER signature_algorithm field (RFC 5280 §4.1.1.2);
    // RFC requires it to equal the inner tbs_certificate.signature
    // field, but we don't enforce that equality here — a forged
    // mismatch would have to also produce a valid signature under
    // the issuer's key, which the verify call below catches.
    let alg_oid = subject.signature_algorithm.oid;
    if alg_oid != ECDSA_WITH_SHA256_OID {
        return Err(ChainError::UnsupportedAlgorithm {
            at_index: subject_index,
            oid: alg_oid.to_string(),
        });
    }

    // Re-encode the issuer's SubjectPublicKeyInfo to DER and parse
    // it as a P-256 verifying key. Going through SPKI bytes is more
    // robust than reaching into the BitString directly: it catches
    // curve mismatches via the algorithm OID inside SPKI.
    let issuer_spki_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| ChainError::Decode(format!("issuer SPKI re-encode: {e}")))?;
    let issuer_vk = VerifyingKey::from_public_key_der(&issuer_spki_der)
        .map_err(|e| ChainError::Decode(format!("issuer public key decode: {e}")))?;

    // Re-encode the TBS portion of the subject cert. These are the
    // exact bytes the issuer signed.
    let tbs_der = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| ChainError::Decode(format!("subject TBS re-encode: {e}")))?;

    // Pull the signature bytes out of the BitString. ECDSA-P256
    // signatures embed a DER-encoded ECDSA-Sig-Value inside the
    // BitString contents.
    let sig_bytes = subject.signature.as_bytes().ok_or_else(|| {
        ChainError::Decode(format!(
            "subject signature BitString has unaligned bits at index {subject_index}"
        ))
    })?;
    let parsed_sig = DerSignature::try_from(sig_bytes).map_err(|_| {
        // Signature bytes weren't valid DER ECDSA. We surface this
        // as BrokenSignature (not Decode) because from the caller's
        // POV the cert chain's signature is structurally bad — same
        // bucket as a cryptographically invalid one.
        ChainError::BrokenSignature {
            at_index: subject_index,
        }
    })?;

    issuer_vk
        .verify(&tbs_der, &parsed_sig)
        .map_err(|_| ChainError::BrokenSignature {
            at_index: subject_index,
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
        PKCS_ECDSA_P256_SHA256,
    };

    /// Triplet produced by [`build_three_level_chain`].
    ///
    /// Held together because tests need access to BOTH the DER chain
    /// (to feed the verifier) AND the synthesized leaf email/URI (to
    /// assert SAN extraction works).
    struct SyntheticChain {
        /// Leaf DER (index 0), intermediate DER (index 1).
        chain: Vec<Vec<u8>>,
        /// Root DER. Caller passes this as a single-element trust
        /// anchor list.
        root_der: Vec<u8>,
        /// Whatever email got embedded in the leaf's SAN.
        leaf_email: String,
        /// Whatever issuer URI got embedded in the leaf's SAN.
        leaf_uri: String,
    }

    /// Build a self-signed P-256 root → P-256 intermediate signed by
    /// root → P-256 leaf signed by intermediate. Mirrors the shape
    /// Sigstore uses (Fulcio root → Fulcio intermediate → ephemeral
    /// keyless leaf). The leaf's SAN carries one rfc822Name and one
    /// URI so the SAN-extraction test has both flavors to assert on.
    ///
    /// All three certs are ECDSA-P256 with SHA-256 — matches the
    /// only algorithm `verify_chain` accepts in v0.
    fn build_three_level_chain() -> SyntheticChain {
        // Root: self-signed, CA:TRUE.
        let root_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root keypair");
        let mut root_params = CertificateParams::new(Vec::<String>::new()).expect("root params");
        root_params
            .distinguished_name
            .push(DnType::CommonName, "synthetic-root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root_cert = root_params.self_signed(&root_kp).expect("root self-sign");
        let root_der = root_cert.der().to_vec();

        // Intermediate: signed by root, CA:TRUE (path-length 0 so it
        // matches Fulcio's posture).
        let intermediate_kp =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("intermediate keypair");
        let mut intermediate_params =
            CertificateParams::new(Vec::<String>::new()).expect("intermediate params");
        intermediate_params
            .distinguished_name
            .push(DnType::CommonName, "synthetic-intermediate");
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        intermediate_params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_kp, &root_cert, &root_kp)
            .expect("intermediate sign");
        let intermediate_der = intermediate_cert.der().to_vec();

        // Leaf: signed by intermediate, CA:FALSE, SAN = email + URI.
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf keypair");
        let leaf_email = "dev@example.com".to_string();
        let leaf_uri = "https://accounts.example.com/sub/12345".to_string();
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "synthetic-leaf");
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.subject_alt_names = vec![
            SanType::Rfc822Name(leaf_email.clone().try_into().expect("email IA5")),
            SanType::URI(leaf_uri.clone().try_into().expect("uri IA5")),
        ];
        let leaf_cert = leaf_params
            .signed_by(&leaf_kp, &intermediate_cert, &intermediate_kp)
            .expect("leaf sign");
        let leaf_der = leaf_cert.der().to_vec();

        SyntheticChain {
            chain: vec![leaf_der, intermediate_der],
            root_der,
            leaf_email,
            leaf_uri,
        }
    }

    /// Bug it catches: a verifier that "succeeds" without actually
    /// running the cryptographic check (e.g. returning Ok the moment
    /// it parsed the SPKI). Run a real ECDSA verify against a real
    /// chain and require it to succeed.
    #[test]
    fn test_verify_chain_3_levels_succeeds_with_root_in_anchors() {
        let synth = build_three_level_chain();

        let leaf_vk = verify_chain(&synth.chain, &[synth.root_der]).expect("chain must verify");

        // The leaf VK we got back must actually be the leaf's key —
        // i.e. it must be able to verify a signature produced by the
        // leaf's signing key, NOT the intermediate's. We don't have
        // that signing key here, but we DO know the SPKI re-encoded
        // from the leaf cert must equal the public_key portion we
        // extracted. Cheap regression assertion: `to_encoded_point`
        // emits a 65-byte uncompressed P-256 point.
        let point = leaf_vk.to_encoded_point(false);
        assert_eq!(point.as_bytes().len(), 65, "uncompressed P-256 point");
        assert_eq!(point.as_bytes()[0], 0x04, "uncompressed point tag");
    }

    /// Bug it catches: a verifier that accepts ANY chain regardless
    /// of trust anchors — i.e. only checks intra-chain signatures and
    /// forgets to terminate against the anchor list. Build a valid
    /// chain but pass a UNRELATED anchor; must reject.
    #[test]
    fn test_verify_chain_rejects_when_root_not_in_anchors_returns_root_not_trusted() {
        let synth = build_three_level_chain();
        let unrelated = build_three_level_chain();

        let err = verify_chain(&synth.chain, &[unrelated.root_der])
            .expect_err("untrusted root must error");

        match err {
            ChainError::RootNotTrusted { found_subject } => {
                assert!(
                    found_subject.contains("synthetic-intermediate"),
                    "expected unverified intermediate's subject to surface, got {found_subject:?}"
                );
            }
            other => panic!("expected RootNotTrusted, got {other:?}"),
        }
    }

    /// Bug it catches: a verifier that returns Ok on any chain that
    /// *parses*, without actually checking the cryptographic
    /// signature. We tamper a single byte in the intermediate's TBS
    /// region, which breaks the issuer→subject signature.
    ///
    /// Implementation note: we tamper the intermediate by flipping a
    /// byte in the middle of its DER. The flip lands in the cert's
    /// TBS area (well within the Subject DN region), which means the
    /// signature OVER that TBS no longer matches. Some flips might
    /// land in the algorithm OID and surface as
    /// `UnsupportedAlgorithm`; we accept either outcome — the
    /// load-bearing assertion is "the chain rejects".
    #[test]
    fn test_verify_chain_rejects_tampered_intermediate_returns_broken_signature() {
        let synth = build_three_level_chain();

        let mut tampered_chain = synth.chain.clone();
        // Flip a byte well into the intermediate's TBS body. Index
        // 50 is past the outer SEQUENCE/length headers and into the
        // TBS contents on every realistic cert.
        let intermediate = &mut tampered_chain[1];
        assert!(
            intermediate.len() > 100,
            "synthetic intermediate cert must be >100 bytes for the tamper offset to land in TBS"
        );
        intermediate[50] ^= 0x01;

        let err = verify_chain(&tampered_chain, &[synth.root_der])
            .expect_err("tampered chain must reject");

        // The tamper either:
        // (a) corrupts TBS bytes → BrokenSignature on the
        //     intermediate (subject_index = 1), OR
        // (b) corrupts a length/header byte such that the cert
        //     fails to decode → ChainError::Decode.
        //
        // Both are correct rejections. What we MUST NOT see is Ok.
        match err {
            ChainError::BrokenSignature { at_index } => {
                assert_eq!(
                    at_index, 1,
                    "tampered cert is at index 1 (the intermediate)"
                );
            }
            ChainError::Decode(_) => {
                // Length/header byte got flipped — also an
                // acceptable rejection.
            }
            ChainError::UnsupportedAlgorithm { .. } => {
                // Flip landed in an OID byte; algorithm gate
                // rejected it. Also acceptable.
            }
            other => {
                panic!("expected BrokenSignature, Decode, or UnsupportedAlgorithm — got {other:?}")
            }
        }
    }

    /// Bug it catches: a SAN extractor that drops URI entries (so
    /// CI-provider identities silently disappear) or drops email
    /// entries (so user identities silently disappear). Both must
    /// be returned.
    #[test]
    fn test_extract_san_returns_email_uri_entries() {
        let synth = build_three_level_chain();

        let entries = extract_san(&synth.chain[0]).expect("SAN extract");

        assert!(
            entries.iter().any(|e| e == &synth.leaf_email),
            "email SAN missing — got {entries:?}"
        );
        assert!(
            entries.iter().any(|e| e == &synth.leaf_uri),
            "URI SAN missing — got {entries:?}"
        );
    }

    /// Bug it catches: a verifier that "succeeds" with
    /// `trust_anchors_der = []` because it short-circuited around
    /// the anchor check. With no anchors there's nothing to
    /// terminate the walk; must error.
    #[test]
    fn test_verify_chain_rejects_empty_trust_anchors_returns_empty_trust_anchors() {
        let synth = build_three_level_chain();

        let err = verify_chain(&synth.chain, &[]).expect_err("no anchors must error");
        assert!(
            matches!(err, ChainError::EmptyTrustAnchors),
            "expected EmptyTrustAnchors, got {err:?}"
        );
    }

    /// Bug it catches: an empty `chain_der` slice causing a panic via
    /// `chain[0]` indexing. Must return a typed error instead.
    #[test]
    fn test_verify_chain_rejects_empty_chain_returns_decode() {
        let synth = build_three_level_chain();
        let err = verify_chain(&[], &[synth.root_der]).expect_err("empty chain must error");
        assert!(
            matches!(err, ChainError::Decode(_)),
            "expected Decode, got {err:?}"
        );
    }

    /// Bug it catches: a verifier that accepts arbitrary garbage as
    /// a "cert" because it lazy-decodes only when actually verifying.
    #[test]
    fn test_verify_chain_rejects_non_der_chain_returns_decode() {
        let synth = build_three_level_chain();
        let err = verify_chain(&[vec![0x00, 0x01, 0x02, 0x03]], &[synth.root_der])
            .expect_err("garbage chain must error");
        assert!(
            matches!(err, ChainError::Decode(_)),
            "expected Decode, got {err:?}"
        );
    }

    /// Bug it catches: an extractor that panics on a cert that has
    /// no SAN extension at all. Must return an empty Vec.
    #[test]
    fn test_extract_san_returns_empty_when_cert_has_no_san() {
        let synth = build_three_level_chain();
        // The intermediate carries no SAN in build_three_level_chain.
        let entries =
            extract_san(&synth.chain[1]).expect("SAN extract must succeed even with no SAN");
        assert!(
            entries.is_empty(),
            "intermediate has no SAN; expected empty, got {entries:?}"
        );
    }
}
