//! PKCS#10 CSR construction for Fulcio's keyless flow.
//!
//! Fulcio expects a CSR whose subjectAlternativeName carries the
//! identity the OIDC token will be checked against (e.g. an email).
//! The CN is irrelevant to Fulcio — it pins identity off the SAN.
//!
//! We hand the work to `x509-cert::builder::RequestBuilder` rather
//! than rolling DER ourselves. The builder takes a `signature::Signer`
//! impl; `p256::ecdsa::SigningKey` produces DER-encoded ECDSA-with-
//! SHA256 signatures via the `DerSignature` type, which is exactly
//! what Fulcio accepts.

use der::{asn1::Ia5String, Encode};
use p256::{ecdsa::DerSignature, ecdsa::SigningKey};
use x509_cert::{
    builder::{Builder, RequestBuilder},
    ext::pkix::{name::GeneralName, SubjectAltName},
    name::Name,
};

use crate::error::FulcioError;

/// A built PKCS#10 CSR plus its subject + SAN, retained so the
/// Fulcio client can sanity-check what it's about to send.
#[derive(Debug, Clone)]
pub struct Csr {
    /// DER-encoded `CertificationRequest` (the bytes you POST to
    /// Fulcio, base64-wrapped at the wire layer).
    pub der: Vec<u8>,
    /// PEM form of the same CSR, useful for `--csr` flags and tests.
    pub pem: String,
    /// The OIDC subject the CSR was built for (echoed back so
    /// callers don't have to hold it separately).
    pub subject_email: String,
}

/// Build a PKCS#10 CSR signed by `signing_key`, with `subject_email`
/// embedded as an `rfc822Name` SubjectAltName.
///
/// The CSR's Subject `CN` is set to the same email so the resulting
/// blob has *something* in the Subject field — Fulcio ignores it,
/// but RFCs and most parsers expect a non-empty Subject.
///
/// # Errors
///
/// Returns [`FulcioError::Csr`] if:
/// * `subject_email` is not valid IA5 (ASCII-only, no NUL),
/// * the Subject DN can't be encoded (only happens for malformed
///   inputs the caller built themselves),
/// * signing or DER encoding fails.
pub fn build_csr(signing_key: &SigningKey, subject_email: &str) -> Result<Csr, FulcioError> {
    if subject_email.is_empty() {
        return Err(FulcioError::Csr("subject_email is empty".to_string()));
    }
    if !subject_email.is_ascii() {
        // IA5String rejects non-ASCII; reject early with a clear
        // message rather than leaking a der::Error.
        return Err(FulcioError::Csr(
            "subject_email must be ASCII (rfc822Name is IA5String)".to_string(),
        ));
    }

    // Subject DN: use the email as the CN. Fulcio ignores Subject;
    // SAN is what binds identity. But an empty Subject upsets some
    // legacy parsers, so we fill CN.
    let subject_dn: Name = format!("CN={subject_email}")
        .parse()
        .map_err(|e: der::Error| FulcioError::Csr(format!("subject DN parse: {e}")))?;

    // SAN: a single rfc822Name carrying the email.
    let email_ia5 = Ia5String::new(subject_email)
        .map_err(|e| FulcioError::Csr(format!("rfc822Name IA5 encode: {e}")))?;
    let san = SubjectAltName(vec![GeneralName::Rfc822Name(email_ia5)]);

    let mut builder = RequestBuilder::new(subject_dn, signing_key)
        .map_err(|e| FulcioError::Csr(format!("RequestBuilder::new: {e}")))?;
    builder
        .add_extension(&san)
        .map_err(|e| FulcioError::Csr(format!("add SAN extension: {e}")))?;

    // `build::<DerSignature>` produces ECDSA-with-SHA256 signatures
    // in DER form. That's what Fulcio expects on the wire.
    let csr = builder
        .build::<DerSignature>()
        .map_err(|e| FulcioError::Csr(format!("RequestBuilder::build: {e}")))?;

    let der = csr
        .to_der()
        .map_err(|e| FulcioError::Csr(format!("CSR to_der: {e}")))?;
    let pem_block = pem::Pem::new("CERTIFICATE REQUEST", der.clone());
    let pem = pem::encode(&pem_block);

    Ok(Csr {
        der,
        pem,
        subject_email: subject_email.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use x509_cert::request::CertReq;

    fn seeded_key() -> SigningKey {
        // Deterministic so tests are reproducible.
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE_u64);
        SigningKey::random(&mut rng)
    }

    #[test]
    fn test_build_csr_round_trip_returns_subject_and_san() {
        let key = seeded_key();
        let csr = build_csr(&key, "alice@example.com").expect("build_csr");

        // Bug it catches: forgetting to fill the DER field.
        assert!(!csr.der.is_empty(), "DER must be non-empty");
        assert_eq!(csr.subject_email, "alice@example.com");
        // PEM wrapper bug: wrong label or no body.
        assert!(csr.pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(csr
            .pem
            .trim_end()
            .ends_with("-----END CERTIFICATE REQUEST-----"));

        // The DER must round-trip back through x509-cert as a CertReq
        // and carry exactly one rfc822Name SAN matching the input.
        let parsed = CertReq::try_from(csr.der.as_slice()).expect("parse CSR");

        // SAN lives in the requested attributes / extensionRequest.
        let mut found_email: Option<String> = None;
        if let Some(attrs) = parsed.info.attributes.iter().next() {
            // Attributes are SET OF AttributeValue; we walk all of
            // them looking for an extensionRequest holding a SAN.
            for attr in parsed.info.attributes.iter() {
                for any in attr.values.iter() {
                    // Try decoding the attribute value as a list of
                    // x509_cert::ext::Extension. If it isn't, skip.
                    if let Ok(exts) = any.decode_as::<Vec<x509_cert::ext::Extension>>() {
                        for ext in exts {
                            if ext.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME {
                                if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes())
                                {
                                    for gn in san.0.iter() {
                                        if let GeneralName::Rfc822Name(e) = gn {
                                            found_email = Some(e.as_str().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // attrs is consumed only to silence unused; real walk
            // is in the loop above.
            let _ = attrs;
        }
        assert_eq!(
            found_email.as_deref(),
            Some("alice@example.com"),
            "rfc822Name SAN must round-trip through DER"
        );
    }

    #[test]
    fn test_build_csr_empty_subject_returns_csr_error() {
        // Bug it catches: silently building a CSR with an empty
        // SAN, which Fulcio would reject with a confusing 4xx.
        let key = seeded_key();
        let err = build_csr(&key, "").expect_err("empty subject must error");
        match err {
            FulcioError::Csr(msg) => {
                assert!(msg.contains("empty"), "message should explain why: {msg}");
            }
            other => panic!("expected Csr variant, got {other:?}"),
        }
    }

    #[test]
    fn test_build_csr_non_ascii_subject_returns_csr_error() {
        // Bug it catches: passing a UTF-8 email through and getting
        // a deep-stack der::Error. We catch it at the boundary with
        // a clear message.
        let key = seeded_key();
        let err =
            build_csr(&key, "alic\u{00e9}@example.com").expect_err("non-ASCII subject must error");
        match err {
            FulcioError::Csr(msg) => {
                assert!(msg.contains("ASCII"), "message names the rule: {msg}");
            }
            other => panic!("expected Csr variant, got {other:?}"),
        }
    }

    // x509_cert's `Extension` import lives behind an associated
    // path; pull der::Decode into scope for from_der above.
    use der::Decode as _;
}
