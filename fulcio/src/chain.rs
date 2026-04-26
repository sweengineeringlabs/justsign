//! PEM cert-chain parser.
//!
//! Fulcio returns a PEM-encoded chain on `POST /api/v2/signingCert`:
//! the leaf first, then any intermediates, then the root. We split
//! the PEM, parse each block as an X.509 certificate, and surface a
//! [`Vec<X509Cert>`] preserving original order.
//!
//! Each [`X509Cert`] carries:
//!
//! * **`der`** — verbatim DER bytes (load-bearing — these are the
//!   bytes the caller will hand to verifiers + log to Rekor; we
//!   *do not* reserialize, because a DER round-trip can change
//!   things like SET ordering on uncareful encoders).
//! * **`subject`** — the parsed Subject DN as RFC 4514 string.
//! * **`san`** — the SubjectAltName extension if present, decoded.
//!
//! v0 does **not** validate trust. That's TUF's job. We only
//! parse + extract — anything more would make this module a
//! liability without the trust root in hand.

use der::{Decode, Encode};
use x509_cert::{
    certificate::Certificate,
    ext::pkix::{name::GeneralName, SubjectAltName},
};

use crate::error::FulcioError;

/// One certificate from a Fulcio chain.
#[derive(Debug, Clone)]
pub struct X509Cert {
    /// DER bytes exactly as they came off the wire (after PEM
    /// unwrap). Re-emit these, do not re-encode.
    pub der: Vec<u8>,
    /// Parsed subject DN as RFC 4514 string (e.g.
    /// `O=sigstore.dev,CN=sigstore-intermediate`).
    pub subject: String,
    /// SubjectAltName, if the certificate carries one. Fulcio
    /// leaf certs always do; intermediates and roots usually
    /// don't.
    pub san: Option<SubjectAltName>,
}

impl X509Cert {
    /// All `rfc822Name` (email) entries in the SAN, if any.
    /// Convenience accessor used by the client to sanity-check
    /// the leaf against the OIDC subject.
    pub fn san_emails(&self) -> Vec<String> {
        let Some(san) = &self.san else {
            return Vec::new();
        };
        san.0
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::Rfc822Name(s) => Some(s.as_str().to_string()),
                _ => None,
            })
            .collect()
    }
}

/// Parse a PEM-encoded cert chain into an ordered list. The first
/// element is whatever the PEM presented first — for Fulcio that's
/// the leaf.
///
/// # Errors
///
/// * [`FulcioError::Pem`] — input isn't valid PEM.
/// * [`FulcioError::EmptyChain`] — PEM was valid but contained zero
///   `CERTIFICATE` blocks.
/// * [`FulcioError::X509`] — a block decoded from PEM but failed
///   X.509 DER decoding.
pub fn parse_chain(pem_bytes: &[u8]) -> Result<Vec<X509Cert>, FulcioError> {
    let blocks = pem::parse_many(pem_bytes)?;

    let mut out = Vec::with_capacity(blocks.len());
    for block in blocks {
        // Be liberal about the PEM tag. Fulcio uses "CERTIFICATE";
        // some servers emit "X509 CERTIFICATE". Reject anything
        // that clearly isn't a cert (e.g. "PRIVATE KEY").
        let tag = block.tag();
        if !tag.contains("CERTIFICATE") {
            continue;
        }
        let der = block.contents().to_vec();
        let cert = Certificate::from_der(&der)
            .map_err(|e| FulcioError::X509(format!("certificate decode: {e}")))?;

        let subject = cert.tbs_certificate.subject.to_string();

        // Look for the SAN extension on the cert. Optional —
        // intermediates routinely omit it.
        let mut san: Option<SubjectAltName> = None;
        if let Some(exts) = &cert.tbs_certificate.extensions {
            for ext in exts {
                if ext.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME {
                    let bytes = ext.extn_value.as_bytes();
                    let decoded = SubjectAltName::from_der(bytes)
                        .map_err(|e| FulcioError::X509(format!("SAN decode: {e}")))?;
                    san = Some(decoded);
                }
            }
        }

        // Sanity: re-encoding the parsed cert must equal the input
        // DER. If it doesn't, the PEM body wasn't a strict-DER cert
        // and downstream verifiers will reject it. We surface this
        // here rather than letting it manifest as a signature
        // verification failure five layers up.
        let reencoded = cert
            .to_der()
            .map_err(|e| FulcioError::X509(format!("re-encode for round-trip check: {e}")))?;
        if reencoded != der {
            return Err(FulcioError::X509(
                "DER round-trip mismatch — input was not strict DER".to_string(),
            ));
        }

        out.push(X509Cert { der, subject, san });
    }

    if out.is_empty() {
        return Err(FulcioError::EmptyChain);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_fixtures::CANNED_CHAIN_PEM;

    #[test]
    fn test_parse_chain_canned_three_cert_chain_returns_correct_count_and_subjects() {
        // Bug it catches: a regression in the PEM splitter that
        // either drops blocks or merges them. The canned chain has
        // three certs.
        let chain = parse_chain(CANNED_CHAIN_PEM.as_bytes()).expect("parse_chain");
        assert_eq!(
            chain.len(),
            3,
            "canned chain has leaf + intermediate + root"
        );

        // Subject must round-trip and be non-empty for every cert.
        for (i, cert) in chain.iter().enumerate() {
            assert!(
                !cert.subject.is_empty(),
                "cert at index {i} has empty subject"
            );
            assert!(!cert.der.is_empty(), "cert at index {i} has empty DER");
        }

        // Leaf carries the SAN with the OIDC email.
        let leaf = &chain[0];
        let emails = leaf.san_emails();
        assert!(
            emails.iter().any(|e| e == "dev@example.com"),
            "leaf SAN must carry dev@example.com, got {emails:?}"
        );

        // Intermediate + root: no email SAN required.
        // (We don't assert the absence — a different test fixture
        // could legitimately include one — but the leaf assertion
        // above is the load-bearing one.)
    }

    #[test]
    fn test_parse_chain_empty_input_returns_empty_chain_error() {
        // Bug it catches: silently returning Vec::new() on an empty
        // chain. That would let a broken Fulcio response sail right
        // through into a "successful" sign with no cert.
        let err = parse_chain(b"").expect_err("empty PEM must error");
        assert!(
            matches!(err, FulcioError::EmptyChain),
            "expected EmptyChain, got {err:?}"
        );
    }

    #[test]
    fn test_parse_chain_pem_without_cert_blocks_returns_empty_chain_error() {
        // Bug it catches: a response that's PEM-shaped but contains
        // only e.g. a PRIVATE KEY block — must be rejected, not
        // returned as a zero-cert "chain".
        let pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        let err = parse_chain(pem.as_bytes()).expect_err("non-cert PEM must error");
        assert!(
            matches!(err, FulcioError::EmptyChain),
            "expected EmptyChain, got {err:?}"
        );
    }

    #[test]
    fn test_parse_chain_malformed_pem_returns_pem_error() {
        // Bug it catches: a panicking PEM splitter on truncated
        // input. Must surface a typed error.
        let pem = "-----BEGIN CERTIFICATE-----\nnot-base64!!!!\n-----END CERTIFICATE-----\n";
        let err = parse_chain(pem.as_bytes()).expect_err("malformed PEM must error");
        // pem 3.x surfaces this as PemError; either Pem or X509
        // is acceptable depending on where the failure lands.
        match err {
            FulcioError::Pem(_) | FulcioError::X509(_) => {}
            other => panic!("expected Pem or X509 error, got {other:?}"),
        }
    }
}
