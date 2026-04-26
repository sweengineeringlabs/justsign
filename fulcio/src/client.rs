//! `FulcioClient` trait + two impls: a deterministic mock and a
//! blocking HTTP client.
//!
//! The trait is the load-bearing surface — every other crate in
//! justsign that needs a cert chain depends on `FulcioClient`, not
//! on `HttpFulcioClient`. That keeps tests fast and lets us swap
//! the transport (e.g. async, or a recorded fixture player) later
//! without touching callers.

use crate::chain::{parse_chain, X509Cert};
use crate::csr::Csr;
use crate::error::FulcioError;

/// A parsed Fulcio response: ordered cert chain (leaf first).
#[derive(Debug, Clone)]
pub struct CertChain {
    /// Leaf, then intermediates, then root.
    pub certs: Vec<X509Cert>,
    /// The PEM bytes Fulcio returned, retained verbatim. Stored
    /// because some downstream consumers (Rekor entry generation,
    /// bundle emission) want the original bytes, not a re-encode.
    pub raw_pem: String,
}

impl CertChain {
    /// Borrow the leaf certificate. Always present — `CertChain`
    /// is constructed only after [`parse_chain`] rejected the
    /// empty case.
    pub fn leaf(&self) -> &X509Cert {
        &self.certs[0]
    }
}

/// The v0 Fulcio surface. Synchronous on purpose: keeps callers
/// simple and matches `reqwest::blocking`.
pub trait FulcioClient {
    /// Submit a CSR + OIDC token, return the signed cert chain.
    fn sign_csr(&self, csr: &Csr, oidc_token: &str) -> Result<CertChain, FulcioError>;
}

// ---------------------------------------------------------------
// Mock client
// ---------------------------------------------------------------

/// Returns a pre-baked canned chain. Used by every test that
/// exercises the *consumer* side of `FulcioClient` without paying
/// the cost (or flake risk) of real network IO.
///
/// The chain is generated deterministically the first time it's
/// asked for and cached — same PEM bytes every run.
pub struct MockFulcioClient {
    chain_pem: String,
}

impl MockFulcioClient {
    /// Build a mock client with the default canned chain (leaf
    /// SAN = `dev@example.com`).
    pub fn new() -> Self {
        Self {
            chain_pem: test_fixtures::CANNED_CHAIN_PEM.to_string(),
        }
    }

    /// Build a mock client that returns the supplied PEM verbatim.
    /// Used by tests that want to feed a pathological chain (empty,
    /// malformed, …) through the trait surface.
    pub fn with_chain_pem(chain_pem: impl Into<String>) -> Self {
        Self {
            chain_pem: chain_pem.into(),
        }
    }
}

impl Default for MockFulcioClient {
    fn default() -> Self {
        Self::new()
    }
}

impl FulcioClient for MockFulcioClient {
    fn sign_csr(&self, _csr: &Csr, oidc_token: &str) -> Result<CertChain, FulcioError> {
        if oidc_token.is_empty() {
            // Real Fulcio rejects this with HTTP 401; the mock
            // mirrors that so consumers can test the error path.
            return Err(FulcioError::Status {
                status: 401,
                body: "missing OIDC token".to_string(),
            });
        }
        let certs = parse_chain(self.chain_pem.as_bytes())?;
        Ok(CertChain {
            certs,
            raw_pem: self.chain_pem.clone(),
        })
    }
}

// ---------------------------------------------------------------
// Real HTTP client
// ---------------------------------------------------------------

/// Blocking Fulcio HTTP client. Hits
/// `POST {base_url}/api/v2/signingCert` with a JSON body carrying
/// the PEM-encoded CSR + the OIDC token.
///
/// Wire format (Fulcio v2):
/// ```json
/// {
///   "credentials": { "oidcIdentityToken": "<token>" },
///   "publicKeyRequest": {
///     "publicKey": { "algorithm": "ECDSA", "content": "<PEM pubkey>" },
///     "proofOfPossession": "<base64 sig over subject>"
///   },
///   "certificateSigningRequest": "<PEM CSR>"
/// }
/// ```
///
/// v0 sends `certificateSigningRequest` only — Fulcio accepts the
/// CSR-only form when the public key + PoP can be derived from the
/// CSR itself. The other shape is wired in a later slice.
pub struct HttpFulcioClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

impl HttpFulcioClient {
    /// Build a client against `base_url` (e.g.
    /// `https://fulcio.sigstage.dev`). Trailing slash is tolerated.
    pub fn new(base_url: impl Into<String>) -> Result<Self, FulcioError> {
        let http = reqwest::blocking::Client::builder()
            .user_agent(concat!("swe_justsign_fulcio/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Inject a pre-built reqwest client (used by tests that point
    /// at a local mock server). The `base_url` is normalized.
    pub fn with_http(base_url: impl Into<String>, http: reqwest::blocking::Client) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        }
    }
}

impl FulcioClient for HttpFulcioClient {
    fn sign_csr(&self, csr: &Csr, oidc_token: &str) -> Result<CertChain, FulcioError> {
        if oidc_token.is_empty() {
            return Err(FulcioError::Status {
                status: 400,
                body: "client refused to send empty OIDC token".to_string(),
            });
        }

        // Fulcio v2 JSON request body. We construct it inline rather
        // than dragging a dedicated struct into the public surface
        // for v0; the shape is small and the protobuf-derived names
        // are quirky enough that a hand-rolled JSON body is clearer.
        let body = serde_json::json!({
            "credentials": { "oidcIdentityToken": oidc_token },
            "certificateSigningRequest": csr.pem,
        });

        let url = format!("{}/api/v2/signingCert", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/pem-certificate-chain")
            .json(&body)
            .send()?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_else(|_| String::from("<unreadable>"));
            return Err(FulcioError::Status {
                status: status.as_u16(),
                body,
            });
        }

        // Fulcio returns either:
        //  * `application/pem-certificate-chain` — raw PEM, or
        //  * `application/json` with a `signedCertificateEmbeddedSct`
        //    field containing the chain.
        // v0 handles both: try PEM first, fall back to JSON.
        let body_bytes = resp.bytes()?;
        let raw_pem = if looks_like_pem(&body_bytes) {
            String::from_utf8_lossy(&body_bytes).to_string()
        } else {
            extract_pem_from_json(&body_bytes)?
        };

        let certs = parse_chain(raw_pem.as_bytes())?;
        Ok(CertChain { certs, raw_pem })
    }
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    // Cheap sniff — good enough for v0; real content negotiation
    // would key off the response Content-Type.
    bytes
        .windows(b"-----BEGIN".len())
        .any(|w| w == b"-----BEGIN")
}

fn extract_pem_from_json(bytes: &[u8]) -> Result<String, FulcioError> {
    // Two known shapes:
    //   { "signedCertificateEmbeddedSct": { "chain": { "certificates": ["<PEM>", ...] } } }
    //   { "signedCertificateDetachedSct":  { "chain": { "certificates": ["<PEM>", ...] } } }
    let v: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| FulcioError::X509(format!("response JSON parse: {e}")))?;

    let chain = v
        .get("signedCertificateEmbeddedSct")
        .or_else(|| v.get("signedCertificateDetachedSct"))
        .and_then(|x| x.get("chain"))
        .and_then(|x| x.get("certificates"))
        .and_then(|x| x.as_array())
        .ok_or_else(|| {
            FulcioError::X509("response JSON has no chain.certificates field".to_string())
        })?;

    let mut out = String::new();
    for cert in chain {
        let s = cert.as_str().ok_or_else(|| {
            FulcioError::X509("chain.certificates entry not a string".to_string())
        })?;
        out.push_str(s);
        if !s.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------
//
// We generate the canned chain deterministically once and cache it
// in a `LazyLock<String>`. Same bytes every run, no I/O, no clock.
//
// The chain is intentionally synthetic — it's not signed by a
// trusted root, it just *looks* like a Fulcio response (3 PEM
// blocks, leaf first, leaf carries an rfc822Name SAN).

pub mod test_fixtures {
    pub use private::CANNED_CHAIN_PEM;

    mod private {
        use core::str::FromStr;
        use der::{asn1::Ia5String, Decode, Encode};
        use once_cell::sync::Lazy;
        use p256::ecdsa::{DerSignature, SigningKey};
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;
        use x509_cert::{
            builder::{Builder, CertificateBuilder, Profile},
            ext::pkix::{name::GeneralName, SubjectAltName},
            name::Name,
            serial_number::SerialNumber,
            spki::SubjectPublicKeyInfoOwned,
            time::Validity,
        };

        /// The canned 3-cert chain (leaf, intermediate, root).
        /// Generated lazily once; same PEM bytes for the lifetime
        /// of the process. `once_cell::Lazy` rather than the std
        /// `LazyLock` because MSRV here is 1.75 and `LazyLock` is
        /// 1.80+.
        pub static CANNED_CHAIN_PEM: Lazy<String> = Lazy::new(build_canned_chain);

        fn build_canned_chain() -> String {
            // Three deterministic seeds → three keys.
            let root_key = key_from_seed(0xAA_AA_AA_AA);
            let int_key = key_from_seed(0xBB_BB_BB_BB);
            let leaf_key = key_from_seed(0xCC_CC_CC_CC);

            let validity = Validity::from_now(core::time::Duration::from_secs(60 * 60 * 24 * 30))
                .expect("validity");

            // Root: self-signed.
            let root_subj = Name::from_str("CN=justsign-test-root,O=justsign-test").expect("dn");
            let root_spki = pubkey_spki(&root_key);
            let root_cert = build_cert(
                Profile::Root,
                SerialNumber::from(1u32),
                validity,
                root_subj.clone(),
                root_spki,
                &root_key,
            );

            // Intermediate: signed by root.
            let int_subj =
                Name::from_str("CN=justsign-test-intermediate,O=justsign-test").expect("dn");
            let int_spki = pubkey_spki(&int_key);
            let int_cert = build_cert(
                Profile::SubCA {
                    issuer: root_subj.clone(),
                    path_len_constraint: Some(0),
                },
                SerialNumber::from(2u32),
                validity,
                int_subj.clone(),
                int_spki,
                &root_key,
            );

            // Leaf: signed by intermediate, with rfc822Name SAN.
            let leaf_subj = Name::from_str("CN=dev@example.com").expect("dn");
            let leaf_spki = pubkey_spki(&leaf_key);
            let san = SubjectAltName(vec![GeneralName::Rfc822Name(
                Ia5String::new("dev@example.com").expect("ia5"),
            )]);
            let mut leaf_builder = CertificateBuilder::new(
                Profile::Leaf {
                    issuer: int_subj.clone(),
                    enable_key_agreement: false,
                    enable_key_encipherment: false,
                },
                SerialNumber::from(3u32),
                validity,
                leaf_subj,
                leaf_spki,
                &int_key,
            )
            .expect("leaf builder");
            leaf_builder.add_extension(&san).expect("add SAN");
            let leaf_cert = leaf_builder.build::<DerSignature>().expect("leaf build");

            // Concatenate as PEM, leaf-first (Fulcio's order).
            let mut out = String::new();
            for cert in [&leaf_cert, &int_cert, &root_cert] {
                let der = cert.to_der().expect("to_der");
                // Round-trip safety: the parse_chain DER round-trip
                // check requires strict-DER input. Our builder
                // produces strict-DER, but we re-decode to be sure.
                let _ = x509_cert::Certificate::from_der(&der).expect("strict-DER round trip");
                let block = pem::Pem::new("CERTIFICATE", der);
                out.push_str(&pem::encode(&block));
            }
            out
        }

        fn key_from_seed(seed: u64) -> SigningKey {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            SigningKey::random(&mut rng)
        }

        fn pubkey_spki(sk: &SigningKey) -> SubjectPublicKeyInfoOwned {
            let vk = sk.verifying_key();
            let der = vk.to_public_key_der().expect("pk to_der");
            SubjectPublicKeyInfoOwned::from_der(der.as_bytes()).expect("spki decode")
        }

        fn build_cert(
            profile: Profile,
            serial: SerialNumber,
            validity: Validity,
            subject: Name,
            spki: SubjectPublicKeyInfoOwned,
            signer: &SigningKey,
        ) -> x509_cert::Certificate {
            let builder = CertificateBuilder::new(profile, serial, validity, subject, spki, signer)
                .expect("cert builder");
            builder.build::<DerSignature>().expect("cert build")
        }

        // Bring `to_public_key_der` into scope.
        use p256::pkcs8::EncodePublicKey as _;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csr::build_csr;
    use p256::ecdsa::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn seeded_key() -> SigningKey {
        let mut rng = ChaCha20Rng::seed_from_u64(0xDEADBEEF_u64);
        SigningKey::random(&mut rng)
    }

    #[test]
    fn test_mock_sign_csr_with_token_returns_canned_chain() {
        // Bug it catches: a regression where MockFulcioClient
        // returns a zero-length chain or the wrong leaf SAN.
        let key = seeded_key();
        let csr = build_csr(&key, "dev@example.com").expect("csr");
        let mock = MockFulcioClient::new();

        let chain = mock.sign_csr(&csr, "fake-oidc-token").expect("sign");
        assert_eq!(chain.certs.len(), 3, "leaf + intermediate + root");
        assert!(chain
            .leaf()
            .san_emails()
            .contains(&"dev@example.com".to_string()));
        assert!(chain.raw_pem.contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn test_mock_sign_csr_with_empty_token_returns_status_401() {
        // Bug it catches: silently accepting an empty OIDC token
        // and producing a chain. Real Fulcio returns 401 here, and
        // the mock must mirror that so callers can test the error
        // path without standing up a network mock.
        let key = seeded_key();
        let csr = build_csr(&key, "dev@example.com").expect("csr");
        let mock = MockFulcioClient::new();
        let err = mock.sign_csr(&csr, "").expect_err("empty token");
        match err {
            FulcioError::Status { status, .. } => assert_eq!(status, 401),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn test_mock_sign_csr_with_empty_chain_pem_returns_empty_chain_error() {
        // Bug it catches: the trait swallowing parse_chain errors.
        let key = seeded_key();
        let csr = build_csr(&key, "dev@example.com").expect("csr");
        let mock = MockFulcioClient::with_chain_pem("");
        let err = mock.sign_csr(&csr, "tok").expect_err("empty chain");
        assert!(matches!(err, FulcioError::EmptyChain), "got {err:?}");
    }

    #[test]
    fn test_http_client_with_empty_token_short_circuits_without_network() {
        // Bug it catches: HttpFulcioClient sending an empty token
        // to the network. Must fail fast client-side.
        let key = seeded_key();
        let csr = build_csr(&key, "dev@example.com").expect("csr");
        let client = HttpFulcioClient::new("https://invalid.example.invalid").expect("client");
        let err = client.sign_csr(&csr, "").expect_err("empty token");
        match err {
            FulcioError::Status { status, .. } => assert_eq!(status, 400),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// Live integration test against Sigstore's staging Fulcio.
    ///
    /// **This is `#[ignore]`d.** It only runs when both:
    /// 1. you pass `--ignored` to cargo test, and
    /// 2. `JUSTSIGN_FULCIO_STAGING=1` is set in the environment.
    ///
    /// Activating it for real also requires a valid OIDC ID token
    /// from a Sigstore-trusted issuer (Google / GitHub / etc.) in
    /// `JUSTSIGN_FULCIO_OIDC_TOKEN`. Without it the test exits in
    /// skip-pass mode — compiles, links, prints SKIP, returns
    /// cleanly — so CI on `cargo test -- --ignored` doesn't fail
    /// just because no human is around to mint a token.
    #[test]
    #[ignore = "live network; requires JUSTSIGN_FULCIO_STAGING=1 + valid OIDC token"]
    fn test_http_client_against_sigstore_staging_skip_pass() {
        if std::env::var("JUSTSIGN_FULCIO_STAGING").as_deref() != Ok("1") {
            eprintln!("SKIP: JUSTSIGN_FULCIO_STAGING not set — staging Fulcio test skipped");
            return;
        }
        let token = match std::env::var("JUSTSIGN_FULCIO_OIDC_TOKEN") {
            Ok(t) if !t.is_empty() => t,
            _ => {
                eprintln!("SKIP: JUSTSIGN_FULCIO_OIDC_TOKEN not set — cannot mint staging cert");
                return;
            }
        };

        let key = seeded_key();
        let csr = build_csr(&key, "dev@example.com").expect("csr");
        let client = HttpFulcioClient::new("https://fulcio.sigstage.dev").expect("client");
        let chain = client.sign_csr(&csr, &token).expect("staging sign_csr");
        assert!(!chain.certs.is_empty(), "staging chain must be non-empty");
    }
}
