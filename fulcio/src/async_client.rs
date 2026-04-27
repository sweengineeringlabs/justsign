//! Async (`tokio`-flavoured) Fulcio client.
//!
//! Gated behind the `async` Cargo feature. The default build is
//! blocking — see `client::FulcioClient` / `HttpFulcioClient`. v0
//! shipped synchronous-only because:
//!
//! * Most justsign callers (the CLI, smoke tests, fixture
//!   generators) are short-lived single-shot processes — wrapping
//!   them in a runtime is overhead, not leverage.
//! * `reqwest::blocking` keeps the surface mockable without a
//!   runtime, which keeps tests fast and the dep graph small.
//!
//! Async is opt-in for a different audience: callers who already
//! run inside `tokio` (a server, a long-lived service, a WASM
//! runtime polyfill) and want the Fulcio call to compose with
//! their existing `.await` chain instead of blocking the executor
//! via `tokio::task::spawn_blocking`.
//!
//! ## Surface
//!
//! * [`AsyncFulcioClient`] — mirrors [`crate::FulcioClient`]
//!   exactly, with `async fn sign_csr(...)` instead of `fn`.
//! * [`HttpFulcioClientAsync`] — `reqwest::Client` (non-blocking)
//!   backed impl. Same wire shape as [`crate::HttpFulcioClient`];
//!   reuses the same JSON body, the same response sniff, the same
//!   error mapping.
//!
//! The shared types (`Csr`, `CertChain`, `FulcioError`) are
//! transport-free, so they cross the sync/async boundary verbatim.
//! There is no async mock client: tests that exercise the
//! *consumer* of the trait should keep using
//! [`crate::MockFulcioClient`] in a `spawn_blocking` if needed,
//! or a custom test impl of `AsyncFulcioClient` for round-trips
//! that genuinely need to be async.

use async_trait::async_trait;

use crate::chain::parse_chain;
use crate::client::CertChain;
use crate::csr::Csr;
use crate::error::FulcioError;

/// The async Fulcio surface. Method signatures mirror
/// [`crate::FulcioClient`] one-for-one — only the `async fn` /
/// `Future` shape differs. Object-safe via `async_trait`.
#[async_trait]
pub trait AsyncFulcioClient: Send + Sync {
    /// Submit a CSR + OIDC token, return the signed cert chain.
    async fn sign_csr(&self, csr: &Csr, oidc_token: &str) -> Result<CertChain, FulcioError>;
}

/// Non-blocking Fulcio HTTP client.
///
/// Hits `POST {base_url}/api/v2/signingCert` with the same JSON
/// body as [`crate::HttpFulcioClient`]. Differences vs the
/// blocking client are confined to:
///
/// * `reqwest::Client` (non-blocking) instead of
///   `reqwest::blocking::Client`.
/// * `.send().await` / `.bytes().await` instead of the blocking
///   equivalents.
///
/// Wire format, error mapping, URL normalisation, and PEM-vs-JSON
/// response sniffing match the blocking client exactly. Any
/// behaviour drift between the two is a bug in this file.
pub struct HttpFulcioClientAsync {
    base_url: String,
    http: reqwest::Client,
}

impl HttpFulcioClientAsync {
    /// Build an async client against `base_url` (e.g.
    /// `https://fulcio.sigstage.dev`). Trailing slash is
    /// tolerated.
    pub fn new(base_url: impl Into<String>) -> Result<Self, FulcioError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!(
                "swe_justsign_fulcio/",
                env!("CARGO_PKG_VERSION"),
                "+async"
            ))
            .build()?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Inject a pre-built non-blocking reqwest client (used by
    /// tests that point at a local mock server). The `base_url` is
    /// normalised the same way [`Self::new`] would.
    pub fn with_http(base_url: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        }
    }

    /// Borrow the (normalised) base URL — exposed for tests that
    /// need to assert constructor invariants.
    #[cfg(test)]
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }
}

#[async_trait]
impl AsyncFulcioClient for HttpFulcioClientAsync {
    async fn sign_csr(&self, csr: &Csr, oidc_token: &str) -> Result<CertChain, FulcioError> {
        if oidc_token.is_empty() {
            // Match the blocking client: fail fast client-side, no
            // network round trip. Status 400 mirrors the blocking
            // path so callers can pattern-match the same way
            // regardless of which transport they picked.
            return Err(FulcioError::Status {
                status: 400,
                body: "client refused to send empty OIDC token".to_string(),
            });
        }

        // Same JSON body shape as the blocking client — keep them
        // in lock-step or wire drift between transports turns a
        // working blocking integration into a broken async one.
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
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| String::from("<unreadable>"));
            return Err(FulcioError::Status {
                status: status.as_u16(),
                body,
            });
        }

        // Fulcio returns either `application/pem-certificate-chain`
        // (raw PEM) or `application/json` (signedCert*). Mirror the
        // blocking client's content sniff exactly.
        let body_bytes = resp.bytes().await?;
        let raw_pem = if looks_like_pem(&body_bytes) {
            String::from_utf8_lossy(&body_bytes).to_string()
        } else {
            extract_pem_from_json(&body_bytes)?
        };

        let certs = parse_chain(raw_pem.as_bytes())?;
        Ok(CertChain { certs, raw_pem })
    }
}

// ── Body-format helpers ──────────────────────────────────────────
//
// These mirror the private helpers in `client.rs`. Duplicated
// rather than re-exported because they're response-shape adapters,
// not part of the public surface, and lifting them to a shared
// module would force every blocking-only build to compile through
// the cfg-gated import path.

fn looks_like_pem(bytes: &[u8]) -> bool {
    bytes
        .windows(b"-----BEGIN".len())
        .any(|w| w == b"-----BEGIN")
}

fn extract_pem_from_json(bytes: &[u8]) -> Result<String, FulcioError> {
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

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_fixtures::CANNED_CHAIN_PEM;
    use crate::csr::build_csr;
    use p256::ecdsa::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    fn seeded_key() -> SigningKey {
        let mut rng = ChaCha20Rng::seed_from_u64(0xCAFE_BABE_u64);
        SigningKey::random(&mut rng)
    }

    /// Minimal local HTTP server: serves one canned response per
    /// connection with the supplied status + body. Mirrors the
    /// `LocalServer` pattern from the TUF crate — raw `TcpListener`
    /// is enough because we test exactly one verb per scenario and
    /// don't care about routing or keep-alive.
    ///
    /// Drop = wake the accept thread via a sentinel TCP connect so
    /// the test can return without leaking the server thread.
    struct LocalServer {
        base_url: String,
        port: u16,
        shutdown: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl LocalServer {
        fn start(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
            let port = listener.local_addr().unwrap().port();
            let base_url = format!("http://127.0.0.1:{port}");
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_t = Arc::clone(&shutdown);

            let handle = thread::spawn(move || loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                if shutdown_t.load(Ordering::SeqCst) {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .expect("write timeout");

                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }

                // Read headers until blank line, then read the body
                // by Content-Length — Fulcio POSTs are small enough
                // that a fixed-size buffer is fine.
                let mut content_length: usize = 0;
                loop {
                    let mut hdr = String::new();
                    match reader.read_line(&mut hdr) {
                        Ok(0) => break,
                        Ok(_) => {
                            if hdr == "\r\n" || hdr == "\n" {
                                break;
                            }
                            if let Some(rest) =
                                hdr.to_ascii_lowercase().strip_prefix("content-length:")
                            {
                                content_length = rest.trim().parse().unwrap_or(0);
                            }
                        }
                        Err(_) => break,
                    }
                }
                if content_length > 0 {
                    let mut body_buf = vec![0u8; content_length];
                    use std::io::Read as _;
                    let _ = reader.read_exact(&mut body_buf);
                }

                let header = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status,
                    status_reason(status),
                    content_type,
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Both);
            });

            Self {
                base_url,
                port,
                shutdown,
                handle: Some(handle),
            }
        }
    }

    fn status_reason(code: u16) -> &'static str {
        match code {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            500 => "Internal Server Error",
            _ => "Status",
        }
    }

    impl Drop for LocalServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
            // Wake the accept thread.
            let _ = std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{}", self.port).parse().unwrap(),
                Duration::from_secs(2),
            );
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    /// Constructor smoke test — no I/O. Bug it catches: a regression
    /// where `HttpFulcioClientAsync::new` fails to build (e.g. the
    /// reqwest `Client` builder picks up an incompatible feature
    /// combination) or strips the wrong characters from the base
    /// URL.
    #[test]
    fn test_http_fulcio_client_async_new_strips_trailing_slash_from_base_url() {
        let with_slash = HttpFulcioClientAsync::new("https://fulcio.example/").expect("client");
        let without_slash = HttpFulcioClientAsync::new("https://fulcio.example").expect("client");
        assert_eq!(with_slash.base_url(), "https://fulcio.example");
        assert_eq!(without_slash.base_url(), "https://fulcio.example");
    }

    /// Empty OIDC token must short-circuit client-side with status
    /// 400, no network round-trip. Mirrors the blocking client's
    /// contract — async callers should be able to pattern-match the
    /// same way.
    ///
    /// Bug it catches: an async impl that forwards an empty token
    /// to the server. Real Fulcio would 401, but the cost is a
    /// pointless network round-trip on a path the client knows is
    /// invalid. Pinning the 400 response also keeps the async +
    /// blocking surfaces interchangeable for downstream callers.
    #[tokio::test]
    async fn test_async_sign_csr_with_empty_token_short_circuits_with_status_400() {
        let key = seeded_key();
        let csr = build_csr(&key, "dev@example.com").expect("csr");
        let client = HttpFulcioClientAsync::new("https://invalid.example.invalid").expect("client");
        let err = client.sign_csr(&csr, "").await.expect_err("empty token");
        match err {
            FulcioError::Status { status, .. } => assert_eq!(status, 400),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// Happy-path round trip: local HTTP server returns a canned
    /// PEM chain, async client decodes it.
    ///
    /// Bug it catches: the async response-body path (PEM sniff,
    /// `parse_chain` invocation) drifting from the blocking client.
    /// This is the load-bearing wire test for the async surface —
    /// without it, only the empty-token short-circuit is exercised.
    #[tokio::test]
    async fn test_async_sign_csr_against_local_server_returns_parsed_chain() {
        let pem = CANNED_CHAIN_PEM.clone();
        let server = LocalServer::start(200, "application/pem-certificate-chain", pem.into_bytes());
        let key = seeded_key();
        let csr = build_csr(&key, "dev@example.com").expect("csr");
        let client = HttpFulcioClientAsync::new(&server.base_url).expect("client");
        let chain = client
            .sign_csr(&csr, "fake-oidc-token")
            .await
            .expect("sign");
        assert_eq!(chain.certs.len(), 3, "leaf + intermediate + root");
        assert!(chain.raw_pem.contains("-----BEGIN CERTIFICATE-----"));
    }

    /// Server-side 4xx must map to `FulcioError::Status` carrying
    /// the upstream code + body verbatim — mirrors the blocking
    /// client and pins the contract for any async-aware retry /
    /// alerting layer.
    ///
    /// Bug it catches: an async impl that swallows `resp.text()`
    /// errors into a generic `Http(_)` variant, hiding the actual
    /// upstream response from the operator.
    #[tokio::test]
    async fn test_async_sign_csr_4xx_response_maps_to_status_error() {
        let server = LocalServer::start(
            403,
            "application/json",
            b"{\"code\":403,\"message\":\"forbidden\"}".to_vec(),
        );
        let key = seeded_key();
        let csr = build_csr(&key, "dev@example.com").expect("csr");
        let client = HttpFulcioClientAsync::new(&server.base_url).expect("client");
        let err = client
            .sign_csr(&csr, "non-empty-token")
            .await
            .expect_err("server said 403");
        match err {
            FulcioError::Status { status, body } => {
                assert_eq!(status, 403);
                assert!(body.contains("forbidden"), "body was {body:?}");
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// Trait object-safety — same compile-time check the blocking
    /// trait already pins. Without `#[async_trait]`'s erasure this
    /// would fail to build.
    ///
    /// Bug it catches: someone adding a generic method or `Self`
    /// return on the trait surface in a future change, which would
    /// silently break dyn dispatch and force every consumer to
    /// thread a generic.
    #[test]
    fn test_async_fulcio_client_trait_is_object_safe() {
        let client = HttpFulcioClientAsync::new("https://fulcio.example").expect("client");
        let _erased: Box<dyn AsyncFulcioClient> = Box::new(client);
    }
}
