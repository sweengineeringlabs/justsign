//! Async (`tokio`-flavoured) Rekor client.
//!
//! Gated behind the `async` Cargo feature. The default build is
//! blocking — see `client::RekorClient` / `HttpRekorClient`. v0
//! shipped synchronous-only because:
//!
//! * Most justsign callers (the CLI, smoke tests, fixture
//!   generators) are short-lived single-shot processes — wrapping
//!   them in a runtime is overhead, not leverage.
//! * `reqwest::blocking` keeps the surface mockable without a
//!   runtime, which keeps tests fast and the dep graph small.
//!
//! Async is opt-in for a different audience: callers who already
//! run inside `tokio` (a server, a long-lived service) and want
//! the Rekor submit/fetch round-trip to compose with their
//! existing `.await` chain instead of blocking the executor via
//! `tokio::task::spawn_blocking`.
//!
//! ## Surface
//!
//! * [`AsyncRekorClient`] — mirrors [`crate::RekorClient`]
//!   exactly, with `async fn submit(...)` instead of `fn`.
//! * [`HttpRekorClientAsync`] — `reqwest::Client` (non-blocking)
//!   backed impl. Same wire shape as [`crate::HttpRekorClient`];
//!   reuses the same JSON envelope, the same response decoder
//!   ([`crate::client::decode_log_entry_bytes`]), the same error
//!   mapping. An inherent `fetch(uuid).await` mirrors the
//!   blocking client.
//!
//! Shared types (`HashedRekord`, `LogEntry`, `RekorError`) are
//! transport-free, so they cross the sync/async boundary verbatim.

use async_trait::async_trait;

use crate::client::{classify_non_success, decode_log_entry_bytes, LogEntry};
use crate::entry::{DsseRekord, HashedRekord};
use crate::RekorError;

/// Default timeout for a single async HTTP exchange with Rekor.
///
/// Mirrors the blocking client's 30-second budget so callers don't
/// see different timeout semantics depending on which transport
/// they picked.
const HTTP_TIMEOUT_SECS: u64 = 30;

/// The async Rekor surface. Method signatures mirror
/// [`crate::RekorClient`] one-for-one — only the `async fn` /
/// `Future` shape differs. Object-safe via `async_trait`.
#[async_trait]
pub trait AsyncRekorClient: Send + Sync {
    /// Submit a `hashedrekord` entry, return the resulting
    /// [`LogEntry`] (UUID, log index, inclusion proof, body).
    async fn submit(&self, entry: &HashedRekord) -> Result<LogEntry, RekorError>;

    /// Submit a `dsse` entry (signature over the DSSE PAE bytes).
    ///
    /// Default impl returns [`RekorError::Unsupported`] so external
    /// async-trait impls written before issue #39 keep building.
    /// The in-tree client ([`HttpRekorClientAsync`]) overrides the
    /// default. Mirrors [`crate::RekorClient::submit_dsse`] on the
    /// blocking trait.
    async fn submit_dsse(&self, _entry: &DsseRekord) -> Result<LogEntry, RekorError> {
        Err(RekorError::Unsupported {
            operation: "submit_dsse",
        })
    }
}

/// Non-blocking Rekor HTTP client.
///
/// Hits `POST {base_url}/api/v1/log/entries` with the same JSON
/// envelope as [`crate::HttpRekorClient`]. Differences vs the
/// blocking client are confined to:
///
/// * `reqwest::Client` (non-blocking) instead of
///   `reqwest::blocking::Client`.
/// * `.send().await` / `.bytes().await` / `.text().await` instead
///   of the blocking equivalents.
///
/// Wire format, error mapping, URL normalisation, and response
/// decoding match the blocking client exactly — both transports
/// route through [`decode_log_entry_bytes`] for the success path.
pub struct HttpRekorClientAsync {
    base_url: String,
    http: reqwest::Client,
}

impl HttpRekorClientAsync {
    /// Build an async client against `base_url` (e.g.
    /// `https://rekor.sigstage.dev`). Trailing slash is tolerated.
    pub fn new(base_url: impl Into<String>) -> Result<Self, RekorError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!(
                "swe_justsign_rekor/",
                env!("CARGO_PKG_VERSION"),
                "+async"
            ))
            .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
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

    /// `GET /api/v1/log/entries/{uuid}` — fetch a previously-
    /// submitted log entry by its server-assigned UUID. Mirrors
    /// the blocking client's inherent `fetch`. Inherent (not on
    /// the trait) because the v0 trait surface is `submit`-only.
    pub async fn fetch(&self, uuid: &str) -> Result<LogEntry, RekorError> {
        let url = format!("{}/api/v1/log/entries/{}", self.base_url, uuid);
        let resp = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await?;
        decode_async(resp).await
    }

    /// Borrow the (normalised) base URL — exposed for tests that
    /// need to assert constructor invariants.
    #[cfg(test)]
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }
}

#[async_trait]
impl AsyncRekorClient for HttpRekorClientAsync {
    async fn submit(&self, entry: &HashedRekord) -> Result<LogEntry, RekorError> {
        // Same envelope as the blocking client. Keep them
        // lock-step or wire drift between transports turns a
        // working blocking integration into a broken async one.
        let spec_value: serde_json::Value = serde_json::from_slice(&entry.encode_json()?)?;
        let body = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": spec_value,
        });

        let url = format!("{}/api/v1/log/entries", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await?;
        decode_async(resp).await
    }

    async fn submit_dsse(&self, entry: &DsseRekord) -> Result<LogEntry, RekorError> {
        // Mirror the blocking `submit_dsse` envelope shape exactly —
        // keep the two transports lock-step so a fix on one path
        // is automatically available on the other.
        let spec_value: serde_json::Value = serde_json::from_slice(&entry.encode_json()?)?;
        let body = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": spec_value,
        });

        let url = format!("{}/api/v1/log/entries", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await?;
        decode_async(resp).await
    }
}

/// Async counterpart to `client::decode_log_entry_response`. The
/// status check and the `text()` fallback live here — the body
/// decode path is shared with the blocking client via
/// [`decode_log_entry_bytes`], and the non-2xx classification is
/// shared via [`classify_non_success`] so the blocking and async
/// transports produce identical error variants for identical
/// responses.
async fn decode_async(resp: reqwest::Response) -> Result<LogEntry, RekorError> {
    let status = resp.status();
    let code = status.as_u16();
    if status.is_success() {
        let raw = resp.bytes().await?;
        return decode_log_entry_bytes(&raw);
    }
    let body = resp
        .text()
        .await
        .unwrap_or_else(|_| String::from("<unreadable>"));
    Err(classify_non_success(code, body))
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Data, HashedRekord, HashedRekordHash, PublicKey, Signature};
    use crate::merkle::hash_leaf;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    fn sample_record() -> HashedRekord {
        HashedRekord {
            signature: Signature {
                content: b"sig-bytes".to_vec(),
                public_key: PublicKey {
                    content: b"pk-bytes".to_vec(),
                },
            },
            data: Data {
                hash: HashedRekordHash {
                    algorithm: "sha256".into(),
                    value: "00".repeat(32),
                },
            },
        }
    }

    /// Build a Rekor-shaped JSON response for the success path.
    /// `body_bytes` is the canonical JSON the server stored — the
    /// fixture base64-encodes it the way real Rekor does.
    fn rekor_success_envelope(uuid: &str, body_bytes: &[u8]) -> Vec<u8> {
        let leaf_hex = {
            let h = hash_leaf(body_bytes);
            let mut s = String::with_capacity(64);
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for b in &h {
                s.push(HEX[(b >> 4) as usize] as char);
                s.push(HEX[(b & 0x0f) as usize] as char);
            }
            s
        };
        let body_b64 = STANDARD.encode(body_bytes);
        let json = serde_json::json!({
            uuid: {
                "body": body_b64,
                "logIndex": 0,
                "verification": {
                    "inclusionProof": {
                        "hashes": Vec::<String>::new(),
                        "logIndex": 0,
                        "rootHash": leaf_hex,
                        "treeSize": 1,
                    }
                }
            }
        });
        serde_json::to_vec(&json).expect("envelope")
    }

    /// Minimal local HTTP server — same pattern used by the
    /// `tuf::client` tests and the fulcio async tests. Serves one
    /// canned response per connection. Drop = wake the accept
    /// thread via a sentinel TCP connect so tests don't leak.
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
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "Status",
        }
    }

    impl Drop for LocalServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
            let _ = std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{}", self.port).parse().unwrap(),
                Duration::from_secs(2),
            );
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    /// Constructor smoke — no I/O. Bug it catches: a regression
    /// where `HttpRekorClientAsync::new` fails to build (incompatible
    /// reqwest features) or fails to normalise the base URL,
    /// silently doubling the path separator on every submit.
    #[test]
    fn test_http_rekor_client_async_new_strips_trailing_slash_from_base_url() {
        let with_slash = HttpRekorClientAsync::new("https://rekor.example/").expect("client");
        let without_slash = HttpRekorClientAsync::new("https://rekor.example").expect("client");
        assert_eq!(with_slash.base_url(), "https://rekor.example");
        assert_eq!(without_slash.base_url(), "https://rekor.example");
    }

    /// Trait object-safety check — same constraint as the blocking
    /// trait. Without `#[async_trait]` erasure this would fail to
    /// build.
    ///
    /// Bug it catches: someone adding a generic method or `Self`
    /// return on the trait surface, silently breaking dyn dispatch
    /// and forcing every consumer to thread a generic.
    #[test]
    fn test_async_rekor_client_trait_is_object_safe() {
        let client = HttpRekorClientAsync::new("https://rekor.example").expect("client");
        let _erased: Box<dyn AsyncRekorClient> = Box::new(client);
    }

    /// Happy-path round trip: local HTTP server returns a Rekor-
    /// shaped envelope, async client decodes a `LogEntry`.
    ///
    /// Bug it catches: divergence between the async submit body /
    /// response decode and the blocking client. This is the
    /// load-bearing wire test for the async surface — without it,
    /// only the constructor + dyn-safety are exercised.
    #[tokio::test]
    async fn test_async_submit_against_local_server_returns_log_entry() {
        let entry = sample_record();
        let body = entry.encode_json().expect("encode");
        let envelope = rekor_success_envelope("deadbeef-0000", &body);
        let server = LocalServer::start(201, "application/json", envelope);

        let client = HttpRekorClientAsync::new(&server.base_url).expect("client");
        let log_entry = client.submit(&entry).await.expect("submit");

        assert_eq!(log_entry.uuid, "deadbeef-0000");
        assert_eq!(log_entry.tree_size, 1);
        assert_eq!(log_entry.body, body);
        assert!(log_entry.inclusion_proof.is_empty());
        // Self-consistency: the canned proof reconstructs its own
        // root, just like the mock client guarantees.
        log_entry
            .verify_self_consistent()
            .expect("envelope must be self-consistent");
    }

    /// Server-side 4xx (rate-limit, validation error) must map to
    /// [`RekorError::ClientError`] carrying the upstream code +
    /// body verbatim — mirrors the blocking client and pins the
    /// contract for any retry / alerting layer built on top.
    ///
    /// Bug it catches: an async impl that swallows the body via a
    /// generic `Transport(_)` variant, hiding the actual server
    /// response from the operator and routing rate-limited 429s
    /// to "your network is down" instead of "you're calling too
    /// fast".
    #[tokio::test]
    async fn test_async_submit_with_429_response_returns_client_error_variant() {
        let server = LocalServer::start(
            429,
            "application/json",
            b"{\"code\":429,\"message\":\"slow down\"}".to_vec(),
        );
        let client = HttpRekorClientAsync::new(&server.base_url).expect("client");
        let err = client
            .submit(&sample_record())
            .await
            .expect_err("server said 429");
        match err {
            RekorError::ClientError { status, body } => {
                assert_eq!(status, 429);
                assert!(body.contains("slow down"), "body was {body:?}");
            }
            other => panic!("expected ClientError, got {other:?}"),
        }
    }

    /// 5xx response on the async path → [`RekorError::ServerError`].
    ///
    /// Bug it catches: divergence between sync and async classifier
    /// — both transports must route 5xx the same way, otherwise
    /// alerting policy depends on which transport the caller picked.
    #[tokio::test]
    async fn test_async_submit_with_5xx_response_returns_server_error_variant() {
        let server = LocalServer::start(
            500,
            "application/json",
            b"{\"message\":\"internal error\"}".to_vec(),
        );
        let client = HttpRekorClientAsync::new(&server.base_url).expect("client");
        let err = client
            .submit(&sample_record())
            .await
            .expect_err("server said 500");
        match err {
            RekorError::ServerError { status, body } => {
                assert_eq!(status, 500);
                assert!(body.contains("internal error"), "body was {body:?}");
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    /// 4xx with the canonical Rekor idempotency body →
    /// [`RekorError::AlreadyExists`]. Async path mirrors the
    /// blocking path's idempotency contract.
    ///
    /// Bug it catches: an async classifier that doesn't share
    /// `classify_non_success` with the blocking client would let
    /// idempotent re-submits surface as `ClientError` and break
    /// retry logic for tokio-flavoured callers (servers, long-
    /// lived signing services).
    #[tokio::test]
    async fn test_async_submit_with_canonical_already_exists_body_returns_already_exists_variant() {
        let server = LocalServer::start(
            409,
            "application/json",
            b"{\"code\":\"AlreadyExists\",\"message\":\"entry already exists\"}".to_vec(),
        );
        let client = HttpRekorClientAsync::new(&server.base_url).expect("client");
        let err = client
            .submit(&sample_record())
            .await
            .expect_err("server said 409");
        match err {
            RekorError::AlreadyExists { body } => {
                assert!(body.contains("AlreadyExists"), "body was {body:?}");
            }
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    /// 200 OK with an unparseable body → [`RekorError::Decode`]
    /// on the async path.
    ///
    /// Bug it catches: a classifier that surfaces a 200-but-bad
    /// body as `Transport(_)` (the reqwest body-read error chain)
    /// or as the generic `Json` (entry-encode) variant would
    /// conflate "the server returned garbage" with either "your
    /// network is broken" or "your input was bad".
    #[tokio::test]
    async fn test_async_submit_with_200_unparseable_body_returns_decode_variant() {
        let server = LocalServer::start(
            200,
            "text/html",
            b"<!DOCTYPE html><html><body>oops</body></html>".to_vec(),
        );
        let client = HttpRekorClientAsync::new(&server.base_url).expect("client");
        let err = client
            .submit(&sample_record())
            .await
            .expect_err("body wasn't Rekor JSON");
        match err {
            RekorError::Decode(_) => {}
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    /// Async path against an unreachable address →
    /// [`RekorError::Transport`].
    ///
    /// Bug it catches: a regression that maps
    /// connection-refused on the tokio path to a 4xx-shaped error
    /// would produce wrong retry policy for service callers (who
    /// retry transport errors with backoff, but do NOT retry
    /// 4xx because the request itself is what's wrong).
    #[tokio::test]
    async fn test_async_submit_against_unreachable_address_returns_transport_variant() {
        // Bind, capture port, drop — guarantees nothing is
        // listening for the duration of the test.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = format!("http://127.0.0.1:{port}");

        let client = HttpRekorClientAsync::new(&url).expect("client");
        let err = client
            .submit(&sample_record())
            .await
            .expect_err("must fail");
        match err {
            RekorError::Transport(_) => {}
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    /// `fetch(uuid)` decodes the same envelope shape as `submit`.
    ///
    /// Bug it catches: a regression where `fetch` and `submit`
    /// stop sharing the response decoder (either by drift or by an
    /// accidental copy-paste change to one path).
    #[tokio::test]
    async fn test_async_fetch_decodes_log_entry_envelope() {
        let entry = sample_record();
        let body = entry.encode_json().expect("encode");
        let envelope = rekor_success_envelope("cafe-d00d", &body);
        let server = LocalServer::start(200, "application/json", envelope);

        let client = HttpRekorClientAsync::new(&server.base_url).expect("client");
        let log_entry = client.fetch("cafe-d00d").await.expect("fetch");

        assert_eq!(log_entry.uuid, "cafe-d00d");
        assert_eq!(log_entry.body, body);
    }
}
