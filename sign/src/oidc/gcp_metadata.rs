//! [`GcpMetadataOidcProvider`] — fetch an instance-identity JWT from
//! the GCE metadata server.
//!
//! GCE / GKE workloads can request a signed JWT for the attached
//! service account by GETting:
//!
//! ```text
//! http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=<aud>
//! ```
//!
//! with the `Metadata-Flavor: Google` header. The response body is
//! the JWT verbatim — no JSON wrapper. This shape is what cosign,
//! sigstore-go, and the Sigstore Rust SDK all use for "ambient
//! identity on GCP".

use super::{OidcError, OidcProvider};

/// Default base URL for the GCE metadata server. Lifted out as a
/// constant so the test suite can swap it for a localhost mock.
/// Must include the scheme — reqwest rejects schemeless URLs.
const DEFAULT_METADATA_BASE_URL: &str = "http://metadata.google.internal";

/// Path the metadata server serves the identity token at. Pinned
/// per the GCE metadata-v1 spec.
const IDENTITY_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/identity";

/// Cap response-body capture at 4 KiB on error so a misbehaving
/// metadata server can't blow up our error path.
const MAX_ERROR_BODY_BYTES: usize = 4096;

/// OIDC provider that fetches an instance-identity JWT from the
/// GCE metadata server.
///
/// Configurable knobs:
///
/// * `audience` — the JWT `aud` claim. Default `"sigstore"`.
/// * `base_url` — points at the metadata server. Default
///   `http://metadata.google.internal`. Tests override this to a
///   localhost mock; production callers should never touch it.
#[derive(Debug, Clone)]
pub struct GcpMetadataOidcProvider {
    audience: String,
    base_url: String,
}

impl GcpMetadataOidcProvider {
    /// Build a provider with an explicit audience; defaults `base_url`
    /// to the production metadata server. Use `Default` for the
    /// standard sigstore audience.
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            base_url: DEFAULT_METADATA_BASE_URL.to_string(),
        }
    }

    /// Override the metadata base URL. Test-only entry point — kept
    /// `pub` rather than `pub(crate)` so that downstream
    /// integration tests can reuse the same hook against their own
    /// mock fixtures.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }
}

impl Default for GcpMetadataOidcProvider {
    fn default() -> Self {
        Self::new("sigstore")
    }
}

impl OidcProvider for GcpMetadataOidcProvider {
    fn fetch_token(&self) -> Result<String, OidcError> {
        let url = format!(
            "{}{IDENTITY_PATH}?audience={}",
            self.base_url, self.audience
        );

        let client = reqwest::blocking::Client::builder()
            .build()
            .map_err(|e| OidcError::Http(format!("build http client: {e}")))?;
        let resp = client
            .get(&url)
            // The header name is REQUIRED — the metadata server
            // refuses requests without it. This is GCE's defense
            // against SSRF: only clients that know to send this
            // header get a token.
            .header("Metadata-Flavor", "Google")
            .send()
            .map_err(|e| OidcError::Http(format!("GET {url}: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = bounded_body(resp);
            return Err(OidcError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }

        // GCE returns the JWT as `text/plain` — the body IS the
        // token, no JSON wrapper. Trim trailing whitespace to handle
        // the rare case the server emits a trailing newline.
        let body = resp
            .text()
            .map_err(|e| OidcError::Http(format!("read identity body: {e}")))?;
        Ok(body.trim().to_string())
    }
}

fn bounded_body(resp: reqwest::blocking::Response) -> String {
    match resp.text() {
        Ok(mut s) => {
            if s.len() > MAX_ERROR_BODY_BYTES {
                s.truncate(MAX_ERROR_BODY_BYTES);
                s.push_str("...[truncated]");
            }
            s
        }
        Err(e) => format!("<error body unreadable: {e}>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    /// One-shot localhost HTTP server. Same shape as the GHA test
    /// helper but kept local to this module to avoid a cross-module
    /// test-only `pub` export.
    fn spawn_one_shot_http(
        response_status_line: &'static str,
        response_body: &'static str,
        content_type: &'static str,
    ) -> (u16, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = tx.send(request);
            let body_bytes = response_body.as_bytes();
            let response = format!(
                "{response_status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                body_bytes.len()
            );
            stream.write_all(response.as_bytes()).expect("write resp");
            stream.flush().expect("flush");
        });
        (port, rx, handle)
    }

    /// Default constructor pins audience "sigstore" and the
    /// production metadata base URL.
    ///
    /// Bug it catches: a default that silently picked a different
    /// audience (e.g. the GCP-default `https://www.googleapis.com/...`)
    /// would mint tokens Fulcio rejects with a confusing audience
    /// mismatch. Pinning the default here makes the regression
    /// visible at unit-test time.
    #[test]
    fn test_default_constructor_uses_sigstore_audience_and_metadata_url() {
        let p = GcpMetadataOidcProvider::default();
        assert_eq!(p.audience, "sigstore");
        assert_eq!(p.base_url, "http://metadata.google.internal");
    }

    /// Happy path against a localhost mock: the provider GETs
    /// `<base>/computeMetadata/v1/instance/service-accounts/default/identity?audience=sigstore`
    /// with `Metadata-Flavor: Google` and returns the response body
    /// verbatim (trimmed of whitespace).
    ///
    /// Bug it catches: a missing `Metadata-Flavor` header would be
    /// silently accepted by our mock but rejected by real GCE; a
    /// path bug (e.g. a trailing-slash regression) would route to
    /// the wrong endpoint. Both are caught by asserting on the
    /// recorded request line.
    #[test]
    fn test_fetch_token_with_mock_metadata_server_returns_jwt_body() {
        let (port, rx, handle) = spawn_one_shot_http(
            "HTTP/1.1 200 OK",
            "eyJhbGciOiJSUzI1NiJ9.gce-instance-identity.sig\n",
            "text/plain",
        );
        let provider =
            GcpMetadataOidcProvider::default().with_base_url(format!("http://127.0.0.1:{port}"));
        let token = provider.fetch_token().expect("happy path must succeed");
        assert_eq!(
            token, "eyJhbGciOiJSUzI1NiJ9.gce-instance-identity.sig",
            "trailing newline must be trimmed"
        );

        let request = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("server must record one request");
        handle.join().expect("server thread must finish");

        assert!(
            request.contains(
                "GET /computeMetadata/v1/instance/service-accounts/default/identity?audience=sigstore"
            ),
            "request line must hit the identity endpoint with the audience query, got: {request}"
        );
        assert!(
            request.contains("Metadata-Flavor: Google")
                || request.contains("metadata-flavor: Google"),
            "request must carry Metadata-Flavor header, got: {request}"
        );
    }

    /// 4xx from the metadata server surfaces as `HttpStatus` with
    /// the body intact, distinguishable from a transport error.
    ///
    /// Bug it catches: a metadata-server response of "this VM has
    /// no service account attached" (a 404 in practice) being
    /// mapped to a generic transport error, which would point
    /// operators at the wrong fix.
    #[test]
    fn test_fetch_token_with_4xx_metadata_response_returns_http_status_with_body() {
        let (port, _rx, handle) = spawn_one_shot_http(
            "HTTP/1.1 404 Not Found",
            "service account not found",
            "text/plain",
        );
        let err = GcpMetadataOidcProvider::default()
            .with_base_url(format!("http://127.0.0.1:{port}"))
            .fetch_token()
            .expect_err("4xx must surface a typed error");
        handle.join().ok();

        match err {
            OidcError::HttpStatus { status, body } => {
                assert_eq!(status, 404);
                assert!(
                    body.contains("service account not found"),
                    "body must round-trip into the error, got: {body}"
                );
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }
}
