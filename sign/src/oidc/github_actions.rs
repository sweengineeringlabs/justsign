//! [`GitHubActionsOidcProvider`] — fetch an ambient OIDC token from
//! the GitHub Actions runner.
//!
//! GHA exposes two env vars when a workflow declares
//! `permissions: id-token: write`:
//!
//! * `ACTIONS_ID_TOKEN_REQUEST_URL` — endpoint to GET.
//! * `ACTIONS_ID_TOKEN_REQUEST_TOKEN` — bearer token for the GET.
//!
//! `<url>?audience=<audience>` returns JSON of shape
//! `{"value": "<jwt>", "count": 1}`. The provider returns the
//! `value` string verbatim.
//!
//! The flow matches what cosign's `experimental` flag does and what
//! `actions/sigstore` uses internally — the on-the-wire shape is
//! pinned by GitHub.

use super::{OidcError, OidcProvider};
use serde::Deserialize;

/// Cap response-body capture at 4 KiB so a misbehaving GHA token
/// endpoint can't blow up our error path. The real response is a
/// few hundred bytes; 4 KiB is a generous diagnostic ceiling.
const MAX_ERROR_BODY_BYTES: usize = 4096;

/// OIDC provider that fetches the ambient identity token from the
/// GitHub Actions runner.
///
/// The provider is stateless — `fetch_token` reads
/// `ACTIONS_ID_TOKEN_REQUEST_URL` and
/// `ACTIONS_ID_TOKEN_REQUEST_TOKEN` from the process env on every
/// call. The audience is the only configurable knob; default
/// `"sigstore"` matches Fulcio's expected `aud` claim.
#[derive(Debug, Clone)]
pub struct GitHubActionsOidcProvider {
    /// JWT `aud` claim to request from the GHA token endpoint.
    audience: String,
}

impl GitHubActionsOidcProvider {
    /// Build a provider for an explicit audience. Use [`Default`]
    /// for the standard sigstore audience.
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
        }
    }
}

impl Default for GitHubActionsOidcProvider {
    fn default() -> Self {
        Self::new("sigstore")
    }
}

/// Wire shape of the GHA token-issuance response.
///
/// `count` is also returned but unused — GHA always returns 1; we
/// don't validate it because doing so would make us brittle to a
/// future schema change that's safe for our use.
#[derive(Debug, Deserialize)]
struct GhaTokenResponse {
    value: String,
}

impl OidcProvider for GitHubActionsOidcProvider {
    fn fetch_token(&self) -> Result<String, OidcError> {
        let url = read_env("ACTIONS_ID_TOKEN_REQUEST_URL")?;
        let token = read_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN")?;

        // GHA expects `?audience=<audience>` appended to the URL it
        // handed us. The URL it hands out already carries other
        // query params (api-version etc.), so we use `&audience=`
        // when the URL already has a `?`, else `?audience=`. We do
        // NOT URL-encode the audience: cosign / sigstore-rs don't,
        // and the legal audience values for sigstore are all
        // alphanumeric.
        let separator = if url.contains('?') { '&' } else { '?' };
        let full_url = format!("{url}{separator}audience={}", self.audience);

        let client = reqwest::blocking::Client::builder()
            .build()
            .map_err(|e| OidcError::Http(format!("build http client: {e}")))?;
        let resp = client
            .get(&full_url)
            .header(reqwest::header::AUTHORIZATION, format!("bearer {token}"))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .map_err(|e| OidcError::Http(format!("GET {full_url}: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = bounded_body(resp);
            return Err(OidcError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }

        let parsed: GhaTokenResponse = resp
            .json()
            .map_err(|e| OidcError::Http(format!("decode GHA token JSON: {e}")))?;
        Ok(parsed.value)
    }
}

/// Read an env var, treating empty as unset so CI templates that
/// expand to `""` produce the actionable `EnvVarMissing` error
/// rather than getting passed downstream.
fn read_env(name: &str) -> Result<String, OidcError> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(OidcError::EnvVarMissing {
            name: name.to_string(),
        }),
    }
}

/// Capture up to [`MAX_ERROR_BODY_BYTES`] of an error response,
/// mapping any IO failure to a stable placeholder so the outer
/// error type is always populated.
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
    use std::sync::Mutex;
    use std::thread;

    /// Serialises tests that mutate process-global env vars. GHA env
    /// vars are read every call, so two tests racing each other on
    /// `ACTIONS_ID_TOKEN_REQUEST_URL` would intermittently see each
    /// other's setup.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// Minimal in-process HTTP/1.1 server for the test path. We use
    /// std's `TcpListener` rather than pulling `httpmock` (and its
    /// async runtime) into the dep graph — the GHA happy path is
    /// one GET with a JSON body, which is cheap to model by hand.
    ///
    /// Returns `(port, recorded_request_line, joinhandle)`.
    /// The handle's join() waits for the single response cycle.
    fn spawn_one_shot_http(
        response_status_line: &'static str,
        response_body: &'static str,
        content_type: &'static str,
    ) -> (
        u16,
        std::sync::mpsc::Receiver<String>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
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

    /// `fetch_token` with neither GHA env var set returns the typed
    /// `EnvVarMissing { name: "ACTIONS_ID_TOKEN_REQUEST_URL" }`.
    ///
    /// Bug it catches: a provider that panicked on missing env, or
    /// one that returned a generic `Http` error (which would push the
    /// operator at the wrong fix — the workflow needs
    /// `permissions: id-token: write`, not a network change).
    #[test]
    fn test_fetch_token_with_no_gha_env_returns_env_var_missing() {
        let _g = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let prev_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").ok();
        let prev_tok = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok();
        std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_URL");
        std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN");

        let err = GitHubActionsOidcProvider::default()
            .fetch_token()
            .expect_err("missing env must err");
        match err {
            OidcError::EnvVarMissing { name } => {
                assert_eq!(name, "ACTIONS_ID_TOKEN_REQUEST_URL");
            }
            other => panic!("expected EnvVarMissing, got {other:?}"),
        }

        if let Some(v) = prev_url {
            std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_URL", v);
        }
        if let Some(v) = prev_tok {
            std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", v);
        }
    }

    /// Happy path against a one-shot localhost HTTP server: the
    /// provider sends `Authorization: bearer <token>`, appends
    /// `?audience=sigstore` to the URL, and returns the JWT from
    /// the JSON body's `value` field.
    ///
    /// Bug it catches: a wiring bug that dropped the bearer header,
    /// forgot the audience query param, or returned the entire JSON
    /// document instead of just `value` would all silently fail
    /// with a Fulcio-side error rather than at the provider; pinning
    /// the wire shape here is what catches them at unit-test time.
    #[test]
    fn test_fetch_token_with_mock_server_returns_jwt_value() {
        let _g = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let prev_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").ok();
        let prev_tok = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok();

        let (port, rx, handle) = spawn_one_shot_http(
            "HTTP/1.1 200 OK",
            r#"{"value":"eyJhbGciOiJSUzI1NiJ9.payload.sig","count":1}"#,
            "application/json",
        );
        std::env::set_var(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("http://127.0.0.1:{port}/issue?api-version=2.0"),
        );
        std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-bearer-secret");

        let token = GitHubActionsOidcProvider::default()
            .fetch_token()
            .expect("happy path must succeed");
        assert_eq!(token, "eyJhbGciOiJSUzI1NiJ9.payload.sig");

        let request = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("server must record one request");
        handle.join().expect("server thread must finish");

        // Wire-shape assertions: the bearer must be set verbatim,
        // the audience query param must be appended, and we must
        // hit the path the env var pointed at.
        assert!(
            request.contains("authorization: bearer runner-bearer-secret")
                || request.contains("Authorization: bearer runner-bearer-secret"),
            "request must carry bearer header, got: {request}"
        );
        assert!(
            request.contains("audience=sigstore"),
            "request must append audience query param, got: {request}"
        );
        assert!(
            request.contains("/issue?api-version=2.0&audience=sigstore"),
            "request must append audience using `&` when URL already has `?`, got: {request}"
        );

        std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_URL");
        std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        if let Some(v) = prev_url {
            std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_URL", v);
        }
        if let Some(v) = prev_tok {
            std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", v);
        }
    }

    /// 4xx from the GHA token endpoint surfaces as `HttpStatus` with
    /// the body intact. Distinguishes "token endpoint said no" from
    /// a transport / DNS / TLS error so callers can pick the right
    /// remediation.
    ///
    /// Bug it catches: a code path that mapped every HTTP failure to
    /// the same `Http(String)` variant — the operator would see
    /// "transport error" for what is actually a permissions issue,
    /// and start chasing networking instead of the workflow YAML.
    #[test]
    fn test_fetch_token_with_4xx_response_returns_http_status_with_body() {
        let _g = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let prev_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").ok();
        let prev_tok = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok();

        let (port, _rx, handle) = spawn_one_shot_http(
            "HTTP/1.1 403 Forbidden",
            r#"{"message":"id-token write permission missing"}"#,
            "application/json",
        );
        std::env::set_var(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("http://127.0.0.1:{port}/issue"),
        );
        std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "anything");

        let err = GitHubActionsOidcProvider::default()
            .fetch_token()
            .expect_err("4xx must surface a typed error");
        handle.join().ok();

        match err {
            OidcError::HttpStatus { status, body } => {
                assert_eq!(status, 403);
                assert!(
                    body.contains("permission missing"),
                    "body must round-trip into the error, got: {body}"
                );
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }

        std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_URL");
        std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        if let Some(v) = prev_url {
            std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_URL", v);
        }
        if let Some(v) = prev_tok {
            std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", v);
        }
    }
}
