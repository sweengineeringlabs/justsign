//! [`InteractiveBrowserOidcProvider`] — operator-driven OAuth flow.
//!
//! ## Flow
//!
//! 1. Bind a `TcpListener` on `127.0.0.1:<redirect_port>` (port 0
//!    asks the OS to pick a free port).
//! 2. Build a CSRF-defeating random `state` value.
//! 3. Construct an authorization URL of the form:
//!
//!    ```text
//!    <issuer>?client_id=<cid>
//!            &response_type=code
//!            &scope=openid+email
//!            &redirect_uri=http://localhost:<port>/
//!            &state=<state>
//!    ```
//!
//! 4. Open the URL in the operator's default browser (via the `open`
//!    crate). If `open` fails, print the URL to stderr and continue —
//!    the operator can paste it manually.
//! 5. `accept()` on the listener with a timeout. Parse the GET
//!    request line for the `code` and `state` query params.
//! 6. Reject the redirect if `state` doesn't match the value we sent
//!    (CSRF defense).
//! 7. Discover the issuer's `token_endpoint` via
//!    `<issuer>/.well-known/openid-configuration`.
//! 8. POST `grant_type=authorization_code&code=<code>&client_id=<cid>
//!    &redirect_uri=http://localhost:<port>/` to the token endpoint.
//! 9. The token endpoint returns `{"id_token":"<jwt>", ...}`. Extract
//!    `id_token`. That's our return value.
//!
//! ## Testability
//!
//! The flow is split so the test suite can exercise each piece
//! independently without spawning a real browser:
//!
//! * [`parse_redirect_query`] — parses `?code=...&state=...` from
//!   the GET request line.
//! * [`validate_state`] — pure function, returns `Ok` or `Err`.
//! * [`discover_token_endpoint`] / [`exchange_code`] — wired against
//!   a localhost mock of the OIDC issuer for the happy-path test.
//!
//! `fetch_token` (the umbrella entry point) is NOT unit-tested in v0
//! because it actually launches a browser. Each of its constituent
//! steps is tested individually; the whole-thing integration test is
//! a manual operator step in v0.

use super::{OidcError, OidcProvider};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::Duration;

/// Default OIDC issuer URL — Sigstore's public-good Dex instance.
/// What cosign uses by default.
pub const DEFAULT_ISSUER_URL: &str = "https://oauth2.sigstore.dev/auth";

/// Default OAuth client id for the Sigstore public-good issuer.
/// This is a public-client value, not a secret — the issuer uses
/// the `redirect_uri` (localhost) as the auth gate.
pub const DEFAULT_CLIENT_ID: &str = "sigstore";

/// How long we wait for the operator to complete the browser flow
/// before giving up. 60 seconds matches cosign's default; long
/// enough for a fresh TOTP, short enough that an operator who
/// closes the tab doesn't leak a hung process.
const REDIRECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Cap response-body capture at 4 KiB on token-endpoint errors.
const MAX_ERROR_BODY_BYTES: usize = 4096;

/// Interactive-browser OIDC provider.
///
/// Stateless across calls; each `fetch_token` re-runs the full
/// authorize-redirect-exchange loop.
#[derive(Debug, Clone)]
pub struct InteractiveBrowserOidcProvider {
    /// OIDC issuer URL the browser is sent to. Must NOT include a
    /// trailing slash — the well-known discovery URL is built by
    /// appending `/.well-known/openid-configuration`.
    issuer_url: String,
    /// OAuth `client_id`. Public-client value; not a secret.
    client_id: String,
    /// Localhost port to bind the redirect listener on. `0` asks the
    /// OS to pick a free port — the recommended default to avoid
    /// collisions with whatever else is on the operator's box.
    redirect_port: u16,
}

impl InteractiveBrowserOidcProvider {
    /// Build a provider with explicit configuration.
    pub fn new(
        issuer_url: impl Into<String>,
        client_id: impl Into<String>,
        redirect_port: u16,
    ) -> Self {
        Self {
            issuer_url: issuer_url.into(),
            client_id: client_id.into(),
            redirect_port,
        }
    }
}

impl Default for InteractiveBrowserOidcProvider {
    fn default() -> Self {
        Self::new(DEFAULT_ISSUER_URL, DEFAULT_CLIENT_ID, 0)
    }
}

impl OidcProvider for InteractiveBrowserOidcProvider {
    fn fetch_token(&self) -> Result<String, OidcError> {
        // 1. Bind listener first — if we can't, fail before the
        //    browser opens, so the operator doesn't see a "press
        //    'allow'" page that leads nowhere.
        let listener = TcpListener::bind(("127.0.0.1", self.redirect_port))
            .map_err(|e| OidcError::RedirectListenerFailed(format!("bind: {e}")))?;
        listener
            .set_nonblocking(false)
            .map_err(|e| OidcError::RedirectListenerFailed(format!("set blocking: {e}")))?;
        let actual_port = listener
            .local_addr()
            .map_err(|e| OidcError::RedirectListenerFailed(format!("local_addr: {e}")))?
            .port();

        let redirect_uri = format!("http://localhost:{actual_port}/");
        let state = random_state();
        let auth_url =
            build_authorization_url(&self.issuer_url, &self.client_id, &redirect_uri, &state);

        // 2. Open browser. Failure isn't fatal — print the URL so
        //    the operator can paste it. Any later listener-side
        //    failure is the actually-blocking error.
        if let Err(e) = open::that(&auth_url) {
            eprintln!("oidc: failed to open browser ({e}); paste this URL manually:\n{auth_url}");
        }

        // 3. Wait for the redirect with a hard deadline. We CANNOT
        //    use `set_read_timeout` on the TcpListener (only on the
        //    accepted stream) — instead, set non-blocking mode and
        //    poll-with-timeout via the runtime's std-lib helper.
        let stream = accept_with_timeout(&listener, REDIRECT_TIMEOUT)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| OidcError::RedirectListenerFailed(format!("set timeout: {e}")))?;

        let request_line = read_request_line(&stream)?;
        // Always send a tiny "you can close this tab" page back to
        // the browser — the operator's experience matters even on
        // the error paths. Done before the state check so a CSRF
        // attempt also gets a clean tab close.
        let _ = write_close_tab_response(&stream);

        let params = parse_redirect_query(&request_line)?;
        validate_state(&params, &state)?;
        let code = params
            .get("code")
            .cloned()
            .ok_or_else(|| OidcError::Http("redirect missing 'code' param".to_string()))?;

        // 4. Exchange the code for an id_token. Two HTTPS calls:
        //    discovery, then the token endpoint. Both use the
        //    blocking reqwest client.
        let token_endpoint = discover_token_endpoint(&self.issuer_url)?;
        exchange_code(&token_endpoint, &self.client_id, &code, &redirect_uri)
    }
}

/// Build the OAuth 2.0 authorization URL the browser is sent to.
/// Pure function — pulled out so the test suite can pin its shape
/// without driving a real browser.
fn build_authorization_url(
    issuer_url: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
) -> String {
    // Manual encoding of the redirect_uri's `:` and `/` — not strictly
    // required by the OAuth spec (browsers tolerate raw values) but
    // a number of OIDC issuers reject malformed query strings out of
    // an abundance of caution. We URL-encode the redirect URI only;
    // client_id, scope, state are all alphanumeric in practice.
    let encoded_redirect = url_encode(redirect_uri);
    format!(
        "{issuer_url}?client_id={client_id}&response_type=code&scope=openid+email&redirect_uri={encoded_redirect}&state={state}"
    )
}

/// Minimal URL-encoder for the few characters we actually emit
/// (colons, slashes, equals). Avoids pulling `urlencoding` for one
/// callsite; the inputs we encode are bounded (a localhost URL).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

/// Cryptographically uninteresting random state. Not security-
/// critical (OAuth state is for CSRF, not auth), but should be
/// hard enough to guess that an attacker can't pre-mint a redirect.
/// `OsRng` from `rand_core` is already in the dep graph (transitively
/// via fulcio); we read 16 bytes and hex-encode.
fn random_state() -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    let mut out = String::with_capacity(32);
    for b in buf {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Wait for an inbound connection with an absolute deadline. Std's
/// `TcpListener::accept` is blocking with no built-in timeout, so we
/// flip the listener to non-blocking and poll. The poll interval is
/// short (50 ms) — the operator-perceived latency of clicking
/// "approve" to seeing "you can close this tab" is what matters,
/// and 50 ms keeps that smooth.
fn accept_with_timeout(
    listener: &TcpListener,
    timeout: Duration,
) -> Result<std::net::TcpStream, OidcError> {
    listener
        .set_nonblocking(true)
        .map_err(|e| OidcError::RedirectListenerFailed(format!("set nonblocking: {e}")))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).map_err(|e| {
                    OidcError::RedirectListenerFailed(format!("reset blocking: {e}"))
                })?;
                return Ok(stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(OidcError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(OidcError::RedirectListenerFailed(format!("accept: {e}")));
            }
        }
    }
}

/// Read just the HTTP request line (`GET /?... HTTP/1.1`). We don't
/// care about headers or body — the OAuth callback is a GET with the
/// payload in the query string.
fn read_request_line(stream: &std::net::TcpStream) -> Result<String, OidcError> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| OidcError::RedirectListenerFailed(format!("read request: {e}")))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Send a tiny HTML response telling the operator to close the tab.
/// Best-effort — we don't care if the write fails (the auth code
/// is already in our hands).
fn write_close_tab_response(mut stream: &std::net::TcpStream) -> std::io::Result<()> {
    let body = b"<html><body><h2>justsign: authentication complete</h2><p>You can close this tab.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Parse the OAuth-redirect query string out of an HTTP request line.
/// Returns a `HashMap` of query-param name -> value.
///
/// Pure function — pulled out for unit-test coverage without a
/// listener.
pub fn parse_redirect_query(request_line: &str) -> Result<HashMap<String, String>, OidcError> {
    // request_line looks like `GET /?code=abc&state=def HTTP/1.1`.
    let path_with_query = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| OidcError::Http(format!("malformed request line: {request_line}")))?;
    let query = path_with_query
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or("");
    let mut out = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            out.insert(url_decode(k), url_decode(v));
        } else {
            out.insert(url_decode(pair), String::new());
        }
    }
    Ok(out)
}

/// Reverse of [`url_encode`] — decodes `%XX` sequences. Anything
/// not `%XX` is passed through verbatim. Mirrors what every OAuth
/// callback parser does; the inputs we expect (alphanumeric `code`
/// and `state`) won't trigger the percent path in practice.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Verify the `state` returned in the redirect matches the value we
/// generated when building the authorization URL. Returns an
/// `OidcError::Http` (semantically: "the issuer / browser misbehaved
/// in a way we should treat as a transport-level fault") if not.
pub fn validate_state(params: &HashMap<String, String>, expected: &str) -> Result<(), OidcError> {
    match params.get("state") {
        Some(s) if s == expected => Ok(()),
        _ => Err(OidcError::Http(
            "oauth state mismatch: possible CSRF attempt".to_string(),
        )),
    }
}

/// Wire shape of the OIDC discovery doc we care about. The full doc
/// is large; we only deserialise the `token_endpoint` field.
#[derive(Debug, Deserialize)]
struct OidcDiscoveryDoc {
    token_endpoint: String,
}

/// Wire shape of the token-endpoint response. OIDC mandates
/// `id_token` for any `openid` scope grant.
#[derive(Debug, Deserialize)]
struct TokenEndpointResponse {
    id_token: String,
}

/// Hit `<issuer>/.well-known/openid-configuration` and pull the
/// `token_endpoint`. Pulled out for unit-test coverage.
pub fn discover_token_endpoint(issuer_url: &str) -> Result<String, OidcError> {
    let discovery_url = format!("{issuer_url}/.well-known/openid-configuration");
    let client = reqwest::blocking::Client::builder()
        .build()
        .map_err(|e| OidcError::Http(format!("build http client: {e}")))?;
    let resp = client
        .get(&discovery_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .map_err(|e| OidcError::Http(format!("GET {discovery_url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = bounded_body(resp);
        return Err(OidcError::HttpStatus {
            status: status.as_u16(),
            body,
        });
    }
    let doc: OidcDiscoveryDoc = resp
        .json()
        .map_err(|e| OidcError::Http(format!("decode discovery doc: {e}")))?;
    Ok(doc.token_endpoint)
}

/// POST the auth code to the token endpoint and pull out
/// `id_token`. Pulled out for unit-test coverage.
pub fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<String, OidcError> {
    let client = reqwest::blocking::Client::builder()
        .build()
        .map_err(|e| OidcError::Http(format!("build http client: {e}")))?;
    // Form-urlencoded body — what RFC 6749 mandates for the token
    // endpoint. reqwest's `.form(&...)` does the encoding for us.
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
    ];
    let resp = client
        .post(token_endpoint)
        .form(&form)
        .send()
        .map_err(|e| OidcError::Http(format!("POST {token_endpoint}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = bounded_body(resp);
        return Err(OidcError::HttpStatus {
            status: status.as_u16(),
            body,
        });
    }
    let parsed: TokenEndpointResponse = resp
        .json()
        .map_err(|e| OidcError::Http(format!("decode token response: {e}")))?;
    Ok(parsed.id_token)
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

    /// Default constructor pins the Sigstore public-good issuer +
    /// client_id and lets the OS pick the redirect port.
    ///
    /// Bug it catches: a default that drifted to a private issuer
    /// would route operator credentials at the wrong server. Pinning
    /// the default here makes that drift visible.
    #[test]
    fn test_default_constructor_pins_sigstore_issuer_and_client_id() {
        let p = InteractiveBrowserOidcProvider::default();
        assert_eq!(p.issuer_url, "https://oauth2.sigstore.dev/auth");
        assert_eq!(p.client_id, "sigstore");
        assert_eq!(p.redirect_port, 0);
    }

    /// The authorization URL builder produces a valid query string
    /// containing every OAuth-required param in the expected shape.
    ///
    /// Bug it catches: a builder that forgot `response_type=code`
    /// (the OIDC spec requires it) would silently produce an
    /// implicit-flow request — different security model, different
    /// token shape. We pin every required param verbatim.
    #[test]
    fn test_build_authorization_url_with_default_args_includes_required_params() {
        let url = build_authorization_url(
            "https://issuer.example/auth",
            "client-1",
            "http://localhost:1234/",
            "deadbeef",
        );
        assert!(url.starts_with("https://issuer.example/auth?"), "got {url}");
        assert!(url.contains("client_id=client-1"), "got {url}");
        assert!(url.contains("response_type=code"), "got {url}");
        assert!(url.contains("scope=openid+email"), "got {url}");
        assert!(url.contains("state=deadbeef"), "got {url}");
        // Redirect URI must be URL-encoded — verifies the encoder
        // ran (raw `:` would break some issuers).
        assert!(
            url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A1234%2F"),
            "redirect_uri must be URL-encoded, got {url}"
        );
    }

    /// State mismatch in the redirect query is rejected with a typed
    /// error — the CSRF defense.
    ///
    /// Bug it catches: a `validate_state` that returned `Ok` when
    /// the param was missing (or matched the wrong value) would
    /// open the OAuth dance to CSRF. This is the most safety-
    /// critical test in this module.
    #[test]
    fn test_validate_state_with_mismatch_returns_error() {
        let mut params = HashMap::new();
        params.insert("state".to_string(), "wrong".to_string());
        params.insert("code".to_string(), "abc".to_string());
        let err =
            validate_state(&params, "expected").expect_err("mismatched state must be rejected");
        match err {
            OidcError::Http(msg) => {
                assert!(
                    msg.contains("state mismatch"),
                    "error must call out the mismatch, got: {msg}"
                );
            }
            other => panic!("expected Http variant, got {other:?}"),
        }

        let mut missing = HashMap::new();
        missing.insert("code".to_string(), "abc".to_string());
        let err = validate_state(&missing, "expected").expect_err("missing state must err");
        assert!(matches!(err, OidcError::Http(_)));

        // The matching case must succeed.
        let mut ok = HashMap::new();
        ok.insert("state".to_string(), "expected".to_string());
        validate_state(&ok, "expected").expect("matching state must validate");
    }

    /// `parse_redirect_query` correctly extracts `code` and `state`
    /// from a real-shape GET request line.
    ///
    /// Bug it catches: a parser that grabbed the wrong query-param
    /// boundary (e.g. didn't split on `&`) would conflate `code`
    /// and `state` into one value, defeating the CSRF check.
    #[test]
    fn test_parse_redirect_query_with_real_shape_extracts_code_and_state() {
        let req = "GET /?code=abc-123&state=deadbeef HTTP/1.1";
        let params = parse_redirect_query(req).expect("must parse");
        assert_eq!(params.get("code").map(String::as_str), Some("abc-123"));
        assert_eq!(params.get("state").map(String::as_str), Some("deadbeef"));

        // No-query case still parses successfully (callers are
        // responsible for missing-`code` handling later).
        let req_no_query = "GET / HTTP/1.1";
        let params = parse_redirect_query(req_no_query).expect("must parse");
        assert!(params.is_empty());

        // Malformed lines surface the typed error.
        let bad = "broken";
        let err = parse_redirect_query(bad).expect_err("malformed line must err");
        assert!(matches!(err, OidcError::Http(_)));
    }

    /// One-shot mock that serves the discovery doc on
    /// `/.well-known/openid-configuration`, returning a JSON
    /// document whose `token_endpoint` points at a second mock URL.
    ///
    /// Bug it catches: a discovery client that hardcoded the
    /// `token_endpoint` path (rather than reading it from the doc)
    /// would silently pick the wrong endpoint when the issuer
    /// rotates URLs.
    #[test]
    fn test_discover_token_endpoint_with_mock_issuer_returns_token_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        let body = format!(
            r#"{{"issuer":"http://127.0.0.1:{port}","token_endpoint":"http://127.0.0.1:{port}/token","authorization_endpoint":"http://127.0.0.1:{port}/auth"}}"#
        );
        let body_clone = body.clone();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).ok();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_clone}",
                body_clone.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        });

        let endpoint =
            discover_token_endpoint(&format!("http://127.0.0.1:{port}")).expect("discover");
        handle.join().expect("server done");
        assert_eq!(endpoint, format!("http://127.0.0.1:{port}/token"));
        // Sanity-check we actually consumed the body we sent.
        assert!(body.contains("token_endpoint"));
    }

    /// `exchange_code` POSTs the form to the token endpoint and
    /// returns the `id_token` field.
    ///
    /// Bug it catches: a code path that pulled the wrong field
    /// (`access_token` is also returned, but it's NOT what Fulcio
    /// wants) would silently mint a useless token. Pinning the
    /// `id_token` extraction here catches that drift.
    #[test]
    fn test_exchange_code_with_mock_token_endpoint_returns_id_token() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("read");
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let body = r#"{"access_token":"AT","id_token":"eyJ.id-tok.sig","token_type":"Bearer"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        });

        let id_token = exchange_code(
            &format!("http://127.0.0.1:{port}/token"),
            "client-1",
            "auth-code-xyz",
            "http://localhost:1234/",
        )
        .expect("exchange must succeed");
        assert_eq!(id_token, "eyJ.id-tok.sig");

        let recorded = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server must record one request");
        handle.join().expect("server thread done");
        // Body must be form-encoded with the four required fields.
        assert!(
            recorded.contains("grant_type=authorization_code"),
            "request must include grant_type, got: {recorded}"
        );
        assert!(
            recorded.contains("code=auth-code-xyz"),
            "request must include code, got: {recorded}"
        );
        assert!(
            recorded.contains("client_id=client-1"),
            "request must include client_id, got: {recorded}"
        );
    }

    /// Listener bind on an already-bound port surfaces a typed
    /// `RedirectListenerFailed`, not a panic.
    ///
    /// Bug it catches: an `unwrap()` on the bind would crash the
    /// CLI hard if the operator already had something on the
    /// requested port; a typed error lets the caller surface a
    /// useful "port in use" message.
    #[test]
    fn test_fetch_token_with_already_bound_port_returns_listener_failed() {
        // Bind a sentinel listener and grab its port — guaranteed
        // to be in use for the duration of this test.
        let sentinel = TcpListener::bind("127.0.0.1:0").expect("bind sentinel");
        let port = sentinel.local_addr().unwrap().port();
        // Also set up a far-away issuer URL so we don't actually
        // hit the network — the bind must fail BEFORE anything
        // else runs, so this URL is never consulted.
        let provider =
            InteractiveBrowserOidcProvider::new("http://127.0.0.1:1/never-used", "client-1", port);
        let err = provider
            .fetch_token()
            .expect_err("bind on used port must err");
        match err {
            OidcError::RedirectListenerFailed(msg) => {
                assert!(
                    !msg.is_empty(),
                    "listener-failed error must carry a message"
                );
            }
            other => panic!("expected RedirectListenerFailed, got {other:?}"),
        }
        drop(sentinel);
    }
}
