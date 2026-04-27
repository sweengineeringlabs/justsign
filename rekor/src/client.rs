//! Rekor client SPI + an in-memory mock + a blocking HTTP client.
//!
//! Three load-bearing types live here:
//!
//! * `RekorClient` trait — the v0 SPI: `submit` only. Inclusion-proof
//!   re-verification is performed against the bundle's own root and
//!   uses the local `merkle::verify_inclusion`, so it does not need
//!   an extra trait method.
//! * `LogEntry` — what `submit` returns (and what `fetch` re-hydrates),
//!   including the inclusion proof that `merkle::verify_inclusion`
//!   consumes.
//! * `MockRekorClient` — synthesises a deterministic single-leaf log
//!   per submission so consumers (notably `swe_justsign_sign`) can
//!   exercise the verifier end-to-end with no HTTP dependency.
//! * `HttpRekorClient` — blocking `reqwest::blocking::Client`-backed
//!   client that talks to a real Rekor server (e.g.
//!   `rekor.sigstage.dev`). Mirrors `HttpFulcioClient` in shape.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;

use crate::entry::HashedRekord;
use crate::merkle::{hash_leaf, verify_inclusion};
use crate::RekorError;

/// What Rekor returns for a submission or lookup.
///
/// Field shapes mirror the public Rekor API closely enough that
/// the v0.5 HTTP client can populate this type from the JSON
/// response without further restructuring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Server-assigned UUID. The v0 mock returns a deterministic
    /// hex of the leaf hash — real Rekor returns its own UUID.
    pub uuid: String,

    /// Position of this entry in the log. 0-based.
    pub log_index: u64,

    /// Total leaves in the tree the inclusion proof is rooted
    /// against.
    pub tree_size: u64,

    /// SHA-256 leaf hash, RFC 6962-prefixed (i.e.
    /// `SHA256(0x00 || canonicalised body bytes)`). Pass this
    /// directly to `merkle::verify_inclusion`.
    pub leaf_hash: [u8; 32],

    /// Merkle inclusion path (siblings, leaf-up). Length depends
    /// on `(log_index, tree_size)` — see RFC 6962 §2.1.1 and
    /// `merkle::expected_path_length`.
    pub inclusion_proof: Vec<[u8; 32]>,

    /// Root of the tree the inclusion proof reconstructs.
    pub root_hash: [u8; 32],

    /// The exact body bytes Rekor stored. The mock returns the
    /// canonical JSON encoding of the submitted entry — the real
    /// HTTP client returns whatever the server stored (in
    /// practice, the same shape since Rekor canonicalises).
    pub body: Vec<u8>,
}

/// Rekor client SPI. v0 has only `submit`; query operations join
/// in v0.5 alongside the HTTP backend.
pub trait RekorClient {
    fn submit(&self, entry: &HashedRekord) -> Result<LogEntry, RekorError>;
}

/// Deterministic in-memory mock — every submission lands in its
/// own fresh 1-leaf log. Useful for round-tripping the verifier
/// without HTTP.
///
/// `MockRekorClient` is `Default`-constructible because it has no
/// state; submissions are pure functions of the entry bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockRekorClient;

impl MockRekorClient {
    pub fn new() -> Self {
        Self
    }
}

impl RekorClient for MockRekorClient {
    fn submit(&self, entry: &HashedRekord) -> Result<LogEntry, RekorError> {
        // Canonicalise the body so the leaf hash is reproducible
        // for the same logical input.
        let body = entry.encode_json()?;
        let leaf_hash = hash_leaf(&body);

        // Single-leaf log → root == leaf_hash, empty inclusion path.
        let root_hash = leaf_hash;
        let inclusion_proof: Vec<[u8; 32]> = Vec::new();

        // UUID = lowercase hex of the leaf hash. Stable for a
        // given entry; mirrors the spirit of Rekor's UUID
        // (server-assigned, but deterministic per content here).
        let uuid = hex_lower_64(&leaf_hash);

        Ok(LogEntry {
            uuid,
            log_index: 0,
            tree_size: 1,
            leaf_hash,
            inclusion_proof,
            root_hash,
            body,
        })
    }
}

impl LogEntry {
    /// Convenience: verify the inclusion proof against the entry's
    /// own `root_hash`. A real consumer must instead verify
    /// against a trusted `SignedTreeHead` root (TUF/Sigstore root
    /// of trust); using `self.root_hash` here only proves the
    /// proof is internally consistent, not that the log itself is
    /// genuine. Useful for tests and for the mock client.
    pub fn verify_self_consistent(&self) -> Result<(), RekorError> {
        verify_inclusion(
            &self.leaf_hash,
            self.log_index,
            self.tree_size,
            &self.inclusion_proof,
            &self.root_hash,
        )
    }
}

/// Lower-case hex of a 32-byte digest. Local copy to avoid pulling
/// `hex` and to keep `lib::hex_lower` private to error formatting.
fn hex_lower_64(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------
// Real HTTP client
// ---------------------------------------------------------------

/// Default timeout for a single HTTP exchange with Rekor.
///
/// 30 seconds is generous for a single proof submission; matches the
/// upper end of cosign / fulcio defaults. Surfaces a concrete
/// `RekorError::Transport` (timeout) instead of hanging a CLI
/// invocation indefinitely on a stalled network.
const HTTP_TIMEOUT_SECS: u64 = 30;

/// Blocking Rekor HTTP client.
///
/// Wire format (Rekor v1):
///
/// * `submit`  → `POST {base_url}/api/v1/log/entries` with body
///   `{"apiVersion": "0.0.1", "kind": "hashedrekord", "spec": <hashedrekord JSON>}`.
/// * `fetch`   → `GET  {base_url}/api/v1/log/entries/{uuid}`.
///
/// Rekor returns a single-key map keyed by UUID for both verbs:
/// `{ "<uuid>": { "body": "<base64 canonical JSON>", "logIndex":
/// ..., "verification": { "inclusionProof": { ... } } } }`. The
/// `body` field is the base64 of the canonicalised entry the server
/// stored — we decode it back into the `LogEntry.body` field so the
/// shape matches what `MockRekorClient` returns.
pub struct HttpRekorClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

impl HttpRekorClient {
    /// Build a client against `base_url` (e.g.
    /// `https://rekor.sigstage.dev`). A trailing slash is tolerated:
    /// callers can pass either `https://rekor.sigstage.dev` or
    /// `https://rekor.sigstage.dev/` and the URL we build is the
    /// same.
    pub fn new(base_url: impl Into<String>) -> Result<Self, RekorError> {
        let http = reqwest::blocking::Client::builder()
            .user_agent(concat!("swe_justsign_rekor/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
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

    /// `GET /api/v1/log/entries/{uuid}` — fetch a previously-submitted
    /// log entry by its server-assigned UUID.
    ///
    /// Inherent (not on the trait) because the v0 trait surface is
    /// `submit`-only; verifiers re-check inclusion proofs against the
    /// bundle's stored root and don't need to round-trip the server.
    /// Callers that DO want a fresh round-trip — the CLI's
    /// `--rekor` verify path, for instance — depend on
    /// `HttpRekorClient` directly.
    pub fn fetch(&self, uuid: &str) -> Result<LogEntry, RekorError> {
        let url = format!("{}/api/v1/log/entries/{}", self.base_url, uuid);
        let resp = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()?;
        decode_log_entry_response(resp)
    }
}

impl RekorClient for HttpRekorClient {
    fn submit(&self, entry: &HashedRekord) -> Result<LogEntry, RekorError> {
        // Rekor accepts the entry as `{apiVersion, kind, spec}` where
        // `spec` is the `hashedrekord` body. The mock canonicalises
        // the body bytes and stores them verbatim; we ship the same
        // canonical body to the server so the round-trip
        // (mock-shape → real-shape) doesn't drift.
        //
        // We embed `spec` as a structured JSON value (not as a string)
        // because Rekor expects `spec: { ... }`, not
        // `spec: "{ ... }"`.
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
            .send()?;
        decode_log_entry_response(resp)
    }
}

/// Decode a Rekor entries response (single-key UUID map) into a
/// `LogEntry`. Shared between `submit` and `fetch` because the wire
/// shape is identical.
///
/// Status-code routing:
/// * 2xx → parse the body via [`decode_log_entry_bytes`]; any parse
///   failure surfaces as [`RekorError::Decode`] (server bug).
/// * 5xx → [`RekorError::ServerError`] (retry-worthy, alert).
/// * 4xx → [`RekorError::AlreadyExists`] if the body matches the
///   Rekor idempotency shape (see [`is_already_exists_body`]),
///   otherwise [`RekorError::ClientError`] (operator-fixable; not
///   retry-worthy with the same payload).
/// * 1xx / 3xx → routed to [`RekorError::ClientError`] because we
///   never expect them on this API and they indicate a misconfigured
///   proxy / redirector in front of Rekor.
fn decode_log_entry_response(resp: reqwest::blocking::Response) -> Result<LogEntry, RekorError> {
    let status = resp.status();
    let code = status.as_u16();
    if status.is_success() {
        let raw = resp.bytes()?;
        return decode_log_entry_bytes(&raw);
    }
    let body = resp.text().unwrap_or_else(|_| String::from("<unreadable>"));
    Err(classify_non_success(code, body))
}

/// Map a non-2xx HTTP status + body to the appropriate error
/// variant. Pure (no I/O) so it's shared verbatim between the
/// blocking and async transports.
pub(crate) fn classify_non_success(status: u16, body: String) -> RekorError {
    if (500..=599).contains(&status) {
        return RekorError::ServerError { status, body };
    }
    if (400..=499).contains(&status) && is_already_exists_body(&body) {
        return RekorError::AlreadyExists { body };
    }
    RekorError::ClientError { status, body }
}

/// Detect Rekor's "entry already exists" idempotency response.
///
/// Rekor signals that a content-identical entry is already in the
/// log via a 4xx with one of two body shapes:
///
/// * Canonical JSON object containing a `code` field whose value
///   is either the string `"AlreadyExists"` or the integer `409`.
///   The string form is what Rekor v1 emits; the integer form is
///   what older deployments and some proxies surface.
/// * A free-form error body that contains the substring
///   `"already exists"` (case-insensitive). This is the fallback
///   for Rekor versions whose error body shape doesn't surface a
///   structured `code` field — and for proxies that rewrite the
///   body but preserve the human-readable message.
///
/// The substring fallback is deliberately permissive: a false
/// positive (a 4xx body that happens to contain "already exists"
/// but is NOT an idempotency signal) routes the caller to
/// `AlreadyExists` instead of `ClientError`. The cost of that
/// false positive is small — the caller treats a re-submittable
/// failure as success and never alerts — but Rekor's own bodies
/// reliably contain this phrase only on the idempotency path, so
/// in practice the heuristic matches Rekor's contract.
pub(crate) fn is_already_exists_body(body: &str) -> bool {
    // Try the structured JSON shape first. We deserialize into a
    // free-form Value because Rekor's error body has multiple
    // historical shapes — `{ "code": "AlreadyExists", ... }`,
    // `{ "code": 409, ... }`, `{ "code": "ALREADY_EXISTS", ... }`.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(code) = value.get("code") {
            if let Some(s) = code.as_str() {
                if s.eq_ignore_ascii_case("alreadyexists")
                    || s.eq_ignore_ascii_case("already_exists")
                {
                    return true;
                }
            }
            if code.as_i64() == Some(409) {
                return true;
            }
        }
    }
    // Substring fallback. Lower-case once; bounded scan over the
    // whole body. Bodies are response-sized (a few KB at worst —
    // Rekor doesn't return MB-sized errors), so the allocation
    // cost is negligible compared to the HTTP round-trip.
    body.to_ascii_lowercase().contains("already exists")
}

/// Decode the *body bytes* of a successful Rekor entries response
/// into a `LogEntry`. Pure (no I/O), so it can be reused by both
/// the blocking and the (gated) async transport without dragging
/// `reqwest::blocking::Response` into the async path.
///
/// Exposed `pub` so the out-of-tree `fuzz/` harness (issue #24) can
/// drive it directly with arbitrary `&[u8]` inputs without going
/// through a real `reqwest::Response`. The function is pure, takes
/// only an opaque byte slice, and surfaces typed errors — exactly
/// the contract the fuzzer asserts (no panics).
pub fn decode_log_entry_bytes(raw: &[u8]) -> Result<LogEntry, RekorError> {
    use serde::de::Error as _;

    // Rekor returns `{ "<uuid>": { ... } }` — a one-element JSON
    // object keyed by the server-assigned UUID. We deserialise into
    // a `BTreeMap` so we don't depend on the field name and grab the
    // (one) entry. Any JSON-shape failure here is server-bug
    // territory (200 OK with an unparseable body) — surface as
    // `Decode`, NOT `Json`, so callers can distinguish a sign-time
    // entry-encode failure from a server response-decode failure.
    let mut map: std::collections::BTreeMap<String, RekorEntryWire> =
        serde_json::from_slice(raw).map_err(RekorError::Decode)?;
    let (uuid, wire) = map.pop_first().ok_or_else(|| {
        RekorError::Decode(serde_json::Error::custom(
            "rekor returned an empty entries map",
        ))
    })?;

    // Body is base64-encoded canonical JSON of the entry the server
    // stored. The mock returns the raw JSON bytes; we decode here so
    // the shape matches. A base64 failure on a 200 is also a server
    // bug — route it to `Decode`.
    let body = STANDARD.decode(wire.body.as_bytes()).map_err(|e| {
        RekorError::Decode(serde_json::Error::custom(format!(
            "rekor body base64 decode: {e}"
        )))
    })?;

    let proof = wire
        .verification
        .and_then(|v| v.inclusion_proof)
        .ok_or_else(|| {
            // Rekor returns inclusionProof for every fresh submission;
            // its absence means the server is in an unsupported config.
            RekorError::Decode(serde_json::Error::custom(
                "rekor response had no verification.inclusionProof",
            ))
        })?;

    let log_index: u64 = u64::try_from(wire.log_index).map_err(|_| {
        RekorError::Decode(serde_json::Error::custom(format!(
            "rekor logIndex was negative: {}",
            wire.log_index
        )))
    })?;
    let proof_log_index: u64 = u64::try_from(proof.log_index).map_err(|_| {
        RekorError::Decode(serde_json::Error::custom(format!(
            "rekor inclusionProof.logIndex was negative: {}",
            proof.log_index
        )))
    })?;
    let tree_size: u64 = u64::try_from(proof.tree_size).map_err(|_| {
        RekorError::Decode(serde_json::Error::custom(format!(
            "rekor inclusionProof.treeSize was negative: {}",
            proof.tree_size
        )))
    })?;

    let leaf_hash = hash_leaf(&body);
    let inclusion_proof: Vec<[u8; 32]> = proof
        .hashes
        .iter()
        .map(|h| decode_hex_32(h))
        .collect::<Result<Vec<_>, RekorError>>()?;
    let root_hash = decode_hex_32(&proof.root_hash)?;

    Ok(LogEntry {
        uuid,
        log_index: proof_log_index.max(log_index),
        tree_size,
        leaf_hash,
        inclusion_proof,
        root_hash,
        body,
    })
}

/// Decode a 64-char lowercase hex string into a 32-byte digest.
/// Bare-bones because we only ever decode SHA-256-shaped hashes
/// from Rekor — anything else is a malformed proof.
pub(crate) fn decode_hex_32(s: &str) -> Result<[u8; 32], RekorError> {
    use serde::de::Error as _;
    if s.len() != 64 {
        return Err(RekorError::Json(serde_json::Error::custom(format!(
            "expected 64-char hex digest, got {} chars",
            s.len()
        ))));
    }
    let mut out = [0u8; 32];
    for (i, byte_slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[i * 2])?;
        let lo = hex_nibble(s.as_bytes()[i * 2 + 1])?;
        *byte_slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, RekorError> {
    use serde::de::Error as _;
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(RekorError::Json(serde_json::Error::custom(format!(
            "bad hex digit: 0x{b:02x}"
        )))),
    }
}

// ── Rekor JSON response wire shapes ──────────────────────────────

/// Per-entry payload Rekor returns inside the UUID-keyed envelope.
#[derive(Deserialize)]
struct RekorEntryWire {
    /// Base64 of the canonical JSON body the server stored.
    body: String,
    /// Server-assigned 0-based log index.
    #[serde(rename = "logIndex")]
    log_index: i64,
    /// Inclusion proof + signed entry timestamp.
    #[serde(default)]
    verification: Option<VerificationWire>,
}

#[derive(Deserialize)]
struct VerificationWire {
    #[serde(rename = "inclusionProof", default)]
    inclusion_proof: Option<InclusionProofWire>,
}

#[derive(Deserialize)]
struct InclusionProofWire {
    /// Sibling hashes leaf-up, lowercase hex.
    hashes: Vec<String>,
    /// 0-based index of the leaf within the tree.
    #[serde(rename = "logIndex")]
    log_index: i64,
    /// Root hash the proof terminates at, lowercase hex.
    #[serde(rename = "rootHash")]
    root_hash: String,
    /// Total leaves in the tree at proof time.
    #[serde(rename = "treeSize")]
    tree_size: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Data, HashedRekord, HashedRekordHash, PublicKey, Signature};

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

    /// `MockRekorClient` returns a self-consistent inclusion proof
    /// — the canned `LogEntry` reconstructs its own root.
    ///
    /// Bug it catches: a mock that returns an inclusion path
    /// inconsistent with its own root (e.g. wrong leaf_hash, off-
    /// by-one log_index) would let downstream consumers
    /// "successfully verify" a bogus proof. The mock must produce
    /// proofs that actually pass the verifier, otherwise it gives
    /// false confidence to every test that uses it.
    #[test]
    fn test_mock_submit_returns_self_consistent_inclusion_proof() {
        let client = MockRekorClient::new();
        let entry = sample_record();
        let log_entry = client.submit(&entry).unwrap();

        log_entry
            .verify_self_consistent()
            .expect("mock must return a verifiable proof");
    }

    /// Mock submissions are deterministic — submitting the same
    /// entry twice yields the same UUID and leaf hash.
    ///
    /// Bug it catches: a mock that randomises the UUID makes tests
    /// flaky and obscures the relationship between content and
    /// log identity. Determinism is a property of the mock — not
    /// of real Rekor — and a test asserting it locks in the
    /// contract.
    #[test]
    fn test_mock_submit_is_deterministic_for_identical_entries() {
        let client = MockRekorClient::new();
        let entry = sample_record();
        let a = client.submit(&entry).unwrap();
        let b = client.submit(&entry).unwrap();
        assert_eq!(a.uuid, b.uuid);
        assert_eq!(a.leaf_hash, b.leaf_hash);
        assert_eq!(a.body, b.body);
    }

    /// `LogEntry.body` is the canonical JSON encoding of the
    /// submitted entry — round-trippable.
    ///
    /// Bug it catches: if the mock stored Debug output or a
    /// different serialisation, downstream consumers couldn't
    /// re-decode the body. The body must round-trip via
    /// `HashedRekord::decode_json`.
    #[test]
    fn test_mock_log_entry_body_round_trips_through_decode_json() {
        let client = MockRekorClient::new();
        let entry = sample_record();
        let log_entry = client.submit(&entry).unwrap();

        let decoded = HashedRekord::decode_json(&log_entry.body).unwrap();
        assert_eq!(decoded, entry);
    }

    /// `LogEntry.uuid` is 64 lowercase hex chars (the leaf hash
    /// formatted) — surface contract for callers that key entries
    /// by UUID.
    #[test]
    fn test_mock_log_entry_uuid_is_64_lowercase_hex_chars() {
        let client = MockRekorClient::new();
        let log_entry = client.submit(&sample_record()).unwrap();
        assert_eq!(log_entry.uuid.len(), 64);
        assert!(log_entry
            .uuid
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// Submitting two different entries produces two different
    /// leaf hashes — confirming the mock isn't accidentally
    /// returning a constant.
    ///
    /// Bug it catches: a mock that ignores its input and always
    /// returns the same canned LogEntry would silently make all
    /// downstream tests "pass" even with wrong inputs.
    #[test]
    fn test_mock_submit_distinguishes_different_entries() {
        let client = MockRekorClient::new();
        let a = client.submit(&sample_record()).unwrap();

        let mut other = sample_record();
        other.signature.content = b"different-sig-bytes".to_vec();
        let b = client.submit(&other).unwrap();

        assert_ne!(a.leaf_hash, b.leaf_hash);
        assert_ne!(a.uuid, b.uuid);
    }

    /// `RekorClient` is object-safe — callers can hold
    /// `Box<dyn RekorClient>` and swap implementations.
    ///
    /// Bug it catches: adding generics or `Self` returns to the
    /// trait would break dyn-dispatch and force every consumer to
    /// thread a generic parameter through. The compile-time check
    /// here pins object-safety as part of the SPI.
    #[test]
    fn test_rekor_client_trait_is_object_safe() {
        let _client: Box<dyn RekorClient> = Box::new(MockRekorClient::new());
        let http = HttpRekorClient::new("https://invalid.example.invalid").expect("http client");
        let _client: Box<dyn RekorClient> = Box::new(http);
    }

    /// `HttpRekorClient::new` strips a trailing slash from the base
    /// URL so callers can pass either form without doubling the
    /// path-separator on submit.
    ///
    /// Bug it catches: a constructor that left the trailing slash
    /// in place would build URLs like
    /// `https://rekor//api/v1/log/entries` — Rekor returns 404 on
    /// the doubled slash on some deployments, and the failure mode
    /// is silently terminal mid-pipeline.
    #[test]
    fn test_http_rekor_client_new_strips_trailing_slash_from_base_url() {
        let with_slash = HttpRekorClient::new("https://rekor.example/").expect("client");
        let without_slash = HttpRekorClient::new("https://rekor.example").expect("client");
        assert_eq!(with_slash.base_url, "https://rekor.example");
        assert_eq!(without_slash.base_url, "https://rekor.example");
    }

    /// `decode_hex_32` rejects digests of the wrong length with a
    /// typed error, not a panic.
    ///
    /// Bug it catches: a server that sends a truncated or padded
    /// hex digest would otherwise either panic on slice indexing or
    /// silently pad with zeroes — both produce wrong leaf hashes
    /// downstream, breaking inclusion-proof verification with
    /// indecipherable error messages.
    #[test]
    fn test_decode_hex_32_with_wrong_length_returns_typed_error() {
        let too_short = decode_hex_32("ab").expect_err("must reject short hex");
        assert!(matches!(too_short, RekorError::Json(_)));
        let too_long = decode_hex_32(&"a".repeat(65)).expect_err("must reject long hex");
        assert!(matches!(too_long, RekorError::Json(_)));
    }

    /// `decode_hex_32` rejects non-hex characters with a typed
    /// error.
    ///
    /// Bug it catches: a server that emits uppercase or non-hex
    /// content would otherwise be silently accepted and produce a
    /// wrong digest. Lowercase hex is what Rekor emits; we accept
    /// uppercase too (RFC 4648 tolerance) but reject anything else.
    #[test]
    fn test_decode_hex_32_with_non_hex_chars_returns_typed_error() {
        let mut s = "a".repeat(63);
        s.push('Z');
        let err = decode_hex_32(&s).expect_err("must reject non-hex");
        assert!(matches!(err, RekorError::Json(_)));
    }

    /// `decode_hex_32` accepts both lower- and upper-case hex —
    /// mirrors RFC 4648 base16 tolerance and matches what the
    /// `hex` crate would do, so we don't surface a parse error if a
    /// future Rekor version starts emitting uppercase.
    #[test]
    fn test_decode_hex_32_accepts_lowercase_and_uppercase_hex() {
        let lower = decode_hex_32(&"ab".repeat(32)).expect("lowercase ok");
        let upper = decode_hex_32(&"AB".repeat(32)).expect("uppercase ok");
        assert_eq!(lower, [0xab; 32]);
        assert_eq!(upper, [0xab; 32]);
    }

    /// Skip-pass integration test against Sigstore's staging Rekor.
    ///
    /// Always-on (no `#[ignore]`): the test compiles, links, and
    /// runs in every `cargo test` invocation. When
    /// `JUSTSIGN_REKOR_STAGING` is unset or not exactly "1" the
    /// test prints `SKIP: ...` and returns success — so CI's
    /// network-free run sees a green box, but the in-tree wire-
    /// format check is preserved and one env-var flip away.
    ///
    /// Bug it catches: wire-format drift between our hashedrekord
    /// JSON envelope (`{apiVersion, kind, spec}`) and what Rekor's
    /// real `/api/v1/log/entries` accepts/returns. Unit tests
    /// verify our encoding is internally consistent; only a live
    /// call against the staging server surfaces upstream API
    /// changes (renamed fields, new required wrappers, changed
    /// status code semantics).
    #[test]
    fn test_http_rekor_client_round_trips_against_staging() {
        if std::env::var("JUSTSIGN_REKOR_STAGING").as_deref() != Ok("1") {
            eprintln!("SKIP: JUSTSIGN_REKOR_STAGING != 1 — staging Rekor test skipped");
            return;
        }

        // Use a randomised data hash so each staging run produces a
        // distinct entry — two runs of the same content would land on
        // an existing UUID (Rekor de-dupes by content) and the test
        // would still be valid, but a unique-per-run hash makes the
        // logs easier to triage.
        use sha2::{Digest, Sha256};
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut hasher = Sha256::new();
        hasher.update(nonce.to_le_bytes());
        hasher.update(b"swe_justsign_rekor staging round-trip test");
        let digest = hasher.finalize();
        let mut hex_value = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for b in digest.iter() {
            hex_value.push(HEX[(b >> 4) as usize] as char);
            hex_value.push(HEX[(b & 0x0f) as usize] as char);
        }

        let entry = HashedRekord {
            signature: Signature {
                content: b"staging-test-signature-bytes-not-real".to_vec(),
                public_key: PublicKey {
                    content: b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n".to_vec(),
                },
            },
            data: Data {
                hash: HashedRekordHash {
                    algorithm: "sha256".into(),
                    value: hex_value,
                },
            },
        };

        let client =
            HttpRekorClient::new("https://rekor.sigstage.dev").expect("staging client builds");

        // Staging may reject our entry on signature-verify (the bytes
        // above are not a real signature). What we're pinning here is
        // the *transport contract*: either a 2xx with a parseable
        // proof, or a structured 4xx (`ClientError` for a bad
        // signature) / 4xx-idempotent (`AlreadyExists` if the same
        // synthetic content was submitted previously). Anything else
        // (panic, hang, untyped error, transport failure on a healthy
        // staging server) is a real bug.
        match client.submit(&entry) {
            Ok(log_entry) => {
                assert!(
                    !log_entry.uuid.is_empty(),
                    "staging submit returned empty UUID"
                );
                assert!(
                    !log_entry.inclusion_proof.is_empty() || log_entry.tree_size == 1,
                    "staging submit returned a proof of length 0 against a tree_size > 1"
                );
                let fetched = client
                    .fetch(&log_entry.uuid)
                    .expect("staging fetch by UUID must succeed");
                assert_eq!(fetched.uuid, log_entry.uuid);
                assert_eq!(fetched.body, log_entry.body);
            }
            Err(RekorError::ClientError { status, body }) => {
                eprintln!(
                    "staging submit returned typed ClientError {status}: {body} \
                     (acceptable for a synthetic signature; transport contract held)"
                );
            }
            Err(RekorError::AlreadyExists { body }) => {
                eprintln!(
                    "staging submit returned AlreadyExists: {body} \
                     (acceptable on a content collision; idempotency contract held)"
                );
            }
            Err(other) => {
                panic!("staging submit returned untyped error: {other:?}");
            }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Issue #32: granular `RekorError` variants — heuristic + wire
    // tests for the new `Transport` / `ServerError` / `ClientError`
    // / `AlreadyExists` / `Decode` split.
    //
    // The `is_already_exists_body` heuristic is the subtle part:
    // these tests are written FIRST (before the heuristic was
    // wired into the response classifier) so they pin the
    // canonical body shapes Rekor actually returns and the
    // permissive substring fallback for older deployments.
    // ──────────────────────────────────────────────────────────────

    /// Canonical Rekor 4xx idempotency body — top-level `code` is
    /// the string `"AlreadyExists"` (Rekor v1 shape).
    ///
    /// Bug it catches: a heuristic that only checks the substring
    /// fallback would also match this body, but a heuristic that
    /// only checks the JSON shape and uses a stricter equality
    /// (e.g. `code == "ALREADY_EXISTS"` only) would miss the
    /// canonical Rekor wire string.
    #[test]
    fn test_is_already_exists_body_with_canonical_alreadyexists_string_returns_true() {
        let body = r#"{"code":"AlreadyExists","message":"entry already exists"}"#;
        assert!(is_already_exists_body(body));
    }

    /// Older / proxy-rewritten bodies surface `code` as the
    /// integer 409 (HTTP "Conflict").
    ///
    /// Bug it catches: a heuristic that only matches the string
    /// shape would route 409-coded bodies to `ClientError` and the
    /// caller would alert on what is actually idempotent re-submit
    /// success.
    #[test]
    fn test_is_already_exists_body_with_integer_409_code_returns_true() {
        let body = r#"{"code":409,"message":"already exists"}"#;
        assert!(is_already_exists_body(body));
    }

    /// SCREAMING_SNAKE variant — some Rekor deployments and proxies
    /// emit `"ALREADY_EXISTS"` instead of `"AlreadyExists"`.
    ///
    /// Bug it catches: a case-sensitive equality check on the
    /// canonical string would miss this and route to
    /// `ClientError`.
    #[test]
    fn test_is_already_exists_body_with_screaming_snake_code_returns_true() {
        let body = r#"{"code":"ALREADY_EXISTS","message":"dup"}"#;
        assert!(is_already_exists_body(body));
    }

    /// Substring fallback — a 4xx body that isn't structured JSON
    /// but contains the human-readable phrase still routes to
    /// `AlreadyExists`. Covers Rekor versions / proxies whose
    /// error body shape doesn't surface a structured `code`.
    ///
    /// Bug it catches: a heuristic that ONLY parses JSON would
    /// misroute proxy-rewritten plain-text bodies.
    #[test]
    fn test_is_already_exists_body_with_plaintext_substring_case_insensitive_returns_true() {
        // Mixed case + extra context — the substring scan must be
        // case-insensitive over the lower-cased body.
        assert!(is_already_exists_body(
            "this entry Already Exists in the log"
        ));
        assert!(is_already_exists_body("ALREADY EXISTS"));
    }

    /// A genuine 4xx that ISN'T idempotent must NOT match —
    /// otherwise every malformed-request response would silently
    /// be treated as success.
    ///
    /// Bug it catches: an over-eager substring fallback (e.g.
    /// matching just "exists") would false-positive on bodies
    /// like "schema does not exist" and treat real client errors
    /// as idempotent.
    #[test]
    fn test_is_already_exists_body_with_unrelated_4xx_body_returns_false() {
        let body = r#"{"code":"ValidationError","message":"signature shape malformed"}"#;
        assert!(!is_already_exists_body(body));
    }

    /// `RekorError` is `From<reqwest::Error>` via the `Transport`
    /// variant — the type-level check ensures `?` propagation in
    /// the construction sites still compiles after the rename.
    ///
    /// Bug it catches: a regression that drops `#[from]` on
    /// `Transport` would force every construction site to wrap
    /// manually, and the compiler would silently let an `Http`-
    /// using site keep building until its branch was reached at
    /// runtime.
    #[test]
    fn test_rekor_error_from_reqwest_error_uses_transport_variant() {
        // We can't easily fabricate a real `reqwest::Error` here,
        // but we can prove the From impl exists by referencing it
        // in a function signature — if the impl is missing, this
        // does not compile.
        fn _typecheck(_e: reqwest::Error) -> RekorError {
            RekorError::from(_e)
        }
    }

    // ── Local HTTP server fixture ─────────────────────────────────

    /// Minimal local HTTP server. One canned response per
    /// connection. Mirrors the pattern in `async_client::tests`
    /// and `tuf::client` — kept in-tree so the blocking client's
    /// test surface doesn't need the `async` feature on.
    struct LocalServer {
        base_url: String,
        port: u16,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl LocalServer {
        fn start(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
            use std::io::{BufRead, BufReader, Write};
            use std::net::TcpListener;
            use std::sync::atomic::{AtomicBool, Ordering};
            use std::sync::Arc;
            use std::thread;
            use std::time::Duration;

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
            409 => "Conflict",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            _ => "Status",
        }
    }

    impl Drop for LocalServer {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;
            use std::time::Duration;
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

    /// Find a free port for a "dead address" (LocalServer started
    /// then dropped) — guarantees nothing is listening so the
    /// client gets a connection-refused at the transport layer.
    fn dead_base_url() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        format!("http://127.0.0.1:{port}")
    }

    /// Build a Rekor-shaped success envelope. Mirrors the helper
    /// in `async_client::tests::rekor_success_envelope` so the
    /// blocking and async wire fixtures stay in lock-step.
    fn rekor_success_envelope(uuid: &str, body_bytes: &[u8]) -> Vec<u8> {
        use crate::merkle::hash_leaf;
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

    /// `submit` against an unreachable address surfaces
    /// [`RekorError::Transport`], NOT `ClientError`.
    ///
    /// Bug it catches: a regression that maps "connection refused"
    /// to a 4xx-shaped error would mislead operators into "fix
    /// your request" when the failure is "your network is down" —
    /// the retry policy and the alerting path differ.
    #[test]
    fn test_submit_against_unreachable_address_returns_transport_variant() {
        let url = dead_base_url();
        let client = HttpRekorClient::new(&url).expect("client");
        let err = client.submit(&sample_record()).expect_err("must fail");
        match err {
            RekorError::Transport(_) => {}
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    /// 5xx response → [`RekorError::ServerError`], carrying the
    /// status code and body verbatim.
    ///
    /// Bug it catches: a classifier that bucketed all non-2xx as
    /// `ClientError` would surface a Rekor outage as if the
    /// caller's request were malformed.
    #[test]
    fn test_submit_with_5xx_response_returns_server_error_variant() {
        let server = LocalServer::start(
            500,
            "application/json",
            br#"{"message":"internal error"}"#.to_vec(),
        );
        let client = HttpRekorClient::new(&server.base_url).expect("client");
        let err = client
            .submit(&sample_record())
            .expect_err("server said 500");
        match err {
            RekorError::ServerError { status, body } => {
                assert_eq!(status, 500);
                assert!(body.contains("internal error"), "body was {body:?}");
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    /// 4xx with a non-AlreadyExists body → [`RekorError::ClientError`].
    ///
    /// Bug it catches: a permissive substring heuristic that
    /// matched any "exists" substring (or that always defaulted
    /// 4xx to `AlreadyExists`) would silently mark malformed-
    /// request failures as idempotent success.
    #[test]
    fn test_submit_with_400_malformed_body_returns_client_error_variant() {
        let server = LocalServer::start(
            400,
            "application/json",
            br#"{"code":"ValidationError","message":"signature shape malformed"}"#.to_vec(),
        );
        let client = HttpRekorClient::new(&server.base_url).expect("client");
        let err = client
            .submit(&sample_record())
            .expect_err("server said 400");
        match err {
            RekorError::ClientError { status, body } => {
                assert_eq!(status, 400);
                assert!(body.contains("ValidationError"), "body was {body:?}");
            }
            other => panic!("expected ClientError, got {other:?}"),
        }
    }

    /// 409 with the canonical Rekor idempotency body →
    /// [`RekorError::AlreadyExists`].
    ///
    /// Bug it catches: a verifier that doesn't detect the
    /// idempotency shape surfaces re-submits of identical content
    /// as failures, breaking retry logic in callers that re-run
    /// signing pipelines (e.g. CI re-invocations on the same
    /// blob).
    #[test]
    fn test_submit_with_409_canonical_body_returns_already_exists_variant() {
        let server = LocalServer::start(
            409,
            "application/json",
            br#"{"code":"AlreadyExists","message":"entry already exists"}"#.to_vec(),
        );
        let client = HttpRekorClient::new(&server.base_url).expect("client");
        let err = client
            .submit(&sample_record())
            .expect_err("server said 409");
        match err {
            RekorError::AlreadyExists { body } => {
                assert!(body.contains("AlreadyExists"), "body was {body:?}");
            }
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    /// 4xx with a free-form body containing the human-readable
    /// phrase (case-insensitive) still routes to
    /// [`RekorError::AlreadyExists`].
    ///
    /// Bug it catches: a JSON-only heuristic would misroute
    /// proxy-rewritten plain-text bodies that preserve the
    /// idempotency phrase but drop the structured `code`.
    #[test]
    fn test_submit_with_4xx_substring_body_returns_already_exists_variant() {
        let server = LocalServer::start(
            400,
            "text/plain",
            b"this entry Already Exists in the log".to_vec(),
        );
        let client = HttpRekorClient::new(&server.base_url).expect("client");
        let err = client
            .submit(&sample_record())
            .expect_err("server said 400");
        match err {
            RekorError::AlreadyExists { body } => {
                assert!(
                    body.to_ascii_lowercase().contains("already exists"),
                    "body was {body:?}",
                );
            }
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    /// 200 OK with an unparseable body (a load balancer error
    /// page, a future-version response shape) →
    /// [`RekorError::Decode`].
    ///
    /// Bug it catches: a classifier that surfaced the parse
    /// failure as `RekorError::Json` (the entry-encode variant)
    /// would conflate "the content I tried to sign was bad" with
    /// "the server returned garbage" — operators can't route on
    /// the difference.
    #[test]
    fn test_submit_with_200_unparseable_body_returns_decode_variant() {
        let server = LocalServer::start(
            200,
            "text/html",
            b"<!DOCTYPE html><html><body>oops</body></html>".to_vec(),
        );
        let client = HttpRekorClient::new(&server.base_url).expect("client");
        let err = client
            .submit(&sample_record())
            .expect_err("body wasn't Rekor JSON");
        match err {
            RekorError::Decode(_) => {}
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    /// `fetch` shares the response-handling path with `submit` —
    /// asserting the new variants on the fetch path catches a
    /// regression where one path is updated but the other still
    /// emits the old `Status` / `Http` variants.
    ///
    /// Bug it catches: divergence between submit and fetch error
    /// classification. The two paths intentionally route through
    /// `decode_log_entry_response`; this test pins that they BOTH
    /// produce the granular variants.
    #[test]
    fn test_fetch_with_5xx_response_returns_server_error_variant() {
        let server = LocalServer::start(502, "text/plain", b"upstream timeout".to_vec());
        let client = HttpRekorClient::new(&server.base_url).expect("client");
        let err = client.fetch("any-uuid").expect_err("server said 502");
        match err {
            RekorError::ServerError { status, body } => {
                assert_eq!(status, 502);
                assert!(body.contains("upstream timeout"), "body was {body:?}");
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    /// `fetch` happy-path round trip — confirms the success path
    /// of the rewritten `decode_log_entry_response` still works.
    ///
    /// Bug it catches: a mistake in the rewrite that broke the
    /// 2xx branch (e.g. routing a successful response through
    /// `classify_non_success`) would silently take down every
    /// real submission.
    #[test]
    fn test_fetch_with_200_envelope_decodes_log_entry() {
        let entry = sample_record();
        let body = entry.encode_json().expect("encode");
        let envelope = rekor_success_envelope("cafe-d00d", &body);
        let server = LocalServer::start(200, "application/json", envelope);

        let client = HttpRekorClient::new(&server.base_url).expect("client");
        let log_entry = client.fetch("cafe-d00d").expect("fetch");

        assert_eq!(log_entry.uuid, "cafe-d00d");
        assert_eq!(log_entry.body, body);
    }
}
