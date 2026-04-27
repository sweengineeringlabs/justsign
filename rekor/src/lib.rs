//! Rekor client for justsign — submit + Merkle inclusion-proof
//! verification.
//!
//! Surface:
//!
//! * RFC 6962 Merkle inclusion-proof verification (`merkle::verify_inclusion`).
//! * `hashedrekord` v0.0.1 entry types (`entry::HashedRekord`) with
//!   JSON encode/decode.
//! * A `RekorClient` trait + two impls: `MockRekorClient` (canned
//!   single-leaf log; deterministic; no I/O) and `HttpRekorClient`
//!   (blocking `reqwest`-backed; talks to a real Rekor server such
//!   as `rekor.sigstage.dev`).
//!
//! `HttpRekorClient` exposes an inherent `fetch(uuid)` method on top
//! of the trait's `submit`, mirroring `GET /api/v1/log/entries/{uuid}`
//! for re-hydration. The trait surface stays minimal because
//! verifiers re-check inclusion proofs against the bundle's stored
//! root and don't need a server round-trip.

pub mod client;
pub mod entry;
pub mod merkle;

#[cfg(feature = "async")]
pub mod async_client;

pub use client::{decode_log_entry_bytes, HttpRekorClient, LogEntry, MockRekorClient, RekorClient};
pub use entry::{Data, HashedRekord, HashedRekordHash, PublicKey, Signature};
pub use merkle::{verify_inclusion, EMPTY_TREE_ROOT, INTERNAL_NODE_PREFIX, LEAF_NODE_PREFIX};

#[cfg(feature = "async")]
pub use async_client::{AsyncRekorClient, HttpRekorClientAsync};

/// Errors surfaced by the Rekor crate — verifier mismatches,
/// shape mismatches, JSON failures, and (later) HTTP failures.
#[derive(Debug, thiserror::Error)]
pub enum RekorError {
    /// The root computed from leaf+path+index does not match the
    /// expected root the caller supplied.
    #[error(
        "merkle root mismatch: computed {} expected {}",
        hex_lower(.computed),
        hex_lower(.expected),
    )]
    RootMismatch {
        computed: [u8; 32],
        expected: [u8; 32],
    },

    /// The proof has the wrong number of sibling hashes for the
    /// (index, tree_size) pair. RFC 6962 §2.1.1 fixes the path
    /// length once those two are known; any other length is a
    /// malformed proof.
    #[error("merkle path length mismatch: expected {expected} got {got}")]
    PathLengthMismatch { expected: u32, got: usize },

    /// The leaf index is >= tree_size. A proof for such an index
    /// cannot exist.
    #[error("merkle leaf index out of range: index {index} tree_size {tree_size}")]
    IndexOutOfRange { index: u64, tree_size: u64 },

    /// `tree_size == 0` — there are no leaves to prove inclusion
    /// against. Distinguished from `IndexOutOfRange` because the
    /// empty-tree case has a well-defined root (SHA-256 of the
    /// empty string per RFC 6962 §2.1) but no leaves at all, and
    /// callers usually want to handle "log is empty" separately
    /// from "leaf is past the end".
    #[error("merkle tree is empty (tree_size = 0); no inclusion proof exists")]
    EmptyTree,

    /// JSON encode/decode failure on a Rekor entry.
    #[error("rekor entry JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Network-level failure talking to a Rekor HTTP endpoint —
    /// DNS resolution, TCP connect, TLS handshake, connection
    /// reset, body-read truncation, etc. The request never
    /// produced a complete HTTP response. Operators handle these
    /// by retrying with backoff; a bundle in this state is
    /// unsubmitted and may have been partially sent (Rekor's
    /// idempotency contract handles partial sends — duplicate
    /// content surfaces as `AlreadyExists` on the retry).
    #[error("rekor transport: {0}")]
    Transport(#[from] reqwest::Error),

    /// HTTP 5xx — the server is reachable but failed the request.
    /// Operators alert and queue for retry; the body is logged
    /// verbatim but should not be parsed for routing because
    /// Rekor's 5xx body shape is not stable across versions.
    #[error("rekor server error {status}: {body}")]
    ServerError {
        /// HTTP status code (500..=599).
        status: u16,
        /// Response body, lossily UTF-8-decoded. Diagnostic only.
        body: String,
    },

    /// HTTP 4xx that is NOT the "entry already exists" idempotency
    /// shape. Operator-fixable: malformed request, bad signature
    /// shape, missing required fields, rate-limit (429), etc.
    /// Distinct from `ServerError` because retries with the same
    /// payload won't help — the caller has to fix the request.
    #[error("rekor client error {status}: {body}")]
    ClientError {
        /// HTTP status code (400..=499, except the AlreadyExists
        /// shape which routes to `AlreadyExists`).
        status: u16,
        /// Response body, lossily UTF-8-decoded. Diagnostic only.
        body: String,
    },

    /// Rekor's "entry already exists" idempotency response.
    /// Distinct from `ClientError` because callers should treat
    /// this as success: the entry IS in the log, it was simply
    /// submitted by a previous attempt. The detection heuristic
    /// (in `client::is_already_exists_body`) accepts the canonical
    /// JSON shape (a top-level object containing `code` field
    /// with value `"AlreadyExists"`, or `code: 409`) AND falls
    /// back to a case-insensitive substring match on
    /// `"already exists"` in the body — the substring fallback
    /// covers Rekor versions whose error body shape doesn't
    /// surface a structured `code`.
    #[error("rekor entry already exists (idempotent): {body}")]
    AlreadyExists {
        /// Response body, lossily UTF-8-decoded. Surfaced verbatim
        /// so callers can log the canonical Rekor message.
        body: String,
    },

    /// HTTP 200 OK but the response body wasn't valid Rekor JSON.
    /// Server-side bug (a load balancer error page returned with a
    /// 200, a partially-truncated body, a future-version response
    /// shape we don't know how to parse). Operators alert; a
    /// retry will probably not help.
    #[error("rekor response decode: {0}")]
    Decode(serde_json::Error),
}

/// Lower-case hex of a 32-byte digest. Used by `RekorError`'s
/// `Display` so mismatch messages are diff-able by eye.
fn hex_lower(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        // Two hex chars per byte; manual to avoid pulling `hex`.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RootMismatch` formats both digests as full 64-char lowercase
    /// hex so on-call engineers can diff them by eye in a log line.
    ///
    /// Bug it catches: a Display impl using `Debug` for `[u8; 32]`
    /// would emit `[0, 1, …]` decimal-array form — unreadable in
    /// logs, and mixing it with hex-formatted expected roots from
    /// other tools means the mismatch can't be spotted.
    #[test]
    fn test_root_mismatch_display_uses_lowercase_hex() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 0xab;
        b[31] = 0xcd;
        let err = RekorError::RootMismatch {
            computed: a,
            expected: b,
        };
        let s = err.to_string();
        assert!(s.contains("ab00000000000000000000000000000000000000000000000000000000000000"));
        assert!(s.contains("00000000000000000000000000000000000000000000000000000000000000cd"));
    }

    /// `Json(_)` is constructible via `From<serde_json::Error>` so
    /// callers can use `?` on `serde_json` calls without wrapping.
    /// `Decode` deliberately does NOT impl `From<serde_json::Error>`
    /// — entry-encode failures (Json) and response-decode failures
    /// (Decode) are different bug classes and must be constructed
    /// explicitly at the right site.
    #[test]
    fn test_rekor_error_from_serde_json_error_uses_json_variant() {
        let e: serde_json::Error = serde_json::from_str::<u32>("not json").unwrap_err();
        let wrapped: RekorError = e.into();
        assert!(matches!(wrapped, RekorError::Json(_)));
    }

    /// `Decode` is the response-decode variant — Display message
    /// surfaces "rekor response decode" so log scrapers can
    /// distinguish it from the entry-encode `Json` variant.
    ///
    /// Bug it catches: a copy-paste of the `Json` Display string
    /// onto `Decode` would make the two variants
    /// indistinguishable in logs, defeating the whole point of
    /// splitting them.
    #[test]
    fn test_decode_variant_display_distinguishes_response_decode_from_entry_json() {
        let e: serde_json::Error = serde_json::from_str::<u32>("not json").unwrap_err();
        let decode = RekorError::Decode(e);
        let rendered = decode.to_string();
        assert!(rendered.contains("rekor response decode"), "got {rendered}");
    }

    /// `AlreadyExists` Display marks itself as idempotent so an
    /// operator who greps logs can spot "this is success-by-
    /// another-name" without parsing the variant tag from the
    /// surrounding error chain.
    #[test]
    fn test_already_exists_display_marks_idempotent() {
        let err = RekorError::AlreadyExists {
            body: r#"{"code":"AlreadyExists"}"#.to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("idempotent"), "got {s}");
        assert!(s.contains("AlreadyExists"), "got {s}");
    }
}
