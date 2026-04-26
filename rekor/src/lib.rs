//! Rekor client for justsign — submit + Merkle inclusion-proof
//! verification.
//!
//! v0 ships verifier-only:
//!
//! * RFC 6962 Merkle inclusion-proof verification (`merkle::verify_inclusion`).
//! * `hashedrekord` v0.0.1 entry types (`entry::HashedRekord`)
//!   with JSON encode/decode.
//! * A `RekorClient` trait + `MockRekorClient` that returns canned
//!   entries with synthesised inclusion proofs — enough for
//!   `swe_justsign_sign` to exercise the verifier without an HTTP
//!   dependency.
//!
//! No real HTTP client lives here in v0. Submitting a real entry +
//! fetching a real proof from rekor.sigstore.dev lands in a later
//! slice; until then everything tests against the mock.

pub mod client;
pub mod entry;
pub mod merkle;

pub use client::{LogEntry, MockRekorClient, RekorClient};
pub use entry::{Data, HashedRekord, HashedRekordHash, PublicKey, Signature};
pub use merkle::{verify_inclusion, EMPTY_TREE_ROOT, INTERNAL_NODE_PREFIX, LEAF_NODE_PREFIX};

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
    #[test]
    fn test_rekor_error_from_serde_json_error_uses_json_variant() {
        let e: serde_json::Error = serde_json::from_str::<u32>("not json").unwrap_err();
        let wrapped: RekorError = e.into();
        assert!(matches!(wrapped, RekorError::Json(_)));
    }
}
