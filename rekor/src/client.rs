//! Rekor client SPI + an in-memory mock.
//!
//! v0 ships:
//!
//! * `RekorClient` trait — the contract a real HTTP-backed client
//!   will implement in v0.5.
//! * `LogEntry` — what `submit` returns, including the inclusion
//!   proof that `merkle::verify_inclusion` consumes.
//! * `MockRekorClient` — synthesises a deterministic single-leaf
//!   log per submission so consumers (notably `swe_justsign_sign`)
//!   can exercise the verifier end-to-end with no HTTP dependency.
//!
//! The mock is intentionally tiny: every submission goes into a
//! brand-new 1-leaf log whose root IS the leaf hash. That's enough
//! to round-trip a verifier; richer mocks (multi-entry log,
//! reproducible tree state) land alongside the real HTTP client.

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
    }
}
