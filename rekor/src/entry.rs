//! Rekor `hashedrekord` v0.0.1 entry shape.
//!
//! This is the JSON Rekor accepts at `POST /api/v1/log/entries` and
//! returns inside `LogEntry.body` (base64-encoded). The shape:
//!
//! ```json
//! {
//!   "signature": {
//!     "content":   "<base64 signature bytes>",
//!     "publicKey": { "content": "<base64 PEM or DER>" }
//!   },
//!   "data": {
//!     "hash": { "algorithm": "sha256", "value": "<hex digest>" }
//!   }
//! }
//! ```
//!
//! v0 ships the bare body (no `apiVersion`/`kind` envelope). The
//! envelope wrapping lives at the submit boundary — added in v0.5
//! when the real HTTP client lands. Today's mock client returns a
//! `LogEntry` containing the body verbatim.

use crate::RekorError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// A `hashedrekord` v0.0.1 entry body — what gets signed and what
/// the log indexes.
///
/// Construct directly with public fields, or via `decode_json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashedRekord {
    /// Detached signature over the original data, plus the public
    /// key the verifier should check it against.
    pub signature: Signature,

    /// Hash of the data that was signed. Rekor never sees the data
    /// itself — only the digest.
    pub data: Data,
}

/// A signature + the public key that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Raw signature bytes — already base64-decoded. The JSON form
    /// stores them as base64 in the `content` field.
    pub content: Vec<u8>,

    /// The public key paired with the signature.
    pub public_key: PublicKey,
}

/// A public key — usually PEM-encoded for `hashedrekord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Raw key bytes — already base64-decoded. The JSON form
    /// stores them as base64 in the `content` field. The
    /// underlying bytes are typically the PEM-encoded
    /// `-----BEGIN PUBLIC KEY-----` block, but the type is
    /// opaque at this layer.
    pub content: Vec<u8>,
}

/// Hash of the signed data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Data {
    pub hash: HashedRekordHash,
}

/// Algorithm + hex digest pair. RFC 6962 + Rekor both standardize
/// on `"sha256"`; other algorithms are rejected by Rekor's server-
/// side schema, but we don't enforce that here — pass-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashedRekordHash {
    /// Algorithm name. Rekor accepts `"sha256"`.
    pub algorithm: String,
    /// Lower-case hex of the digest. Rekor's schema is strict
    /// about hex form; we preserve whatever the caller supplies
    /// so a server-side rejection is reproducible.
    pub value: String,
}

impl HashedRekord {
    /// Decode from the canonical JSON body.
    pub fn decode_json(buf: &[u8]) -> Result<Self, RekorError> {
        use serde::de::Error as _;
        let wire: HashedRekordWire = serde_json::from_slice(buf)?;
        let signature_content =
            STANDARD
                .decode(wire.signature.content.as_bytes())
                .map_err(|e| {
                    RekorError::Json(serde_json::Error::custom(format!(
                        "signature.content base64: {e}"
                    )))
                })?;
        let public_key_content = STANDARD
            .decode(wire.signature.public_key.content.as_bytes())
            .map_err(|e| {
                RekorError::Json(serde_json::Error::custom(format!(
                    "signature.publicKey.content base64: {e}"
                )))
            })?;
        Ok(HashedRekord {
            signature: Signature {
                content: signature_content,
                public_key: PublicKey {
                    content: public_key_content,
                },
            },
            data: Data {
                hash: HashedRekordHash {
                    algorithm: wire.data.hash.algorithm,
                    value: wire.data.hash.value,
                },
            },
        })
    }

    /// Encode to the canonical JSON body.
    pub fn encode_json(&self) -> Result<Vec<u8>, RekorError> {
        let wire = HashedRekordWire {
            signature: SignatureWire {
                content: STANDARD.encode(&self.signature.content),
                public_key: PublicKeyWire {
                    content: STANDARD.encode(&self.signature.public_key.content),
                },
            },
            data: DataWire {
                hash: HashWire {
                    algorithm: self.data.hash.algorithm.clone(),
                    value: self.data.hash.value.clone(),
                },
            },
        };
        let bytes = serde_json::to_vec(&wire)?;
        Ok(bytes)
    }
}

// ── JSON wire shapes — base64 transcoding lives at the
//    HashedRekord::decode_json / encode_json boundary so callers see
//    raw bytes in the public types. ─────────────────────────────

#[derive(Deserialize, Serialize)]
struct HashedRekordWire {
    signature: SignatureWire,
    data: DataWire,
}

#[derive(Deserialize, Serialize)]
struct SignatureWire {
    content: String,
    #[serde(rename = "publicKey")]
    public_key: PublicKeyWire,
}

#[derive(Deserialize, Serialize)]
struct PublicKeyWire {
    content: String,
}

#[derive(Deserialize, Serialize)]
struct DataWire {
    hash: HashWire,
}

#[derive(Deserialize, Serialize)]
struct HashWire {
    algorithm: String,
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> HashedRekord {
        HashedRekord {
            signature: Signature {
                content: vec![0xDE, 0xAD, 0xBE, 0xEF],
                public_key: PublicKey {
                    content: b"-----BEGIN PUBLIC KEY-----\nMFk...\n-----END PUBLIC KEY-----\n"
                        .to_vec(),
                },
            },
            data: Data {
                hash: HashedRekordHash {
                    algorithm: "sha256".into(),
                    value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .into(),
                },
            },
        }
    }

    /// Encode → decode round-trip preserves every field, including
    /// raw signature bytes containing high-bit values.
    ///
    /// Bug it catches: forgetting the `publicKey` JSON rename
    /// (camelCase, not snake_case) silently breaks compatibility
    /// with every Rekor server and CLI — they emit `publicKey`,
    /// not `public_key`. The round-trip would still pass on its
    /// own output, but real-world JSON would fail to decode.
    /// Combined with the known-good vector test below, both halves
    /// are pinned.
    #[test]
    fn test_encode_then_decode_round_trips_hashed_rekord() {
        let original = sample_record();
        let json = original.encode_json().unwrap();
        let decoded = HashedRekord::decode_json(&json).unwrap();
        assert_eq!(original, decoded);
    }

    /// Decode a known-good Rekor body using the EXACT field names
    /// Rekor produces — `publicKey` (camelCase). Guards against
    /// the snake-case slip described above.
    #[test]
    fn test_decode_canonical_rekor_body_with_camel_case_public_key_field() {
        let json = br#"{
            "signature": {
                "content": "3q2+7w==",
                "publicKey": { "content": "aGVsbG8=" }
            },
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }
            }
        }"#;
        let rec = HashedRekord::decode_json(json).unwrap();
        assert_eq!(rec.signature.content, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(rec.signature.public_key.content, b"hello");
        assert_eq!(rec.data.hash.algorithm, "sha256");
        assert_eq!(rec.data.hash.value.len(), 64);
    }

    /// Encode emits the camelCase `publicKey` key, matching the
    /// Rekor wire format. A snake_case key here would round-trip
    /// our own data fine but be rejected by the real Rekor server.
    #[test]
    fn test_encode_emits_camel_case_public_key_field() {
        let json = sample_record().encode_json().unwrap();
        let s = std::str::from_utf8(&json).unwrap();
        assert!(s.contains("\"publicKey\""), "encoded JSON: {s}");
        assert!(!s.contains("public_key"), "encoded JSON: {s}");
    }

    /// Bad base64 in `signature.content` surfaces a typed error,
    /// not a panic.
    ///
    /// Bug it catches: an `unwrap()` on the base64 step would crash
    /// on any malformed body from the network or a malicious peer.
    #[test]
    fn test_decode_invalid_signature_base64_returns_typed_error() {
        let json = br#"{
            "signature": {
                "content": "!!!not base64!!!",
                "publicKey": { "content": "aGVsbG8=" }
            },
            "data": { "hash": { "algorithm": "sha256", "value": "abc" } }
        }"#;
        let err = HashedRekord::decode_json(json).unwrap_err();
        assert!(matches!(err, RekorError::Json(_)));
    }

    /// Missing required field (e.g. `data`) → typed error, no panic.
    #[test]
    fn test_decode_missing_data_field_returns_typed_error() {
        let json = br#"{
            "signature": {
                "content": "3q2+7w==",
                "publicKey": { "content": "aGVsbG8=" }
            }
        }"#;
        let err = HashedRekord::decode_json(json).unwrap_err();
        assert!(matches!(err, RekorError::Json(_)));
    }
}
