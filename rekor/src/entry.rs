//! Rekor entry types.
//!
//! Two schemas are supported here:
//!
//! * [`HashedRekord`] — `hashedrekord` v0.0.1. The schema for
//!   `MessageSignature`-content bundles (cosign `sign-blob` shape):
//!   the signature is verified against `SHA-256(payload)`.
//! * [`DsseRekord`]  — `dsse` v0.0.1. The schema for
//!   `DsseEnvelope`-content bundles (cosign `attest` / DSSE shape):
//!   the signature is verified against the DSSE PAE bytes
//!   (`DSSEv1 SP <type-len> SP <type> SP <payload-len> SP <payload>`),
//!   not the payload hash. Schemas mismatch is the load-bearing
//!   reason both types exist — submitting a DSSE bundle's signature
//!   to the hashedrekord schema fails Rekor's signature
//!   verification with `invalid signature when validating ASN.1
//!   encoded signature`.
//!
//! ## `hashedrekord` body shape
//!
//! This is the JSON Rekor accepts at `POST /api/v1/log/entries` and
//! returns inside `LogEntry.body` (base64-encoded):
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
//! ## `dsse` submit shape
//!
//! ```json
//! {
//!   "apiVersion": "0.0.1",
//!   "kind": "dsse",
//!   "spec": {
//!     "proposedContent": {
//!       "envelope": "<JSON-serialised DSSE envelope as a string>",
//!       "verifiers": ["<base64-encoded PEM cert(s) or pubkey>"]
//!     }
//!   }
//! }
//! ```
//!
//! Note that `envelope` is the DSSE envelope JSON *as a string*
//! (not nested JSON) per
//! `sigstore/rekor/pkg/types/dsse/v0.0.1/dsse_v0_0_1_schema.json`,
//! and each `verifiers` entry is base64 of the PEM (cert or pubkey)
//! bytes — also per the schema's `format: "byte"` field convention.
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

// ──────────────────────────────────────────────────────────────────
// DSSE rekor entry (sigstore/rekor types/dsse v0.0.1).
//
// Producer-side struct. The wire shape Rekor accepts at
// `POST /api/v1/log/entries` is `{apiVersion: "0.0.1", kind: "dsse",
// spec: <encode_json output>}`; the envelope wrapping lives at the
// submit boundary in `client::HttpRekorClient::submit_dsse` so the
// mock and the HTTP client share this same canonical body.
// ──────────────────────────────────────────────────────────────────

/// `dsse` v0.0.1 rekor entry.
///
/// Used by callers whose bundles are DSSE-shaped (cosign `attest` /
/// `sign-blob` keyless) — separate from [`HashedRekord`] which is for
/// `MessageSignature`-shaped bundles (cosign `sign-blob` static-key).
/// Schemas mismatch is the load-bearing reason: hashedrekord's
/// signature verification expects `signature == ECDSA(SHA-256(payload))`,
/// but DSSE signs PAE bytes, not payload bytes. Submitting a DSSE
/// bundle's signature via the hashedrekord schema fails Rekor's
/// signature verification with `invalid signature when validating
/// ASN.1 encoded signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsseRekord {
    /// JSON-serialised DSSE envelope. Rekor parses this on receipt
    /// to extract the inner signatures + payload + payload_type.
    /// Held verbatim here so the producer that built the envelope
    /// (typically [`crate::HashedRekord`]'s peer construction site
    /// in `swe_justsign_sign`) can hand the canonical bytes through
    /// without a re-encode round-trip.
    pub envelope_bytes: Vec<u8>,

    /// Verifier credentials. Each entry is PEM-encoded — a leaf
    /// cert (for keyless flows) OR a public key (for static-key
    /// flows). The producer typically supplies a single leaf cert
    /// for keyless flows. Rekor verifies each `signature` in the
    /// envelope against each verifier by computing the DSSE PAE and
    /// checking the ECDSA signature.
    ///
    /// Stored as raw PEM bytes here; [`Self::encode_json`] handles
    /// the base64 transcoding required by the schema's `format:
    /// "byte"` field convention.
    pub verifiers_pem: Vec<Vec<u8>>,
}

impl DsseRekord {
    /// Encode to the JSON `spec` body Rekor expects on
    /// `POST /api/v1/log/entries`.
    ///
    /// Wire shape (the `spec` object only — the `apiVersion`/`kind`
    /// envelope is added at the submit boundary):
    ///
    /// ```json
    /// {
    ///   "proposedContent": {
    ///     "envelope": "<DSSE envelope JSON as a STRING>",
    ///     "verifiers": ["<base64 of PEM bytes>", ...]
    ///   }
    /// }
    /// ```
    ///
    /// `envelope` is a JSON string field — NOT nested JSON. Rekor
    /// parses the string back into JSON on receipt; nesting it as a
    /// JSON object here would fail schema validation.
    pub fn encode_json(&self) -> Result<Vec<u8>, RekorError> {
        use serde::de::Error as _;

        // The envelope must round-trip through UTF-8: Rekor's schema
        // declares it as `type: "string"`, and serde_json::Value's
        // String variant requires `Vec<u8>` to be valid UTF-8.
        // Rejecting non-UTF-8 here surfaces a typed error rather
        // than silently emitting a malformed string field.
        let envelope_str = std::str::from_utf8(&self.envelope_bytes).map_err(|e| {
            RekorError::Json(serde_json::Error::custom(format!(
                "dsse envelope is not valid UTF-8: {e}"
            )))
        })?;

        let verifiers: Vec<String> = self
            .verifiers_pem
            .iter()
            .map(|pem| STANDARD.encode(pem))
            .collect();

        let body = serde_json::json!({
            "proposedContent": {
                "envelope": envelope_str,
                "verifiers": verifiers,
            }
        });
        let bytes = serde_json::to_vec(&body)?;
        Ok(bytes)
    }
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

    // ── DsseRekord encoder tests ──────────────────────────────────

    /// Pin the canonical wire shape for `DsseRekord::encode_json`.
    /// The `proposedContent.envelope` field MUST be a JSON string
    /// (the DSSE envelope's JSON serialised as a string), and
    /// `proposedContent.verifiers` MUST be an array of base64-
    /// encoded PEM strings — per
    /// `sigstore/rekor/pkg/types/dsse/v0.0.1/dsse_v0_0_1_schema.json`.
    ///
    /// Bug it catches: a refactor that flips the field naming (e.g.
    /// `proposedContent.payload` instead of `proposedContent.envelope`,
    /// or `keys` instead of `verifiers`) silently breaks every Rekor
    /// submission because production Rekor enforces this schema and
    /// rejects unknown fields. Equally — a refactor that nests the
    /// envelope as a JSON object instead of a string would also be
    /// rejected by Rekor's schema validation.
    #[test]
    fn test_dsse_rekord_encode_json_emits_canonical_shape() {
        let envelope_json =
            br#"{"payloadType":"text/plain","payload":"aGVsbG8=","signatures":[{"sig":"AAA="}]}"#;
        let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

        let entry = DsseRekord {
            envelope_bytes: envelope_json.to_vec(),
            verifiers_pem: vec![pem.to_vec()],
        };

        let body = entry.encode_json().expect("encode");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");

        // Top-level object has exactly `proposedContent` (writeOnly
        // submit shape per the schema).
        let pc = parsed
            .get("proposedContent")
            .expect("proposedContent must be present");

        // `envelope` is a JSON STRING field — NOT a nested JSON
        // object. Pin both: the type AND the exact byte sequence
        // (we round-trip through std::str::from_utf8 so the bytes
        // are preserved verbatim).
        let env_value = pc.get("envelope").expect("envelope field present");
        let env_str = env_value
            .as_str()
            .expect("envelope must be a JSON string, not nested JSON");
        assert_eq!(env_str.as_bytes(), envelope_json);

        // `verifiers` is an array of base64-encoded PEM strings.
        // Pin the base64 contents — the schema's `format: "byte"`
        // requires base64-of-the-PEM, NOT raw PEM, NOT base64-of-DER.
        let verifiers = pc
            .get("verifiers")
            .and_then(|v| v.as_array())
            .expect("verifiers must be an array");
        assert_eq!(verifiers.len(), 1);
        let v0 = verifiers[0].as_str().expect("verifier must be a string");
        let decoded = STANDARD.decode(v0).expect("verifier must be base64");
        assert_eq!(decoded, pem);

        // No stray fields in proposedContent — the writeOnly schema
        // requires exactly { envelope, verifiers }; an extra field
        // is a regression that would surface as "additionalProperties
        // not allowed" from Rekor's strict schema validation.
        let pc_obj = pc.as_object().expect("proposedContent is an object");
        assert_eq!(
            pc_obj.len(),
            2,
            "proposedContent must have exactly envelope+verifiers, got {pc_obj:?}",
        );
    }

    /// `DsseRekord::encode_json` accepts multiple verifiers and
    /// preserves their order — Rekor's schema specifies an array,
    /// not a set, and order-sensitive callers (those producing
    /// envelopes signed by multiple keys) need stable ordering.
    ///
    /// Bug it catches: an encoder that deduplicates or sorts
    /// verifiers would silently drop or reorder the producer's
    /// supplied list, breaking multi-signature DSSE flows.
    #[test]
    fn test_dsse_rekord_encode_json_preserves_verifier_order() {
        let entry = DsseRekord {
            envelope_bytes: br#"{"payloadType":"x","payload":"","signatures":[]}"#.to_vec(),
            verifiers_pem: vec![b"first-pem".to_vec(), b"second-pem".to_vec()],
        };
        let body = entry.encode_json().expect("encode");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");
        let verifiers = parsed["proposedContent"]["verifiers"]
            .as_array()
            .expect("verifiers array");
        let v0 = STANDARD.decode(verifiers[0].as_str().unwrap()).unwrap();
        let v1 = STANDARD.decode(verifiers[1].as_str().unwrap()).unwrap();
        assert_eq!(v0, b"first-pem");
        assert_eq!(v1, b"second-pem");
    }

    /// Non-UTF-8 envelope bytes surface a typed `RekorError::Json`
    /// rather than silently emitting a malformed JSON-string field.
    /// The schema declares `envelope` as `type: "string"`, and
    /// serde_json::Value::String requires UTF-8.
    ///
    /// Bug it catches: an encoder that called
    /// `String::from_utf8_lossy` would silently corrupt envelope
    /// bytes containing non-UTF-8 sequences (which, in practice,
    /// shouldn't happen — DSSE envelopes are JSON, hence UTF-8 — but
    /// a producer-side bug or a fuzzer could supply invalid input).
    #[test]
    fn test_dsse_rekord_encode_json_rejects_non_utf8_envelope_with_typed_error() {
        let entry = DsseRekord {
            // 0xFF is invalid UTF-8 in any position.
            envelope_bytes: vec![0xFF, 0xFE, 0xFD],
            verifiers_pem: vec![b"pem".to_vec()],
        };
        let err = entry.encode_json().expect_err("must reject non-UTF-8");
        assert!(matches!(err, RekorError::Json(_)), "got {err:?}");
    }
}
