//! DSSE — Dead Simple Signing Envelope (v1).
//!
//! Reference: <https://github.com/secure-systems-lab/dsse>
//!
//! The on-disk JSON shape:
//!
//! ```json
//! {
//!   "payloadType": "application/vnd.in-toto+json",
//!   "payload":     "<base64 payload bytes>",
//!   "signatures":  [{ "keyid": "...", "sig": "<base64 signature>" }]
//! }
//! ```
//!
//! The bytes that get signed are NOT the JSON above — they're the
//! Pre-Authentication Encoding (PAE), constructed from the raw
//! payload bytes + payloadType. The PAE is what every signer hashes
//! and signs; verifiers re-derive it from the envelope to check the
//! signature.
//!
//! PAE layout (bytes):
//!
//! ```text
//! DSSEv1 SP <pt-byte-len-decimal> SP <pt-bytes> SP <p-byte-len-decimal> SP <p-bytes>
//! ```
//!
//! All length fields are decimal ASCII strings of the byte length;
//! the literal SP is a single ASCII space (0x20). `pt-bytes` and
//! `p-bytes` are the raw byte sequences — no encoding, no escaping.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Literal prefix for DSSE v1 PAE.
pub const DSSE_PAE_PREFIX: &[u8] = b"DSSEv1";

/// Decoded DSSE envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Media type describing what `payload` represents. Sigstore
    /// commonly uses `application/vnd.in-toto+json` for in-toto
    /// attestations or specific `application/vnd.dev.sigstore.*`
    /// types for blob signatures.
    pub payload_type: String,

    /// Raw payload bytes — already base64-decoded. The JSON form
    /// stores them as base64 in the `payload` field.
    pub payload: Vec<u8>,

    /// One entry per signature. DSSE permits multiple signatures
    /// per envelope (e.g. one keyless + one static-key); a verifier
    /// applies its policy to decide which (or how many) must
    /// validate.
    pub signatures: Vec<Signature>,
}

/// One signature inside a DSSE envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Key identifier — opaque string the verifier maps to a public
    /// key. Optional per the DSSE spec (signers may omit it when
    /// the verifier already has the key out-of-band).
    pub keyid: Option<String>,

    /// Raw signature bytes. The JSON form stores them as base64 in
    /// the `sig` field.
    pub sig: Vec<u8>,
}

impl Envelope {
    /// Decode an envelope from the canonical JSON form.
    pub fn decode_json(buf: &[u8]) -> Result<Self, EnvelopeDecodeError> {
        let wire: EnvelopeWire = serde_json::from_slice(buf)?;
        let payload = STANDARD.decode(wire.payload.as_bytes()).map_err(|e| {
            EnvelopeDecodeError::PayloadBase64 {
                detail: e.to_string(),
            }
        })?;
        let mut signatures = Vec::with_capacity(wire.signatures.len());
        for s in wire.signatures {
            let sig = STANDARD.decode(s.sig.as_bytes()).map_err(|e| {
                EnvelopeDecodeError::SignatureBase64 {
                    detail: e.to_string(),
                }
            })?;
            signatures.push(Signature {
                keyid: s.keyid,
                sig,
            });
        }
        Ok(Envelope {
            payload_type: wire.payload_type,
            payload,
            signatures,
        })
    }

    /// Encode an envelope to the canonical JSON form.
    pub fn encode_json(&self) -> Result<Vec<u8>, EnvelopeEncodeError> {
        let wire = EnvelopeWire {
            payload_type: self.payload_type.clone(),
            payload: STANDARD.encode(&self.payload),
            signatures: self
                .signatures
                .iter()
                .map(|s| SignatureWire {
                    keyid: s.keyid.clone(),
                    sig: STANDARD.encode(&s.sig),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&wire)?;
        Ok(bytes)
    }

    /// Compute the Pre-Authentication Encoding (PAE) — the bytes a
    /// signer hashes and signs. Verifiers re-derive this from the
    /// envelope and check each signature against it.
    ///
    /// Convenience for `pae(self.payload_type.as_bytes(), &self.payload)`.
    pub fn pae(&self) -> Vec<u8> {
        pae(self.payload_type.as_bytes(), &self.payload)
    }
}

/// Compute DSSE v1 Pre-Authentication Encoding for the given
/// payload type + raw payload bytes.
///
/// `payload_type` is interpreted as bytes — UTF-8 in practice
/// (media types are ASCII), but we don't enforce that: PAE is
/// purely byte-level, and any signing-tool that hashes the result
/// only cares about the byte sequence.
pub fn pae(payload_type: &[u8], payload: &[u8]) -> Vec<u8> {
    let pt_len = payload_type.len().to_string();
    let p_len = payload.len().to_string();
    // Capacity: prefix + 4 spaces + 2 length strings + pt + payload.
    let cap =
        DSSE_PAE_PREFIX.len() + 4 + pt_len.len() + p_len.len() + payload_type.len() + payload.len();
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(DSSE_PAE_PREFIX);
    out.push(b' ');
    out.extend_from_slice(pt_len.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type);
    out.push(b' ');
    out.extend_from_slice(p_len.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

// ── JSON wire shapes (private — base64 transcoding lives at the
//    Envelope::decode_json / encode_json boundary so callers see
//    the decoded bytes form). ────────────────────────────────────

#[derive(Deserialize, Serialize)]
struct EnvelopeWire {
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: String,
    signatures: Vec<SignatureWire>,
}

#[derive(Deserialize, Serialize)]
struct SignatureWire {
    #[serde(skip_serializing_if = "Option::is_none")]
    keyid: Option<String>,
    sig: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeDecodeError {
    #[error("envelope JSON parse: {0}")]
    Json(#[from] serde_json::Error),

    #[error("payload base64 decode: {detail}")]
    PayloadBase64 { detail: String },

    #[error("signature base64 decode: {detail}")]
    SignatureBase64 { detail: String },
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeEncodeError {
    #[error("envelope JSON serialise: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PAE for the empty-payload case.
    ///
    /// Bug it catches: a builder that omits the trailing space when
    /// payload is empty would emit `"DSSEv1 N PT 0"` instead of
    /// `"DSSEv1 N PT 0 "`. The kernel-level rule is that ALL the
    /// space delimiters are present regardless of empty fields —
    /// drop one and the bytes hash to a different digest, breaking
    /// every empty-payload signature.
    #[test]
    fn test_pae_empty_payload_keeps_trailing_space_separator() {
        let result = pae(b"text/plain", b"");
        assert_eq!(result, b"DSSEv1 10 text/plain 0 ");
    }

    /// PAE example from the DSSE spec.
    ///
    /// Bug it catches: any drift in the prefix string, the space
    /// placement, or the decimal-length encoding (e.g., emitting
    /// hex or zero-padded numbers) would break interoperability
    /// with every Sigstore signer.
    #[test]
    fn test_pae_canonical_example_from_spec() {
        // From the DSSE spec, transcribed verbatim.
        let pt = b"http://example.com/HelloWorld";
        let payload = b"hello world";
        let result = pae(pt, payload);
        let expected = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world";
        assert_eq!(result, expected);
    }

    /// PAE encodes byte lengths, not character counts. A multi-byte
    /// UTF-8 payload like `"café"` is 5 bytes (the é = 2 bytes), so
    /// the length field must say 5, not 4.
    ///
    /// Bug it catches: a builder using `String::len()` thinks 4 chars
    /// → length 5 (correct, in Rust); but a builder using
    /// `.chars().count()` would emit 4. The latter mis-encoding
    /// breaks any non-ASCII payload.
    #[test]
    fn test_pae_byte_length_for_multibyte_utf8_payload() {
        let payload = "café".as_bytes(); // 5 bytes
        assert_eq!(payload.len(), 5);
        let result = pae(b"text/plain", payload);
        assert_eq!(result, b"DSSEv1 10 text/plain 5 caf\xC3\xA9");
    }

    /// Decode of a known-good envelope round-trips fields.
    #[test]
    fn test_decode_well_formed_envelope_extracts_fields() {
        let json = br#"{
            "payloadType": "application/vnd.in-toto+json",
            "payload": "aGVsbG8=",
            "signatures": [
                { "keyid": "k1", "sig": "MEUCIQ==" }
            ]
        }"#;
        let env = Envelope::decode_json(json).unwrap();
        assert_eq!(env.payload_type, "application/vnd.in-toto+json");
        assert_eq!(env.payload, b"hello");
        assert_eq!(env.signatures.len(), 1);
        assert_eq!(env.signatures[0].keyid.as_deref(), Some("k1"));
        assert_eq!(env.signatures[0].sig, &[0x30, 0x45, 0x02, 0x21]);
    }

    /// `keyid` is optional per the DSSE spec — decode tolerates
    /// signatures that omit it (e.g., keyless flows where the cert
    /// chain identifies the signer).
    ///
    /// Bug it catches: a parser requiring `keyid` would reject every
    /// keyless Sigstore envelope. Common Go-port mistake.
    #[test]
    fn test_decode_signature_without_keyid_is_accepted() {
        let json = br#"{
            "payloadType": "x",
            "payload": "",
            "signatures": [{ "sig": "MEUCIQ==" }]
        }"#;
        let env = Envelope::decode_json(json).unwrap();
        assert!(env.signatures[0].keyid.is_none());
    }

    /// Envelope with zero signatures is well-formed JSON but a
    /// verifier would reject it (no signatures to check). The
    /// decoder accepts the shape; policy is the caller's job.
    #[test]
    fn test_decode_envelope_with_zero_signatures_succeeds() {
        let json = br#"{
            "payloadType": "x",
            "payload": "aGVsbG8=",
            "signatures": []
        }"#;
        let env = Envelope::decode_json(json).unwrap();
        assert!(env.signatures.is_empty());
        assert_eq!(env.payload, b"hello");
    }

    /// Bad base64 in the payload field surfaces as a typed error,
    /// not a panic.
    ///
    /// Bug it catches: a parser using `unwrap()` on the base64 step
    /// would panic on any malformed envelope from a malicious or
    /// truncated source. Typed error lets the caller route on it
    /// (drop the envelope, log, retry, etc.).
    #[test]
    fn test_decode_invalid_payload_base64_returns_typed_error() {
        let json = br#"{
            "payloadType": "x",
            "payload": "not valid base64!!",
            "signatures": []
        }"#;
        let err = Envelope::decode_json(json).unwrap_err();
        assert!(matches!(err, EnvelopeDecodeError::PayloadBase64 { .. }));
    }

    /// Encode → decode round-trip preserves every load-bearing
    /// field, including multi-byte payload bytes and a multi-
    /// signature shape.
    ///
    /// Bug it catches: any drift in the encode path — base64 padding
    /// elision, signature-array key ordering — would surface as a
    /// re-decode mismatch.
    #[test]
    fn test_encode_then_decode_round_trips_envelope() {
        let original = Envelope {
            payload_type: "application/vnd.in-toto+json".into(),
            payload: b"\x00\x01\x02\x03\xff\xfe\xfd\x80".to_vec(),
            signatures: vec![
                Signature {
                    keyid: Some("k1".into()),
                    sig: vec![0xAA, 0xBB, 0xCC],
                },
                Signature {
                    keyid: None,
                    sig: vec![0xDE, 0xAD, 0xBE, 0xEF],
                },
            ],
        };
        let json = original.encode_json().unwrap();
        let decoded = Envelope::decode_json(&json).unwrap();
        assert_eq!(original, decoded);
    }

    /// `Envelope::pae()` and the free `pae()` function produce
    /// identical bytes for the same inputs.
    #[test]
    fn test_envelope_pae_matches_free_function() {
        let env = Envelope {
            payload_type: "x/y".into(),
            payload: b"hi".to_vec(),
            signatures: vec![],
        };
        assert_eq!(env.pae(), pae(b"x/y", b"hi"));
    }
}
