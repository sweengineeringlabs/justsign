//! in-toto attestation Statement (predicate v1).
//!
//! Reference: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
//!
//! The on-disk JSON shape:
//!
//! ```json
//! {
//!   "_type": "https://in-toto.io/Statement/v1",
//!   "subject": [
//!     { "name": "pkg:oci/example@sha256:...", "digest": { "sha256": "abc..." } }
//!   ],
//!   "predicateType": "https://slsa.dev/provenance/v1",
//!   "predicate": { ... predicate-type-specific JSON ... }
//! }
//! ```
//!
//! The Statement is what gets wrapped inside a DSSE envelope's
//! `payload` field with `payloadType = "application/vnd.in-toto+json"`.
//!
//! We deliberately do NOT constrain the `predicate` field's shape:
//! that's per-predicate-type (SLSA Provenance, SPDX, custom), and a
//! shared crate that pinned a single shape would need a breaking
//! release every time a new predicate landed. We keep it as
//! `serde_json::Value` and let predicate-specific crates parse it.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Canonical `_type` value for in-toto Statement v1.
///
/// All v1 Statements MUST carry exactly this string. A Statement with
/// a different value is either a different version (which we don't
/// understand) or malformed.
pub const IN_TOTO_STATEMENT_V1_TYPE: &str = "https://in-toto.io/Statement/v1";

/// Decoded in-toto Statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// Statement type URI. Always [`IN_TOTO_STATEMENT_V1_TYPE`] for
    /// v1 — `decode_json` rejects anything else.
    pub _type: String,

    /// One or more subjects the statement is making a claim about.
    /// in-toto requires at least one; we don't enforce non-emptiness
    /// at decode time (callers can decide whether an empty list is a
    /// policy violation).
    pub subject: Vec<Subject>,

    /// URI naming the predicate type, e.g.
    /// `"https://slsa.dev/provenance/v1"`. Verifiers route on this to
    /// pick a predicate parser.
    pub predicate_type: String,

    /// Predicate body — opaque JSON whose shape is determined by
    /// `predicate_type`. Held as `serde_json::Value` so this crate
    /// stays predicate-agnostic.
    pub predicate: Value,
}

/// Subject of an in-toto Statement — names a single artifact and
/// pins it by one or more digest algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// Human-readable name for the artifact (e.g. an OCI ref, a file
    /// path, a purl). Not parsed by this crate.
    pub name: String,

    /// Map of digest algorithm → hex-encoded digest. in-toto permits
    /// multiple algos per subject (e.g. `sha256` + `sha512`) so a
    /// verifier can pick whichever it trusts. `BTreeMap` for
    /// deterministic JSON ordering on encode.
    pub digest: BTreeMap<String, String>,
}

impl Statement {
    /// Decode a Statement from its canonical JSON form.
    ///
    /// Rejects payloads whose `_type` is missing or not exactly
    /// [`IN_TOTO_STATEMENT_V1_TYPE`].
    pub fn decode_json(buf: &[u8]) -> Result<Self, StatementDecodeError> {
        let wire: StatementWire = serde_json::from_slice(buf)?;
        if wire._type != IN_TOTO_STATEMENT_V1_TYPE {
            return Err(StatementDecodeError::WrongType {
                got: wire._type,
                expected: IN_TOTO_STATEMENT_V1_TYPE,
            });
        }
        let subject = wire
            .subject
            .into_iter()
            .map(|s| Subject {
                name: s.name,
                digest: s.digest,
            })
            .collect();
        Ok(Statement {
            _type: wire._type,
            subject,
            predicate_type: wire.predicate_type,
            predicate: wire.predicate,
        })
    }

    /// Encode a Statement to its canonical JSON form.
    ///
    /// The `_type` field is emitted verbatim; if a caller mutated it
    /// to something other than [`IN_TOTO_STATEMENT_V1_TYPE`], the
    /// encoded bytes will reflect that (and a v1 verifier will
    /// reject them on decode). We don't silently rewrite it — that
    /// would mask a caller bug.
    pub fn encode_json(&self) -> Result<Vec<u8>, StatementEncodeError> {
        let wire = StatementWire {
            _type: self._type.clone(),
            subject: self
                .subject
                .iter()
                .map(|s| SubjectWire {
                    name: s.name.clone(),
                    digest: s.digest.clone(),
                })
                .collect(),
            predicate_type: self.predicate_type.clone(),
            predicate: self.predicate.clone(),
        };
        let bytes = serde_json::to_vec(&wire)?;
        Ok(bytes)
    }
}

// ── JSON wire shapes (private). ─────────────────────────────────

#[derive(Deserialize, Serialize)]
struct StatementWire {
    #[serde(rename = "_type")]
    _type: String,
    subject: Vec<SubjectWire>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: Value,
}

#[derive(Deserialize, Serialize)]
struct SubjectWire {
    name: String,
    digest: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StatementDecodeError {
    #[error("statement JSON parse: {0}")]
    Json(#[from] serde_json::Error),

    #[error("statement _type mismatch: got {got:?}, expected {expected:?}")]
    WrongType { got: String, expected: &'static str },
}

#[derive(Debug, thiserror::Error)]
pub enum StatementEncodeError {
    #[error("statement JSON serialise: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Decode of a known-good single-subject Statement preserves
    /// every load-bearing field.
    ///
    /// Bug it catches: a renamer that aliased `predicateType` →
    /// `predicate_type` in the wire form (instead of the Rust form)
    /// would lose the predicate type entirely on decode, since the
    /// JSON key is camelCase per the in-toto spec.
    #[test]
    fn test_decode_well_formed_statement_extracts_fields() {
        let json = br#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                { "name": "artifact.tar.gz", "digest": { "sha256": "abc123" } }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": { "buildType": "https://example.com/build" }
        }"#;
        let stmt = Statement::decode_json(json).unwrap();
        assert_eq!(stmt._type, IN_TOTO_STATEMENT_V1_TYPE);
        assert_eq!(stmt.subject.len(), 1);
        assert_eq!(stmt.subject[0].name, "artifact.tar.gz");
        assert_eq!(
            stmt.subject[0].digest.get("sha256"),
            Some(&"abc123".to_string())
        );
        assert_eq!(stmt.predicate_type, "https://slsa.dev/provenance/v1");
        assert_eq!(
            stmt.predicate,
            json!({ "buildType": "https://example.com/build" })
        );
    }

    /// Statement missing the `_type` field is rejected at decode.
    ///
    /// Bug it catches: a parser that defaulted `_type` to the
    /// expected v1 URI on absence would happily accept malformed
    /// payloads from non-conformant signers and propagate them as
    /// "valid" Statements — masking interop bugs upstream.
    #[test]
    fn test_decode_missing_type_field_returns_error() {
        let json = br#"{
            "subject": [{ "name": "x", "digest": { "sha256": "abc" } }],
            "predicateType": "p",
            "predicate": {}
        }"#;
        let err = Statement::decode_json(json).unwrap_err();
        assert!(matches!(err, StatementDecodeError::Json(_)));
    }

    /// Statement with a `_type` other than the v1 URI is rejected.
    ///
    /// Bug it catches: silently accepting `_type =
    /// "https://in-toto.io/Statement/v0.1"` (the older draft) means
    /// callers think they have v1 semantics when they have v0.1
    /// semantics — and the predicate shape changed between the two.
    #[test]
    fn test_decode_wrong_type_uri_returns_typed_error() {
        let json = br#"{
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{ "name": "x", "digest": { "sha256": "abc" } }],
            "predicateType": "p",
            "predicate": {}
        }"#;
        let err = Statement::decode_json(json).unwrap_err();
        match err {
            StatementDecodeError::WrongType { got, expected } => {
                assert_eq!(got, "https://in-toto.io/Statement/v0.1");
                assert_eq!(expected, IN_TOTO_STATEMENT_V1_TYPE);
            }
            other => panic!("expected WrongType, got {other:?}"),
        }
    }

    /// Multi-subject Statement decodes every subject in order — order
    /// is load-bearing because some predicate types (e.g. SLSA
    /// Provenance) reference subjects by index.
    ///
    /// Bug it catches: a decoder that deduplicated subjects (e.g. via
    /// a HashSet) would silently collapse two subjects sharing a
    /// digest, breaking predicate-by-index references.
    #[test]
    fn test_decode_multi_subject_preserves_order() {
        let json = br#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                { "name": "first",  "digest": { "sha256": "a" } },
                { "name": "second", "digest": { "sha256": "b" } },
                { "name": "third",  "digest": { "sha256": "c" } }
            ],
            "predicateType": "p",
            "predicate": {}
        }"#;
        let stmt = Statement::decode_json(json).unwrap();
        assert_eq!(stmt.subject.len(), 3);
        assert_eq!(stmt.subject[0].name, "first");
        assert_eq!(stmt.subject[1].name, "second");
        assert_eq!(stmt.subject[2].name, "third");
    }

    /// Subject with multiple digest algorithms preserves all of them.
    ///
    /// Bug it catches: a decoder that took only the first algo (e.g.
    /// "always sha256") would discard sha512/sha3-256 entries that a
    /// downstream verifier might be configured to require.
    #[test]
    fn test_decode_subject_with_multiple_digest_algos_preserves_all() {
        let json = br#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": "x",
                "digest": {
                    "sha256":   "aaa",
                    "sha512":   "bbb",
                    "sha3-256": "ccc"
                }
            }],
            "predicateType": "p",
            "predicate": {}
        }"#;
        let stmt = Statement::decode_json(json).unwrap();
        let d = &stmt.subject[0].digest;
        assert_eq!(d.len(), 3);
        assert_eq!(d.get("sha256"), Some(&"aaa".to_string()));
        assert_eq!(d.get("sha512"), Some(&"bbb".to_string()));
        assert_eq!(d.get("sha3-256"), Some(&"ccc".to_string()));
    }

    /// Encode → decode round-trip preserves every field, including
    /// predicate JSON structure with nested objects.
    ///
    /// Bug it catches: a re-encoding that flattened the predicate
    /// (e.g. JSON-stringifying it into a `String` and back) would
    /// corrupt non-string predicate values like numbers or arrays.
    #[test]
    fn test_encode_then_decode_round_trips_statement() {
        let mut digest = BTreeMap::new();
        digest.insert("sha256".to_string(), "abc123".to_string());
        digest.insert("sha512".to_string(), "def456".to_string());

        let original = Statement {
            _type: IN_TOTO_STATEMENT_V1_TYPE.to_string(),
            subject: vec![Subject {
                name: "pkg:oci/example@sha256:abc".to_string(),
                digest,
            }],
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            predicate: json!({
                "buildType": "https://example.com/build",
                "buildDefinition": {
                    "buildType": "v1",
                    "externalParameters": { "ref": "main" }
                },
                "runDetails": { "builder": { "id": "https://example.com/builder" } }
            }),
        };
        let bytes = original.encode_json().unwrap();
        let decoded = Statement::decode_json(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    /// Encoded JSON uses the camelCase wire key `predicateType`, not
    /// the Rust `predicate_type`. Sigstore consumers read the wire
    /// shape and a snake_case key would silently de-serialise to a
    /// missing field on the other end.
    ///
    /// Bug it catches: forgetting `#[serde(rename = "predicateType")]`
    /// on the wire struct.
    #[test]
    fn test_encode_uses_camel_case_predicate_type_key() {
        let stmt = Statement {
            _type: IN_TOTO_STATEMENT_V1_TYPE.to_string(),
            subject: vec![],
            predicate_type: "p".to_string(),
            predicate: json!({}),
        };
        let bytes = stmt.encode_json().unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(
            s.contains("\"predicateType\""),
            "expected camelCase predicateType in encoded JSON, got: {s}"
        );
        assert!(
            !s.contains("\"predicate_type\""),
            "snake_case predicate_type leaked into wire form: {s}"
        );
    }
}
