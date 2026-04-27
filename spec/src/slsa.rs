//! SLSA Provenance v1 predicate.
//!
//! Reference: <https://slsa.dev/spec/v1.0/provenance>
//!
//! This module is a **typed shape** for the JSON value that goes into
//! an in-toto Statement's `predicate` field when `predicateType ==
//! "https://slsa.dev/provenance/v1"`. The spec crate stays predicate-
//! agnostic for `Statement::predicate` (it's just `serde_json::Value`)
//! — this module is the per-predicate-type adapter for SLSA v1.
//!
//! The on-the-wire JSON shape, as the SLSA v1 spec defines it:
//!
//! ```json
//! {
//!   "buildDefinition": {
//!     "buildType": "<URI>",
//!     "externalParameters": <object>,
//!     "internalParameters": <object>,
//!     "resolvedDependencies": [ResourceDescriptor]
//!   },
//!   "runDetails": {
//!     "builder": {
//!       "id": "<URI>",
//!       "version": <map<string,string>>,
//!       "builderDependencies": [ResourceDescriptor]
//!     },
//!     "metadata": {
//!       "invocationId": "<string>",
//!       "startedOn": "<RFC3339 timestamp>",
//!       "finishedOn": "<RFC3339 timestamp>"
//!     },
//!     "byproducts": [ResourceDescriptor]
//!   }
//! }
//! ```
//!
//! Optional fields are skipped on serialise when `None` so a hand-
//! crafted minimal predicate matches the SLSA reference fixtures
//! byte-for-byte (no spurious `"metadata": null` keys).
//!
//! Timestamps (`startedOn`, `finishedOn`) are held as RFC 3339
//! `String`s. Parsing them into a typed time value would pull in the
//! `time` crate; the spec crate is deliberately a primitive (serde +
//! `BTreeMap` only) and a higher-level builder-side crate can layer
//! parsing on top without breaking this struct's wire shape.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Canonical `predicateType` URI for SLSA Provenance v1.
///
/// All SLSA-v1 attestations MUST carry exactly this string in the
/// in-toto Statement's `predicateType` field. Verifiers route on it
/// to pick a predicate parser; a Statement carrying any other URI is
/// either a different predicate type entirely (e.g. SPDX, custom) or
/// a different SLSA version (v0.2, v2.x) whose predicate shape is
/// NOT compatible with this struct.
pub const SLSA_PROVENANCE_V1_PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";

/// Top-level SLSA Provenance v1 predicate body.
///
/// This is the value placed into an in-toto Statement's `predicate`
/// field. The `_type` and `subject[…]` of the wrapping Statement are
/// the in-toto crate's responsibility — this struct does NOT
/// duplicate them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaProvenanceV1 {
    /// The "what was built and how" half of the predicate. Consumers
    /// re-derive policy decisions from `build_type` +
    /// `external_parameters`.
    pub build_definition: BuildDefinition,

    /// The "who built it and when" half of the predicate. Consumers
    /// re-derive identity / audit decisions from `builder.id` +
    /// `metadata`.
    pub run_details: RunDetails,
}

/// `buildDefinition` — declaratively names the build being attested.
///
/// `build_type` is the routing field: it pins what `external_parameters`
/// looks like for this build system. Two different builders MAY share
/// a `build_type` URI iff they accept the same parameters; otherwise
/// they MUST mint distinct URIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildDefinition {
    /// URI naming the build process. Verifiers route on this to pick
    /// a parameter schema. Held as `String`, not URL-typed: the SLSA
    /// spec doesn't require RFC 3986 conformance and we don't want
    /// to reject practical URIs that pass a stricter parser.
    pub build_type: String,

    /// Parameters supplied by the user / caller of the build. Shape
    /// varies by `build_type`. Held as `serde_json::Value` because
    /// the spec crate stays predicate-agnostic in the same way it
    /// holds in-toto's `Statement::predicate` opaque.
    pub external_parameters: Value,

    /// Parameters the build system itself supplied (e.g. a CI's
    /// runner pool, the worker node's OS image). Optional per the
    /// spec; absent fields are omitted from the serialised JSON
    /// (no `"internalParameters": null` shape).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_parameters: Option<Value>,

    /// Resolved dependencies the build consumed (source repos, base
    /// images, package downloads). Empty by default — `serde(default)`
    /// keeps a missing field on decode equal to an empty list, which
    /// matches the SLSA spec's intent ("no dependencies declared").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_dependencies: Vec<ResourceDescriptor>,
}

/// `runDetails` — describes the actual build execution.
///
/// Symmetric to [`BuildDefinition`]: `builder` answers "who", optional
/// `metadata` answers "when / where in the run", `byproducts` carries
/// any extra outputs the verifier might cross-reference (logs, SBOMs,
/// VEX documents).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunDetails {
    /// Identity of the build system that performed the build. Always
    /// required by the spec — a provenance with no builder is not a
    /// provenance.
    pub builder: Builder,

    /// Optional run-level metadata (invocation id, timestamps).
    /// Skipped on serialise when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BuildMetadata>,

    /// Auxiliary outputs produced by the build (build logs, SBOMs).
    /// Empty by default; missing on the wire decodes to empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub byproducts: Vec<ResourceDescriptor>,
}

/// `builder` — names the build system + (optionally) its version
/// and any tooling dependencies.
///
/// `id` is a URI; it's the routing field a verifier uses to decide
/// "do I trust this builder for this artifact?". `version` is a map
/// rather than a single string so a builder with multiple component
/// versions (e.g. workflow runner + cache backend) can pin all of
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Builder {
    /// URI naming the builder identity. The SLSA threat model
    /// assumes verifiers maintain a list of trusted builder URIs.
    pub id: String,

    /// Map of component → version string. `BTreeMap` for stable
    /// (lexicographic) JSON ordering on encode — re-encoding a
    /// decoded predicate produces byte-identical output, which
    /// matters for any caller that hashes the predicate body.
    /// `serde(default)` so a missing wire field decodes to empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub version: BTreeMap<String, String>,

    /// Tooling the builder itself depends on (compilers, system
    /// libraries pulled into the build sandbox). Optional per the
    /// spec; empty by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub builder_dependencies: Vec<ResourceDescriptor>,
}

/// `metadata` — optional run-level facts (invocation id, when the
/// run started / finished).
///
/// Every field is optional in the SLSA spec, so every field here is
/// `Option<…>`. A `BuildMetadata` whose every field is `None` should
/// not appear in the encoded JSON at all — its parent `RunDetails`
/// flips to `metadata: None` instead. This struct still skips its
/// own `None` fields on serialise so a partially-populated metadata
/// (e.g. just an invocation id) round-trips cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildMetadata {
    /// Globally-unique identifier for this build invocation. The
    /// SLSA spec doesn't constrain the format; a builder MAY use a
    /// UUID, a CI run URL, or a content-addressed hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,

    /// RFC 3339 timestamp when the build started. Held as `String`
    /// to keep the spec crate free of a `time` dependency; callers
    /// who need a typed timestamp parse it with their own crate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_on: Option<String>,

    /// RFC 3339 timestamp when the build finished. Same string-vs-
    /// typed rationale as `started_on`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_on: Option<String>,
}

/// in-toto / SLSA `ResourceDescriptor`.
///
/// Reference: <https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md>
///
/// A descriptor pins ONE resource by some combination of name, URI,
/// digest, and / or inline content. The SLSA spec requires "at
/// least one of name, uri, digest, content" be set, but does NOT
/// require that the parser enforce it — and a verifier that gates
/// on the descriptor SHOULD do its own structural check anyway. We
/// hold every field as optional and let policy decide what's
/// required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDescriptor {
    /// Human-readable name. Distinct from `uri` because a descriptor
    /// can name an artifact (e.g. `"source"`) without pinning a URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Locator URI (e.g. `git+https://github.com/...@<sha>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// Map of digest algorithm → hex digest. `BTreeMap` for stable
    /// lexicographic ordering on encode — same rationale as
    /// `Subject::digest` in the in-toto module.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub digest: BTreeMap<String, String>,

    /// Inline base64-encoded resource bytes. Verifiers SHOULD prefer
    /// `digest`; `content` is for resources too small to warrant a
    /// separate URI (e.g. a one-line config snippet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// Hint URI for downloading the resource if `uri` isn't directly
    /// fetchable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_location: Option<String>,

    /// IANA media type of the resource bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Free-form annotations. Held as `serde_json::Value` so this
    /// crate stays predicate-agnostic about the annotation schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
}

impl SlsaProvenanceV1 {
    /// Encode the predicate body to a `serde_json::Value`.
    ///
    /// Returning `Value` (not `Vec<u8>`) is deliberate: the in-toto
    /// `Statement::predicate` field IS a `Value`, so callers building
    /// a Statement can hand the result straight in without an extra
    /// `serde_json::from_slice` round trip.
    ///
    /// In practice this can only fail on a `Value` whose internal
    /// invariants were broken (e.g. via unsafe construction); the
    /// spec crate forbids `unsafe_code` so for callers using only
    /// safe APIs this returns `Ok` unconditionally. The `Result`
    /// surface is kept so a caller threading errors uniformly
    /// doesn't have to special-case this site.
    pub fn encode_json(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The predicate-type constant matches the URI string the SLSA
    /// v1 spec pins exactly.
    ///
    /// Bug it catches: a stray trailing slash, version drift to
    /// `provenance/v1.0`, or a typo (`provanance`) would silently
    /// route the predicate to the wrong parser at the verifier and
    /// the bug would only surface as a "WrongPredicateType" failure
    /// at integration time. Pinning the literal here surfaces it at
    /// commit time.
    #[test]
    fn test_predicate_type_constant_matches_slsa_v1_uri_exactly() {
        assert_eq!(
            SLSA_PROVENANCE_V1_PREDICATE_TYPE,
            "https://slsa.dev/provenance/v1"
        );
    }

    /// A fully-populated predicate round-trips: encode_json → from_value
    /// produces a struct equal to the original, including every
    /// nested ResourceDescriptor / Builder / BuildMetadata field.
    ///
    /// Bug it catches: a missing `#[serde(rename_all = "camelCase")]`
    /// on any of the inner structs would cause `from_value` to leave
    /// most fields default (snake_case wire keys would be unknown to
    /// the deserialiser) — the equality assert would fail because
    /// nearly every field would differ.
    #[test]
    fn test_encode_then_decode_round_trips_full_predicate() {
        let original = SlsaProvenanceV1 {
            build_definition: BuildDefinition {
                build_type: "https://example.com/build/v1".to_string(),
                external_parameters: json!({ "ref": "refs/heads/main", "workflow": "ci.yml" }),
                internal_parameters: Some(json!({ "runner": "ubuntu-22.04" })),
                resolved_dependencies: vec![ResourceDescriptor {
                    name: Some("source".to_string()),
                    uri: Some("git+https://github.com/example/repo@deadbeef".to_string()),
                    digest: {
                        let mut d = BTreeMap::new();
                        d.insert("sha1".to_string(), "deadbeef".to_string());
                        d
                    },
                    content: None,
                    download_location: None,
                    media_type: None,
                    annotations: None,
                }],
            },
            run_details: RunDetails {
                builder: Builder {
                    id: "https://github.com/actions/runner".to_string(),
                    version: {
                        let mut v = BTreeMap::new();
                        v.insert("github_actions_runner".to_string(), "2.317.0".to_string());
                        v.insert("os".to_string(), "linux".to_string());
                        v
                    },
                    builder_dependencies: vec![],
                },
                metadata: Some(BuildMetadata {
                    invocation_id: Some("abc-123".to_string()),
                    started_on: Some("2024-01-01T00:00:00Z".to_string()),
                    finished_on: Some("2024-01-01T00:05:00Z".to_string()),
                }),
                byproducts: vec![ResourceDescriptor {
                    name: Some("build-log".to_string()),
                    uri: None,
                    digest: BTreeMap::new(),
                    content: None,
                    download_location: Some("https://example.com/log.txt".to_string()),
                    media_type: Some("text/plain".to_string()),
                    annotations: Some(json!({ "level": "info" })),
                }],
            },
        };

        let value = original.encode_json().unwrap();
        let decoded: SlsaProvenanceV1 = serde_json::from_value(value).unwrap();
        assert_eq!(original, decoded);
    }

    /// Encoded JSON uses camelCase wire keys (`buildDefinition`,
    /// `runDetails`, `buildType`, `externalParameters`, …) — NOT
    /// snake_case.
    ///
    /// Bug it catches: forgetting `#[serde(rename_all = "camelCase")]`
    /// on `SlsaProvenanceV1` (or any inner struct) would emit
    /// snake_case keys, and the resulting JSON would not match the
    /// SLSA spec's wire shape — Sigstore consumers would see "field
    /// missing" on every renamed key.
    #[test]
    fn test_encode_uses_camel_case_wire_keys_at_every_level() {
        let predicate = SlsaProvenanceV1 {
            build_definition: BuildDefinition {
                build_type: "t".to_string(),
                external_parameters: json!({}),
                internal_parameters: Some(json!({})),
                resolved_dependencies: vec![],
            },
            run_details: RunDetails {
                builder: Builder {
                    id: "i".to_string(),
                    version: BTreeMap::new(),
                    builder_dependencies: vec![],
                },
                metadata: Some(BuildMetadata {
                    invocation_id: Some("i".to_string()),
                    started_on: Some("s".to_string()),
                    finished_on: Some("f".to_string()),
                }),
                byproducts: vec![],
            },
        };
        let value = predicate.encode_json().unwrap();
        let s = serde_json::to_string(&value).unwrap();

        // camelCase keys present.
        for key in [
            "\"buildDefinition\"",
            "\"runDetails\"",
            "\"buildType\"",
            "\"externalParameters\"",
            "\"internalParameters\"",
            "\"invocationId\"",
            "\"startedOn\"",
            "\"finishedOn\"",
        ] {
            assert!(
                s.contains(key),
                "expected camelCase wire key {key} in encoded JSON, got: {s}"
            );
        }
        // snake_case keys MUST NOT leak.
        for key in [
            "\"build_definition\"",
            "\"run_details\"",
            "\"build_type\"",
            "\"external_parameters\"",
            "\"internal_parameters\"",
            "\"invocation_id\"",
            "\"started_on\"",
            "\"finished_on\"",
        ] {
            assert!(
                !s.contains(key),
                "snake_case wire key {key} leaked into encoded JSON: {s}"
            );
        }
    }

    /// A minimal predicate (only the spec-required fields) encodes
    /// to JSON that does NOT contain spurious `null` or empty-array
    /// keys for the optional fields.
    ///
    /// Bug it catches: forgetting `skip_serializing_if = ...` on
    /// optional fields would emit `"internalParameters": null` and
    /// `"resolvedDependencies": []` even when absent — bloating the
    /// payload, breaking byte-equality tests on hand-crafted SLSA
    /// fixtures, and (in some Sigstore consumers) failing schema
    /// validation that rejects unexpected null fields.
    #[test]
    fn test_encode_minimal_predicate_omits_optional_fields() {
        let predicate = SlsaProvenanceV1 {
            build_definition: BuildDefinition {
                build_type: "t".to_string(),
                external_parameters: json!({}),
                internal_parameters: None,
                resolved_dependencies: vec![],
            },
            run_details: RunDetails {
                builder: Builder {
                    id: "i".to_string(),
                    version: BTreeMap::new(),
                    builder_dependencies: vec![],
                },
                metadata: None,
                byproducts: vec![],
            },
        };
        let s = serde_json::to_string(&predicate.encode_json().unwrap()).unwrap();

        for forbidden in [
            "internalParameters",
            "resolvedDependencies",
            "metadata",
            "byproducts",
            "builderDependencies",
            "version",
            "null",
        ] {
            assert!(
                !s.contains(forbidden),
                "minimal predicate must NOT contain {forbidden:?}, got: {s}"
            );
        }

        // Required fields ARE present.
        for required in ["buildDefinition", "runDetails", "buildType", "builder"] {
            assert!(
                s.contains(required),
                "minimal predicate MUST contain {required:?}, got: {s}"
            );
        }
    }

    /// The `digest` field in a `Builder` and a `ResourceDescriptor`
    /// is a `BTreeMap`, so the serialised JSON pins the key order
    /// in lexicographic sequence. Two identical predicates encode
    /// to byte-identical output regardless of insertion order.
    ///
    /// Bug it catches: switching to a `HashMap` (or any non-
    /// deterministic order) would mean re-encoding a decoded
    /// predicate produces different bytes from the original — and
    /// any consumer that hashes the predicate body (Rekor's
    /// canonical-JSON contract, an SBOM digest, a transparency-log
    /// inclusion proof) would compute a different hash on the
    /// round trip than on the original encode.
    #[test]
    fn test_btreemap_digest_serialises_in_stable_lexicographic_order() {
        let mut digest_a = BTreeMap::new();
        digest_a.insert("sha512".to_string(), "z".to_string());
        digest_a.insert("sha256".to_string(), "a".to_string());
        digest_a.insert("sha1".to_string(), "m".to_string());

        let mut digest_b = BTreeMap::new();
        // Insert in reverse order — should still serialise the same.
        digest_b.insert("sha1".to_string(), "m".to_string());
        digest_b.insert("sha256".to_string(), "a".to_string());
        digest_b.insert("sha512".to_string(), "z".to_string());

        let mk = |digest: BTreeMap<String, String>| -> String {
            let rd = ResourceDescriptor {
                name: None,
                uri: None,
                digest,
                content: None,
                download_location: None,
                media_type: None,
                annotations: None,
            };
            serde_json::to_string(&rd).unwrap()
        };

        let s_a = mk(digest_a);
        let s_b = mk(digest_b);
        assert_eq!(s_a, s_b);

        // And the order is sha1 → sha256 → sha512 (lex sort, which
        // happens to be the desired-by-humans order for SHA family
        // members in this triplet).
        let pos_sha1 = s_a.find("sha1").unwrap();
        let pos_sha256 = s_a.find("sha256").unwrap();
        let pos_sha512 = s_a.find("sha512").unwrap();
        assert!(pos_sha1 < pos_sha256);
        assert!(pos_sha256 < pos_sha512);
    }

    /// A `ResourceDescriptor` populated with EVERY field round-trips
    /// (encode → decode preserves all of them).
    ///
    /// Bug it catches: a typo on any one field's serde rename (e.g.
    /// `media_type` vs `mediaType`) would silently drop that field
    /// on decode and the test would catch the missing field on the
    /// equality assert.
    #[test]
    fn test_resource_descriptor_with_all_fields_round_trips() {
        let mut digest = BTreeMap::new();
        digest.insert("sha256".to_string(), "abc".to_string());
        digest.insert("sha512".to_string(), "def".to_string());

        let original = ResourceDescriptor {
            name: Some("dep".to_string()),
            uri: Some("https://example.com/dep.tar.gz".to_string()),
            digest,
            content: Some("aGVsbG8=".to_string()),
            download_location: Some("https://mirror.example.com/dep.tar.gz".to_string()),
            media_type: Some("application/gzip".to_string()),
            annotations: Some(json!({ "license": "Apache-2.0" })),
        };

        let value = serde_json::to_value(&original).unwrap();
        let decoded: ResourceDescriptor = serde_json::from_value(value).unwrap();
        assert_eq!(original, decoded);
    }

    /// A `ResourceDescriptor` with NO fields set (every `Option` =
    /// `None`, every `BTreeMap`/`Vec` empty) encodes to `{}` and
    /// decodes back to the same all-empty struct.
    ///
    /// Bug it catches: a missing `serde(default)` on `digest` (the
    /// `BTreeMap` field) would make `from_value` REJECT a wire
    /// shape with no `digest` key — even though the SLSA spec
    /// makes `digest` optional. A descriptor naming a resource by
    /// `uri` alone (no digest yet, e.g. for an unverified source)
    /// would fail to deserialise.
    #[test]
    fn test_resource_descriptor_with_no_fields_round_trips_to_empty_object() {
        let original = ResourceDescriptor {
            name: None,
            uri: None,
            digest: BTreeMap::new(),
            content: None,
            download_location: None,
            media_type: None,
            annotations: None,
        };
        let s = serde_json::to_string(&original).unwrap();
        assert_eq!(s, "{}");

        let decoded: ResourceDescriptor = serde_json::from_str("{}").unwrap();
        assert_eq!(original, decoded);
    }

    /// A hand-crafted minimal SLSA-v1-shaped JSON value (exactly
    /// the shape a real SLSA-conformant builder might emit)
    /// deserialises into our struct without loss.
    ///
    /// Bug it catches: any drift between OUR struct's wire shape
    /// and the SLSA spec's wire shape would surface as a
    /// "missing field" deserialisation error on the very first
    /// real SLSA fixture we hit — at integration time, not at
    /// unit-test time. Pinning the fixture inline catches it
    /// earlier.
    #[test]
    fn test_deserialise_minimal_real_slsa_v1_fixture() {
        let fixture = r#"{
            "buildDefinition": {
                "buildType": "https://github.com/actions/workflow@v1",
                "externalParameters": {
                    "workflow": {
                        "ref": "refs/heads/main",
                        "repository": "https://github.com/example/repo",
                        "path": ".github/workflows/release.yml"
                    }
                },
                "internalParameters": {
                    "github": { "runner_environment": "github-hosted" }
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/example/repo@refs/heads/main",
                        "digest": { "gitCommit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" }
                    }
                ]
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/actions/runner/github-hosted"
                },
                "metadata": {
                    "invocationId": "https://github.com/example/repo/actions/runs/12345/attempts/1",
                    "startedOn": "2024-01-01T00:00:00Z",
                    "finishedOn": "2024-01-01T00:10:00Z"
                }
            }
        }"#;

        let predicate: SlsaProvenanceV1 = serde_json::from_str(fixture).unwrap();
        assert_eq!(
            predicate.build_definition.build_type,
            "https://github.com/actions/workflow@v1"
        );
        assert_eq!(
            predicate.run_details.builder.id,
            "https://github.com/actions/runner/github-hosted"
        );
        assert_eq!(predicate.build_definition.resolved_dependencies.len(), 1);
        let dep = &predicate.build_definition.resolved_dependencies[0];
        assert_eq!(
            dep.uri.as_deref(),
            Some("git+https://github.com/example/repo@refs/heads/main")
        );
        assert_eq!(
            dep.digest.get("gitCommit"),
            Some(&"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string())
        );
        let metadata = predicate.run_details.metadata.as_ref().unwrap();
        assert_eq!(metadata.started_on.as_deref(), Some("2024-01-01T00:00:00Z"));
        assert_eq!(
            metadata.finished_on.as_deref(),
            Some("2024-01-01T00:10:00Z")
        );
        // Optional fields not present in the fixture decode to
        // their empty defaults — no spurious errors.
        assert!(predicate.run_details.byproducts.is_empty());
        assert!(predicate.run_details.builder.version.is_empty());
    }

    /// `BuildMetadata` with only `invocation_id` populated
    /// (timestamps absent) round-trips and the absent fields stay
    /// absent from the wire.
    ///
    /// Bug it catches: applying `serde(default)` without
    /// `skip_serializing_if = "Option::is_none"` on the timestamp
    /// fields would mean they decode-default to `None` correctly
    /// but encode as `"startedOn": null` — a builder that wants to
    /// emit a partial metadata block would produce non-spec JSON.
    #[test]
    fn test_build_metadata_partial_population_round_trips_cleanly() {
        let original = BuildMetadata {
            invocation_id: Some("inv-1".to_string()),
            started_on: None,
            finished_on: None,
        };
        let s = serde_json::to_string(&original).unwrap();
        assert!(s.contains("\"invocationId\":\"inv-1\""));
        assert!(!s.contains("startedOn"));
        assert!(!s.contains("finishedOn"));
        assert!(!s.contains("null"));

        let decoded: BuildMetadata = serde_json::from_str(&s).unwrap();
        assert_eq!(original, decoded);
    }
}
