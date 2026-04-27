//! OCI 1.1 referrer manifest construction for Sigstore bundles.
//!
//! v0 scope: build the JSON manifest bytes that wrap a
//! [`spec::Bundle`] and reference an OCI artifact via the
//! `subject` field defined by OCI Image Spec v1.1. The caller is
//! responsible for pushing both the bundle blob and this manifest
//! to a registry — v0 does NOT include an HTTP client, so the
//! returned bytes are exactly what would land at
//! `/v2/<name>/manifests/<digest>` once pushed.
//!
//! Wire-shape choices:
//!
//! * `mediaType` is `application/vnd.oci.image.manifest.v1+json` —
//!   the standard image-manifest media type. OCI 1.1 distinguishes
//!   "manifest as artifact" purely via the `artifactType` field;
//!   the manifest media type itself is unchanged.
//! * `artifactType` is the Sigstore bundle media type
//!   (`application/vnd.dev.sigstore.bundle.v0.3+json`). This is
//!   what cosign emits and what `oras discover --artifact-type`
//!   filters on.
//! * `config` is the canonical empty-config descriptor (digest of
//!   the two-byte JSON `{}`). The empty config is the modern OCI
//!   1.1 convention for "this manifest has no config blob"; older
//!   readers that require a real config blob must fetch the empty
//!   blob (which any 1.1-aware registry serves).
//! * `layers[0]` is the bundle blob — exactly one layer, mediaType
//!   matches `artifactType`. cosign uses the same shape.
//! * `subject` carries the descriptor of the artifact being signed.
//!   This is what the registry's `/referrers/<digest>` endpoint
//!   indexes on to find signatures attached to an image.
//!
//! Bundle digest = SHA-256 of the raw bundle JSON bytes (the
//! exact bytes the layer blob would carry). Manifest digest =
//! SHA-256 of the JSON manifest bytes returned from
//! [`build_referrer_manifest`].

use crate::error::OciError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Media type returned for the referrer manifest.
///
/// Same as the standard OCI image manifest. v1.1 distinguishes
/// "manifest as artifact" via `artifactType`; the manifest media
/// type itself stays put.
pub const OCI_IMAGE_MANIFEST_V1_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// `artifactType` value the referrer manifest carries — the
/// Sigstore bundle v0.3 media type. cosign uses the same string.
pub const SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE: &str =
    "application/vnd.dev.sigstore.bundle.v0.3+json";

/// Canonical empty-config media type (OCI 1.1).
pub const OCI_EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";

/// SHA-256 digest of the canonical empty config blob (`{}`, 2 bytes).
///
/// Pinned as a constant because it's a fixed value defined by OCI
/// 1.1 and recomputing it at runtime would only obscure the spec
/// reference. Verifiable via `printf '{}' | sha256sum`.
pub const OCI_EMPTY_CONFIG_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// Size in bytes of the canonical empty config blob (`{}`).
pub const OCI_EMPTY_CONFIG_SIZE: u64 = 2;

/// OCI 1.1 image manifest descriptor (config / layer / subject).
///
/// We model it explicitly rather than reuse a third-party OCI
/// types crate so the on-wire JSON is fully under our control —
/// every field name matches the OCI spec exactly and we never
/// emit an unexpected field that some pedantic registry would
/// reject.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciDescriptor {
    /// Media type of the referenced blob.
    #[serde(rename = "mediaType")]
    pub media_type: String,

    /// Digest in `<algo>:<hex>` form. v0 only emits `sha256:`.
    pub digest: String,

    /// Blob size in bytes.
    pub size: u64,
}

/// OCI 1.1 image manifest, referrer-shaped.
///
/// Field ordering in the struct matches the order the JSON output
/// will use (serde respects struct field order for non-flattened
/// structs). The order matches what cosign emits to maximise
/// byte-for-byte parity with existing Sigstore tooling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciReferrerManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: i64,

    #[serde(rename = "mediaType")]
    pub media_type: String,

    #[serde(rename = "artifactType")]
    pub artifact_type: String,

    pub config: OciDescriptor,

    pub layers: Vec<OciDescriptor>,

    /// Subject points to the artifact being signed. OCI 1.1
    /// registries index this for `/referrers/<digest>` lookups.
    pub subject: OciDescriptor,
}

/// Build an OCI 1.1 referrer manifest that wraps `bundle` and
/// references `subject_digest` as its subject.
///
/// Returns `(manifest_bytes, manifest_media_type)` — caller is
/// responsible for pushing to a registry. v0 doesn't include the
/// HTTP push (issue follow-up).
///
/// The bundle is encoded to JSON internally (using
/// [`spec::Bundle::encode_json`]) so the layer descriptor's
/// digest matches the bytes the caller will later push as the
/// blob. If the caller has already serialised the bundle they
/// can use [`build_referrer_manifest_for_bundle_bytes`] to avoid
/// re-encoding.
pub fn build_referrer_manifest(
    bundle: &spec::Bundle,
    subject_digest: &str,
    subject_media_type: &str,
    subject_size: u64,
) -> Result<(Vec<u8>, String), OciError> {
    // Validate digest format up front so a typo'd "sha256-..." or
    // bare hex string surfaces here, not deep inside a registry
    // rejection later. v0 only emits sha256, but accepts any
    // `<algo>:<hex>` shape so future SHA-512 callers don't have
    // to round-trip through the parser.
    validate_digest_format(subject_digest)?;

    let bundle_bytes = bundle
        .encode_json()
        .map_err(|e| OciError::BundleEncode(e.to_string()))?;
    let bundle_size = bundle_bytes.len() as u64;
    let bundle_digest = sha256_digest_string(&bundle_bytes);

    build_referrer_manifest_for_bundle_bytes(
        &bundle_digest,
        bundle_size,
        subject_digest,
        subject_media_type,
        subject_size,
    )
}

/// Build a referrer manifest when the caller already has the
/// bundle bytes serialised (and therefore already knows the
/// bundle digest).
///
/// Used by [`crate::sign_oci`] to avoid a second JSON encode of
/// the bundle. Public so callers that need to push the bundle
/// blob and the manifest as a coordinated pair can compute the
/// digest once.
pub fn build_referrer_manifest_for_bundle_bytes(
    bundle_digest: &str,
    bundle_size: u64,
    subject_digest: &str,
    subject_media_type: &str,
    subject_size: u64,
) -> Result<(Vec<u8>, String), OciError> {
    validate_digest_format(bundle_digest)?;
    validate_digest_format(subject_digest)?;

    let manifest = OciReferrerManifest {
        schema_version: 2,
        media_type: OCI_IMAGE_MANIFEST_V1_MEDIA_TYPE.to_string(),
        artifact_type: SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE.to_string(),
        config: OciDescriptor {
            media_type: OCI_EMPTY_CONFIG_MEDIA_TYPE.to_string(),
            digest: OCI_EMPTY_CONFIG_DIGEST.to_string(),
            size: OCI_EMPTY_CONFIG_SIZE,
        },
        layers: vec![OciDescriptor {
            media_type: SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE.to_string(),
            digest: bundle_digest.to_string(),
            size: bundle_size,
        }],
        subject: OciDescriptor {
            media_type: subject_media_type.to_string(),
            digest: subject_digest.to_string(),
            size: subject_size,
        },
    };

    let bytes = serde_json::to_vec(&manifest).map_err(OciError::Json)?;
    Ok((bytes, OCI_IMAGE_MANIFEST_V1_MEDIA_TYPE.to_string()))
}

/// Compute the `sha256:<lowerhex>` digest string of `bytes`.
///
/// Public because [`crate::sign_oci`] returns it alongside the
/// manifest bytes so callers don't need to re-hash to push.
pub fn sha256_digest_string(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(7 + digest.len() * 2);
    hex.push_str("sha256:");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
    }
    hex
}

/// Reject digests that don't match the `<algo>:<hex>` shape
/// described in the OCI spec.
///
/// Loose validation on purpose — registries accept algorithms
/// beyond `sha256:` (e.g. `sha512:`), so we don't whitelist. We
/// only ensure the colon-separated shape and that the hex part
/// is an even-length string of `[0-9a-f]`.
fn validate_digest_format(digest: &str) -> Result<(), OciError> {
    let (algo, hex) = digest
        .split_once(':')
        .ok_or_else(|| OciError::BadDigestFormat {
            value: digest.to_string(),
        })?;
    if algo.is_empty() || hex.is_empty() || hex.len() % 2 != 0 {
        return Err(OciError::BadDigestFormat {
            value: digest.to_string(),
        });
    }
    if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(OciError::BadDigestFormat {
            value: digest.to_string(),
        });
    }
    Ok(())
}

/// Parsed view of an OCI 1.1 referrer manifest, returned by
/// [`parse_referrer_manifest`] for verifiers.
///
/// We intentionally surface only the fields a verifier needs to
/// route on; the full struct is available via direct serde decode
/// if a caller wants the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedReferrerManifest {
    pub artifact_type: String,
    pub schema_version: i64,
    pub layer: OciDescriptor,
    pub subject: OciDescriptor,
}

/// Parse a referrer manifest and validate the OCI 1.1 shape used
/// by cosign:
///
/// * `schemaVersion` MUST be 2.
/// * `artifactType` MUST be the Sigstore bundle v0.3 media type.
/// * `subject` MUST be present (this is what makes the manifest
///   a referrer at all).
/// * `layers` MUST contain exactly one entry — the bundle blob.
///
/// Returns the fields a verifier needs without exposing the
/// internal `OciReferrerManifest` shape.
pub fn parse_referrer_manifest(manifest_bytes: &[u8]) -> Result<ParsedReferrerManifest, OciError> {
    let manifest: OciReferrerManifest =
        serde_json::from_slice(manifest_bytes).map_err(OciError::Json)?;

    if manifest.schema_version != 2 {
        return Err(OciError::WrongSchemaVersion {
            found: manifest.schema_version,
        });
    }

    if manifest.artifact_type != SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE {
        return Err(OciError::WrongArtifactType {
            found: manifest.artifact_type,
            expected: SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE.to_string(),
        });
    }

    if manifest.layers.len() != 1 {
        return Err(OciError::WrongLayerCount {
            found: manifest.layers.len(),
        });
    }

    let layer = manifest
        .layers
        .into_iter()
        .next()
        .expect("len checked above");

    Ok(ParsedReferrerManifest {
        artifact_type: manifest.artifact_type,
        schema_version: manifest.schema_version,
        layer,
        subject: manifest.subject,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use spec::{
        Bundle, BundleContent, Envelope, Signature as DsseSignature, VerificationMaterial,
        SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE,
    };

    /// Hand-built minimal bundle; used as the layer blob in the
    /// shape tests so we don't pay for ECDSA in tests that only
    /// exercise the OCI manifest construction.
    fn fixture_bundle() -> Bundle {
        Bundle {
            media_type: SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE.to_string(),
            verification_material: VerificationMaterial {
                certificate: None,
                tlog_entries: vec![],
                timestamp_verification_data: None,
            },
            content: BundleContent::DsseEnvelope(Envelope {
                payload_type: "text/plain".to_string(),
                payload: b"oci-test".to_vec(),
                signatures: vec![DsseSignature {
                    keyid: Some("k1".to_string()),
                    sig: vec![0xCD; 70],
                }],
            }),
        }
    }

    /// A valid OCI 1.1 referrer manifest carries every
    /// non-optional field cosign emits, parses as JSON, and the
    /// constants land in the correct fields.
    ///
    /// Bug it catches: any drift in field naming (e.g.
    /// `artifact_type` vs `artifactType` from a missing serde
    /// rename) would surface here as the JSON failing to parse
    /// back into our struct, OR the fields landing in the wrong
    /// JSON keys for an OCI registry.
    #[test]
    fn test_build_referrer_manifest_has_correct_oci_1_1_shape() {
        let bundle = fixture_bundle();
        let subject_digest =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let subject_media_type = "application/vnd.oci.image.manifest.v1+json";
        let subject_size = 1234u64;

        let (bytes, mt) =
            build_referrer_manifest(&bundle, subject_digest, subject_media_type, subject_size)
                .unwrap();

        assert_eq!(mt, OCI_IMAGE_MANIFEST_V1_MEDIA_TYPE);

        // Parse as raw JSON to assert exact field names — bypasses
        // our own struct so a serde rename typo can't hide a bug.
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schemaVersion"], 2);
        assert_eq!(value["mediaType"], OCI_IMAGE_MANIFEST_V1_MEDIA_TYPE);
        assert_eq!(value["artifactType"], SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE);

        assert_eq!(value["config"]["mediaType"], OCI_EMPTY_CONFIG_MEDIA_TYPE);
        assert_eq!(value["config"]["digest"], OCI_EMPTY_CONFIG_DIGEST);
        assert_eq!(value["config"]["size"], OCI_EMPTY_CONFIG_SIZE);

        let layers = value["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0]["mediaType"], SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE);
        assert!(layers[0]["digest"].as_str().unwrap().starts_with("sha256:"));
        assert!(layers[0]["size"].as_u64().unwrap() > 0);

        assert_eq!(value["subject"]["mediaType"], subject_media_type);
        assert_eq!(value["subject"]["digest"], subject_digest);
        assert_eq!(value["subject"]["size"], subject_size);
    }

    /// The `subject` digest passed in MUST be the digest that ends
    /// up in the manifest — verifiers read `subject.digest` to
    /// know what artifact this signature is attached to, so any
    /// silent rewrite would point the signature at a different
    /// artifact.
    #[test]
    fn test_build_referrer_manifest_subject_digest_round_trips() {
        let bundle = fixture_bundle();
        let subject_digest =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let (bytes, _) = build_referrer_manifest(
            &bundle,
            subject_digest,
            "application/vnd.oci.image.manifest.v1+json",
            42,
        )
        .unwrap();

        let parsed = parse_referrer_manifest(&bytes).unwrap();
        assert_eq!(parsed.subject.digest, subject_digest);
    }

    /// Layer digest MUST equal SHA-256 of the bundle bytes — that
    /// invariant is what lets a verifier fetch the layer blob and
    /// be sure they have the bundle the manifest references.
    #[test]
    fn test_build_referrer_manifest_layer_digest_matches_bundle_bytes() {
        let bundle = fixture_bundle();
        let bundle_bytes = bundle.encode_json().unwrap();
        let expected = sha256_digest_string(&bundle_bytes);

        let (manifest_bytes, _) = build_referrer_manifest(
            &bundle,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "application/vnd.oci.image.manifest.v1+json",
            10,
        )
        .unwrap();

        let parsed = parse_referrer_manifest(&manifest_bytes).unwrap();
        assert_eq!(parsed.layer.digest, expected);
        assert_eq!(parsed.layer.size, bundle_bytes.len() as u64);
    }

    /// A digest that's missing the `<algo>:` prefix is rejected
    /// up front — cheaper than discovering it at registry-push
    /// time, and prevents a silently-malformed manifest from
    /// reaching the wire.
    #[test]
    fn test_build_referrer_manifest_rejects_bad_subject_digest() {
        let bundle = fixture_bundle();
        let bad_digest = "deadbeef"; // missing "sha256:" prefix
        let err = build_referrer_manifest(
            &bundle,
            bad_digest,
            "application/vnd.oci.image.manifest.v1+json",
            10,
        )
        .unwrap_err();
        match err {
            OciError::BadDigestFormat { value } => assert_eq!(value, bad_digest),
            other => panic!("expected BadDigestFormat, got {other:?}"),
        }
    }

    /// Non-hex characters in the digest hex part are rejected.
    #[test]
    fn test_build_referrer_manifest_rejects_non_hex_digest() {
        let bundle = fixture_bundle();
        let bad_digest = "sha256:zz11"; // 'z' isn't hex
        let err = build_referrer_manifest(
            &bundle,
            bad_digest,
            "application/vnd.oci.image.manifest.v1+json",
            10,
        )
        .unwrap_err();
        assert!(matches!(err, OciError::BadDigestFormat { .. }));
    }

    /// Parser rejects a manifest with the wrong artifactType.
    #[test]
    fn test_parse_referrer_manifest_rejects_wrong_artifact_type() {
        let manifest = OciReferrerManifest {
            schema_version: 2,
            media_type: OCI_IMAGE_MANIFEST_V1_MEDIA_TYPE.to_string(),
            artifact_type: "application/vnd.example.other+json".to_string(),
            config: OciDescriptor {
                media_type: OCI_EMPTY_CONFIG_MEDIA_TYPE.to_string(),
                digest: OCI_EMPTY_CONFIG_DIGEST.to_string(),
                size: OCI_EMPTY_CONFIG_SIZE,
            },
            layers: vec![OciDescriptor {
                media_type: SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE.to_string(),
                digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                size: 100,
            }],
            subject: OciDescriptor {
                media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                size: 200,
            },
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let err = parse_referrer_manifest(&bytes).unwrap_err();
        match err {
            OciError::WrongArtifactType { found, expected } => {
                assert_eq!(found, "application/vnd.example.other+json");
                assert_eq!(expected, SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE);
            }
            other => panic!("expected WrongArtifactType, got {other:?}"),
        }
    }

    /// Parser rejects schemaVersion != 2.
    #[test]
    fn test_parse_referrer_manifest_rejects_wrong_schema_version() {
        let mut manifest = OciReferrerManifest {
            schema_version: 1,
            media_type: OCI_IMAGE_MANIFEST_V1_MEDIA_TYPE.to_string(),
            artifact_type: SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE.to_string(),
            config: OciDescriptor {
                media_type: OCI_EMPTY_CONFIG_MEDIA_TYPE.to_string(),
                digest: OCI_EMPTY_CONFIG_DIGEST.to_string(),
                size: OCI_EMPTY_CONFIG_SIZE,
            },
            layers: vec![OciDescriptor {
                media_type: SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE.to_string(),
                digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                size: 100,
            }],
            subject: OciDescriptor {
                media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                size: 200,
            },
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let err = parse_referrer_manifest(&bytes).unwrap_err();
        assert!(matches!(err, OciError::WrongSchemaVersion { found: 1 }));

        // Sanity: the same manifest with schemaVersion == 2 parses.
        manifest.schema_version = 2;
        let bytes = serde_json::to_vec(&manifest).unwrap();
        parse_referrer_manifest(&bytes).unwrap();
    }

    /// Parser rejects manifests with zero or multiple layers.
    /// cosign only ever emits a single layer (the bundle blob).
    #[test]
    fn test_parse_referrer_manifest_rejects_wrong_layer_count() {
        let manifest_zero_layers = OciReferrerManifest {
            schema_version: 2,
            media_type: OCI_IMAGE_MANIFEST_V1_MEDIA_TYPE.to_string(),
            artifact_type: SIGSTORE_BUNDLE_V0_3_ARTIFACT_TYPE.to_string(),
            config: OciDescriptor {
                media_type: OCI_EMPTY_CONFIG_MEDIA_TYPE.to_string(),
                digest: OCI_EMPTY_CONFIG_DIGEST.to_string(),
                size: OCI_EMPTY_CONFIG_SIZE,
            },
            layers: vec![],
            subject: OciDescriptor {
                media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                size: 200,
            },
        };
        let bytes = serde_json::to_vec(&manifest_zero_layers).unwrap();
        let err = parse_referrer_manifest(&bytes).unwrap_err();
        assert!(matches!(err, OciError::WrongLayerCount { found: 0 }));
    }

    /// `sha256_digest_string` produces lowercase hex with the
    /// `sha256:` prefix — both required by the OCI digest grammar.
    /// Vector pinned from `printf '' | sha256sum`.
    #[test]
    fn test_sha256_digest_string_matches_known_vector() {
        let empty = sha256_digest_string(b"");
        assert_eq!(
            empty,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let abc = sha256_digest_string(b"abc");
        assert_eq!(
            abc,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Empty-config digest constant matches `printf '{}' | sha256sum`.
    /// Pinned because OCI 1.1 refers to this exact digest as the
    /// canonical empty-config descriptor — drift here would make
    /// our manifests reject-able by strict 1.1 registries.
    #[test]
    fn test_oci_empty_config_digest_matches_canonical_value() {
        let computed = sha256_digest_string(b"{}");
        assert_eq!(computed, OCI_EMPTY_CONFIG_DIGEST);
    }
}
