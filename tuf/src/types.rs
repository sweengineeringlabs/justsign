//! TUF role wire types: `Signed<T>` envelope + the four standard
//! roles' inner shapes (`Root`, `Timestamp`, `Snapshot`, `Targets`).
//!
//! `Root` itself lives in [`crate::root`] for backward-compat with v0
//! consumers that already import `tuf::Root`. Everything else is
//! introduced here.
//!
//! # Wire shape
//!
//! Every TUF metadata file on the wire is the same envelope:
//!
//! ```json
//! {
//!   "signed":     { ... role-specific body ... },
//!   "signatures": [ { "keyid": "...", "sig": "..." }, ... ]
//! }
//! ```
//!
//! The signatures cover the OLPC canonical-JSON encoding of the
//! `signed` field, NOT the wrapping envelope. This module models the
//! envelope as a generic [`Signed<T>`] so the same parsing path
//! handles every role.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::root::Signature;

/// TUF metadata envelope — `{ "signed": T, "signatures": [...] }`.
///
/// Generic over the role body so the same parsing path serves
/// `Root`, `Timestamp`, `Snapshot`, `Targets`. We keep `signed` as
/// a [`serde_json::Value`] in addition to the typed body so the
/// caller can re-canonicalise the original `signed` subtree without
/// going through a typed round-trip (which would re-emit fields in
/// a different order than the wire bytes — not what we want when
/// the wire form is the signature input).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Signed<T> {
    /// The role body, parsed into the typed `T` for ergonomic access.
    pub signed: T,

    /// The signatures attached to this metadata document, sibling
    /// of `signed`.
    pub signatures: Vec<Signature>,
}

/// Helper: parse a `{"signed": ..., "signatures": [...]}` envelope
/// AND retain the raw `signed` subtree as a [`serde_json::Value`] so
/// it can be re-canonicalised for signature verification.
///
/// Returning the typed body + the raw `Value` from one parse pass
/// avoids a second walk over the bytes.
pub(crate) fn parse_signed_envelope<T>(
    bytes: &[u8],
) -> Result<(Signed<T>, serde_json::Value), serde_json::Error>
where
    T: for<'de> Deserialize<'de>,
{
    // We deserialise twice: once into the typed envelope (so we can
    // borrow strongly-typed fields), once into a Value (so we can
    // hand `signed` to the canonicaliser without round-tripping
    // through T's Serialize impl, which is allowed to drop unknown
    // fields).
    let typed: Signed<T> = serde_json::from_slice(bytes)?;
    let v: serde_json::Value = serde_json::from_slice(bytes)?;
    let signed_value = v
        .get("signed")
        .cloned()
        .ok_or_else(|| serde::de::Error::custom("envelope missing `signed` field"))?;
    Ok((typed, signed_value))
}

/// Per-role pointer that timestamp.json carries to snapshot.json
/// (and that snapshot.json carries to each targets metadata).
///
/// Mirrors the TUF spec `META` shape. `length` is optional in newer
/// spec versions; `hashes` is required when `length` is present.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MetaInfo {
    /// Version of the referenced metadata. Used for monotonicity
    /// checks (the current spec; v0 stores it but the cross-check is
    /// caller-driven).
    pub version: u32,

    /// Optional declared byte length of the referenced metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,

    /// Optional hash map from algorithm name (`"sha256"`) to
    /// lowercase-hex digest. Required by the spec when `length` is
    /// set; in practice Sigstore's timestamp/snapshot roles always
    /// emit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<BTreeMap<String, String>>,
}

/// `signed` body of a `timestamp.json` document.
///
/// Timestamp's only job is to attest "the current snapshot.json's
/// hash is X, and this attestation expires at Y." It's the
/// shortest-lived role (~1 day) so a compromised snapshot can be
/// detected within a day even if no other role rotates.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Timestamp {
    /// `_type` — always `"timestamp"`.
    #[serde(rename = "_type")]
    pub type_field: String,

    #[serde(default)]
    pub spec_version: String,

    /// Monotonically-increasing version of THIS timestamp document.
    pub version: u32,

    /// ISO 8601 / RFC 3339 expiry — typically 1 day in the future.
    pub expires: String,

    /// Pointer to the current `snapshot.json`. The map is keyed by
    /// the metadata role name as it appears in the URL — for the
    /// timestamp role this is always the single key `"snapshot.json"`.
    pub meta: BTreeMap<String, MetaInfo>,
}

impl Timestamp {
    /// Convenience: extract the snapshot pointer. Returns the
    /// `"snapshot.json"` entry from `meta` (the canonical key in
    /// timestamp metadata).
    pub fn snapshot_meta(&self) -> Option<&MetaInfo> {
        self.meta.get("snapshot.json")
    }
}

/// `signed` body of a `snapshot.json` document.
///
/// Snapshot's job is to lock in a consistent set of `targets`
/// metadata files at a specific moment, so a freshness attack
/// cannot mix-and-match an old `targets` with a new one. Lifetime
/// is typically 7 days.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Snapshot {
    #[serde(rename = "_type")]
    pub type_field: String,

    #[serde(default)]
    pub spec_version: String,

    pub version: u32,
    pub expires: String,

    /// Pointers to every `targets` metadata file (top-level + any
    /// delegations). For Sigstore's bootstrap the only key is
    /// `"targets.json"`.
    pub meta: BTreeMap<String, MetaInfo>,
}

impl Snapshot {
    /// Convenience: extract the top-level targets pointer.
    pub fn targets_meta(&self) -> Option<&MetaInfo> {
        self.meta.get("targets.json")
    }
}

/// `signed` body of a `targets.json` document.
///
/// `targets` lists the actual files (binaries, trust roots) the TUF
/// repo distributes, each with hashes and length the consumer must
/// match. v0 only models the surface required to verify this
/// document's signatures + cross-check; we keep the targets map
/// open-ended so the caller can extract concrete artefacts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Targets {
    #[serde(rename = "_type")]
    pub type_field: String,

    #[serde(default)]
    pub spec_version: String,

    pub version: u32,
    pub expires: String,

    /// Map of target path (relative to the repo's `targets/` URL)
    /// to per-target metadata. Kept as `Value` because the inner
    /// shape includes `hashes`, `length`, and an optional `custom`
    /// blob whose schema varies by repo.
    pub targets: BTreeMap<String, serde_json::Value>,

    /// Optional delegations sub-tree. Sigstore's targets.json does
    /// not currently use delegations, so v0 does not walk this; we
    /// retain it as raw JSON so the round-trip preserves the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegations: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_signed_envelope_parses_root_and_retains_signed_value() {
        let doc = json!({
            "signed": {
                "_type": "root",
                "spec_version": "1.0.31",
                "version": 1,
                "expires": "2099-01-01T00:00:00Z",
                "keys": {},
                "roles": {
                    "root":      { "keyids": [], "threshold": 1 },
                    "timestamp": { "keyids": [], "threshold": 1 },
                    "snapshot":  { "keyids": [], "threshold": 1 },
                    "targets":   { "keyids": [], "threshold": 1 }
                },
                "consistent_snapshot": true
            },
            "signatures": []
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        let (env, signed_value) =
            parse_signed_envelope::<crate::root::Root>(&bytes).expect("envelope");
        assert_eq!(env.signed.version, 1);
        assert_eq!(signed_value.get("_type").unwrap(), "root");
    }

    #[test]
    fn test_timestamp_snapshot_meta_returns_snapshot_pointer() {
        let mut meta = BTreeMap::new();
        meta.insert(
            "snapshot.json".to_string(),
            MetaInfo {
                version: 7,
                length: Some(1234),
                hashes: Some({
                    let mut h = BTreeMap::new();
                    h.insert("sha256".to_string(), "ab".repeat(32));
                    h
                }),
            },
        );
        let ts = Timestamp {
            type_field: "timestamp".into(),
            spec_version: "1.0.31".into(),
            version: 9,
            expires: "2099-01-01T00:00:00Z".into(),
            meta,
        };
        assert_eq!(ts.snapshot_meta().unwrap().version, 7);
    }
}
