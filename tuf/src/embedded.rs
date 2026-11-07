//! Bundled Sigstore production trust roots.
//!
//! This module ships the Sigstore production TUF root metadata bytes
//! verbatim, baked into the `swe_justsign_tuf` library at build time
//! via [`include_bytes!`].
//!
//! The decision to bundle (option (a) per ADR
//! `docs/3-design/adr/001_sigstore_tuf_bootstrap.md`) is the
//! v0 bootstrap policy: zero-config trust establishment, with chained
//! root walking ([`crate::client::TufClient::fetch_root`]) handling
//! Sigstore's signed rotations transparently. Operators who need to
//! override the embedded root (air-gapped deployments, custom mirrors,
//! security-paranoid pipelines) use
//! [`crate::client::TufClient::with_initial_root_bytes`].
//!
//! # Provenance
//!
//! The bytes were fetched from
//! <https://tuf-repo-cdn.sigstore.dev/14.root.json> and cross-checked
//! against the Sigstore root-signing GitHub repository at
//! <https://raw.githubusercontent.com/sigstore/root-signing/main/metadata/root.json>
//! and
//! <https://raw.githubusercontent.com/sigstore/root-signing/main/metadata/root_history/14.root.json>.
//! All three sources produced byte-identical content. See the v0.1.0
//! commit message that landed this asset for the fetch timestamp and
//! the SHA-256 cross-check.
//!
//! # Integrity gates
//!
//! Two integrity gates protect callers from a corrupted or stale
//! embedded asset:
//!
//! 1. **Build-time check** ([`build.rs`](../../build.rs)): parses the
//!    asset as JSON, asserts the `signed._type == "root"` shape, and
//!    fails the build if the asset is already expired. Emits a
//!    `cargo:warning` if expiry is less than 30 days away.
//! 2. **Runtime expiry guard**
//!    ([`crate::client::TufClient::with_initial_root_bytes`]): parses
//!    the bytes again on construction and returns
//!    [`crate::TufError::EmbeddedRootExpired`] if the system clock has
//!    passed the embedded root's `expires` timestamp.
//!
//! # Rotation policy
//!
//! Sigstore publishes new root versions that are signed by the
//! previous root (the "old signs new" half of TUF spec §5.3.4). The
//! chained-root walker
//! ([`crate::client::TufClient::fetch_root`]) walks N -> N+1 -> ...
//! until 404, so a Sigstore rotation is invisible to operators: the
//! embedded root only needs to be a *valid ancestor* of the current
//! production root, not the current production root itself. A
//! justsign release with a refreshed asset is only required if
//! Sigstore publishes a non-chained rotation (no occurrences in
//! Sigstore's history to date) or if the embedded root expires
//! before chain-walking can reach a successor.

/// The bundled Sigstore production TUF root metadata bytes.
///
/// Verbatim copy of the wire-form `{ "signatures": [...], "signed":
/// {...} }` envelope from the Sigstore production CDN. The build
/// script asserts this is well-formed JSON with the expected `signed`
/// shape; runtime constructors re-parse and re-validate before
/// trusting.
pub const SIGSTORE_PRODUCTION_ROOT_BYTES: &[u8] =
    include_bytes!("../assets/sigstore_prod.root.json");

/// Lowercase-hex SHA-256 digest of [`SIGSTORE_PRODUCTION_ROOT_BYTES`].
///
/// Used by the runtime test
/// ([`tests::test_embedded_root_sha256_matches_constant`]) to confirm
/// the asset bytes haven't drifted from this hash. The hash is
/// computed once at landing and cross-checked against the Sigstore
/// CDN AND the Sigstore root-signing GitHub repository before being
/// committed.
pub const SIGSTORE_PRODUCTION_ROOT_SHA256: &str =
    "c8c41ec13f06ccabf5b48541ee2550098b4c7b5349e1d180390c29a7d5c2642c";

/// Source URL the embedded bytes were fetched from.
pub const SIGSTORE_PRODUCTION_ROOT_SOURCE: &str = "https://tuf-repo-cdn.sigstore.dev/14.root.json";

/// UTC ISO 8601 timestamp the bytes were fetched from
/// [`SIGSTORE_PRODUCTION_ROOT_SOURCE`].
pub const SIGSTORE_PRODUCTION_ROOT_FETCHED_AT: &str = "2026-04-27T12:05:00Z";

/// Sigstore TUF root version number embedded in the asset.
///
/// Cross-checked against the parsed `signed.version` field by the
/// runtime test
/// ([`tests::test_embedded_root_version_matches_metadata`]).
pub const SIGSTORE_PRODUCTION_ROOT_VERSION: u32 = 14;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::time::SystemTime;

    /// The embedded bytes parse cleanly into the typed [`Root`] body.
    ///
    /// Bug it catches: an asset that is valid JSON but has the wrong
    /// shape (e.g. a snapshot.json was committed by mistake, or the
    /// asset is the bare `signed` body without the surrounding
    /// envelope). Without this test the failure mode would surface
    /// only on `TufClient::sigstore()` at runtime, not at `cargo
    /// test`.
    #[test]
    fn test_embedded_root_parses_into_typed_root_body() {
        let v: Value =
            serde_json::from_slice(SIGSTORE_PRODUCTION_ROOT_BYTES).expect("asset is valid JSON");
        let signed = v
            .get("signed")
            .cloned()
            .expect("envelope must contain `signed`");
        let root: Root =
            serde_json::from_value(signed).expect("`signed` must deserialise as TUF Root");
        assert_eq!(root.type_field, "root", "asset _type must be \"root\"");
        assert!(root.version > 0, "asset version must be > 0");
        assert!(!root.expires.is_empty(), "asset expires must not be empty");
        assert!(!root.keys.is_empty(), "asset must declare at least one key");
        assert!(
            !root.roles.is_empty(),
            "asset must declare at least one role"
        );
    }

    /// The recomputed SHA-256 of [`SIGSTORE_PRODUCTION_ROOT_BYTES`]
    /// matches the [`SIGSTORE_PRODUCTION_ROOT_SHA256`] constant.
    ///
    /// Bug it catches: the asset file and the constant drifted out of
    /// sync (e.g. someone committed a refreshed asset but forgot to
    /// update the constant, or vice versa). The constant is the
    /// load-bearing trust claim of this whole bundling slice; if the
    /// bytes don't match, the embedded "trust root" is worse than no
    /// root at all (it's a confident-but-wrong root).
    #[test]
    fn test_embedded_root_sha256_matches_constant() {
        let mut h = Sha256::new();
        h.update(SIGSTORE_PRODUCTION_ROOT_BYTES);
        let digest = h.finalize();
        let mut actual = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for b in digest.iter() {
            actual.push(HEX[(b >> 4) as usize] as char);
            actual.push(HEX[(b & 0x0f) as usize] as char);
        }
        assert_eq!(
            actual, SIGSTORE_PRODUCTION_ROOT_SHA256,
            "asset bytes and SIGSTORE_PRODUCTION_ROOT_SHA256 constant disagree; \
             update one to match the other and re-verify both against the upstream Sigstore mirror"
        );
    }

    /// The embedded root's `expires` timestamp is in the future at
    /// the time the test runs.
    ///
    /// Bug it catches: the build.rs check passed (no expiry at build
    /// time) but the runtime check would still reject (stricter
    /// parser, different "now" source, or the build pipeline's clock
    /// is wrong). Without this test we'd only discover a divergence
    /// in production. Mirrors what
    /// [`crate::client::TufClient::with_initial_root_bytes`] does on
    /// every invocation.
    #[test]
    fn test_embedded_root_not_expired_at_test_time() {
        let v: Value =
            serde_json::from_slice(SIGSTORE_PRODUCTION_ROOT_BYTES).expect("asset is valid JSON");
        let expires = v
            .get("signed")
            .and_then(|s| s.get("expires"))
            .and_then(|e| e.as_str())
            .expect("asset must have signed.expires string");
        let expired = crate::expiry::is_expired(expires, SystemTime::now())
            .expect("asset expires must be parseable RFC 3339 UTC-Z");
        assert!(
            !expired,
            "embedded Sigstore root has already expired at {}; \
             upgrade swe_justsign_tuf to a release that ships a fresh asset",
            expires
        );
    }

    /// `signed.version` in the embedded asset matches the
    /// [`SIGSTORE_PRODUCTION_ROOT_VERSION`] constant.
    ///
    /// Bug it catches: a refreshed asset was committed without
    /// bumping the version constant (or vice versa), causing the
    /// constant to lie about which Sigstore root version operators
    /// are actually trusting. The version is operator-visible
    /// information surfaced in the ADR + the commit message.
    #[test]
    fn test_embedded_root_version_matches_metadata() {
        let v: Value =
            serde_json::from_slice(SIGSTORE_PRODUCTION_ROOT_BYTES).expect("asset is valid JSON");
        let version = v
            .get("signed")
            .and_then(|s| s.get("version"))
            .and_then(|n| n.as_u64())
            .expect("asset must have signed.version integer");
        assert_eq!(
            version as u32, SIGSTORE_PRODUCTION_ROOT_VERSION,
            "asset signed.version ({}) and SIGSTORE_PRODUCTION_ROOT_VERSION constant ({}) \
             disagree; update the constant to match the asset",
            version, SIGSTORE_PRODUCTION_ROOT_VERSION
        );
    }
}
