//! SBOM (Software Bill of Materials) attestation predicate-type
//! constants.
//!
//! References:
//! - CycloneDX BOM v1.5: <https://cyclonedx.org/specification/overview/>
//! - SPDX Document v2.3: <https://spdx.dev/specifications/>
//!
//! Per the in-toto Statement v1 model, an SBOM attestation has shape:
//!
//! ```json
//! {
//!   "_type": "https://in-toto.io/Statement/v1",
//!   "subject": [ ... ],
//!   "predicateType": "https://cyclonedx.org/bom/v1.5",
//!   "predicate": { ... CycloneDX or SPDX document JSON ... }
//! }
//! ```
//!
//! Unlike SLSA Provenance, this crate does NOT model the SBOM body —
//! the CycloneDX / SPDX schemas are large, evolve independently, and
//! are produced externally by `cyclonedx-rs` / `spdx-rs`. We expose
//! ONLY the predicate-type URIs as constants. Higher-level wrappers
//! in [`swe_justsign_sign::sbom`](../../../sign/src/sbom.rs) accept
//! the SBOM as `serde_json::Value` and route on these constants.
//!
//! Two-constant design rationale: a verifier that conflates these
//! types (e.g. accepts a CycloneDX bundle when it expected SPDX)
//! fails the policy boundary the predicate-type was meant to enforce.
//! Holding the constants here — sourced from a single crate — means
//! every signer and verifier in the workspace pulls the byte-for-byte
//! same URI; a typo would surface as a workspace-wide compile failure
//! rather than a silent interop drift.

/// CycloneDX BOM v1.5 predicate-type URI.
///
/// Verifiers route on this exact string to interpret the predicate
/// body as a CycloneDX BOM JSON document. Trailing-slash and case
/// drift are NOT tolerated — predicate-type matching is a literal
/// string compare per cosign's behaviour.
pub const CYCLONEDX_BOM_V1_5_PREDICATE_TYPE: &str = "https://cyclonedx.org/bom/v1.5";

/// SPDX Document v2.3 predicate-type URI.
///
/// Verifiers route on this exact string to interpret the predicate
/// body as an SPDX 2.3 document JSON. As with CycloneDX, the match
/// is byte-for-byte; a v2.2 document carrying a v2.3 URI is a
/// caller bug we deliberately do NOT mask.
pub const SPDX_DOCUMENT_V2_3_PREDICATE_TYPE: &str = "https://spdx.dev/Document/v2.3";

#[cfg(test)]
mod tests {
    use super::*;

    /// CycloneDX predicate-type constant equals the exact spec URL.
    ///
    /// Bug it catches: a typo in the URI (e.g. dropping the `v1.5`
    /// suffix, capitalising the host, adding a trailing slash) would
    /// silently make every CycloneDX verifier in the workspace reject
    /// valid bundles produced by other Sigstore tooling — and accept
    /// bundles that other tooling would reject. Predicate-type URIs
    /// are policy boundaries; pin the literal.
    #[test]
    fn test_cyclonedx_predicate_type_equals_canonical_uri() {
        assert_eq!(
            CYCLONEDX_BOM_V1_5_PREDICATE_TYPE,
            "https://cyclonedx.org/bom/v1.5"
        );
    }

    /// SPDX predicate-type constant equals the exact spec URL.
    ///
    /// Bug it catches: same drift class as the CycloneDX test, but
    /// for SPDX. The two URIs share enough structure (lowercase,
    /// scheme, version suffix) that a copy-paste between them is a
    /// realistic mistake; pinning each independently catches the
    /// case where one was changed without the other.
    #[test]
    fn test_spdx_predicate_type_equals_canonical_uri() {
        assert_eq!(
            SPDX_DOCUMENT_V2_3_PREDICATE_TYPE,
            "https://spdx.dev/Document/v2.3"
        );
    }

    /// CycloneDX and SPDX predicate-type constants MUST be distinct.
    ///
    /// Bug it catches: a refactor that aliased one constant to the
    /// other (e.g. `pub const SPDX_... = CYCLONEDX_...;`) would
    /// silently make the cross-type rejection in
    /// `verify_cyclonedx_rejects_spdx_bundle` a tautology — the test
    /// would pass for the wrong reason and the safety property
    /// (no cross-acceptance between SBOM types) would be unenforced.
    #[test]
    fn test_cyclonedx_and_spdx_predicate_types_are_distinct() {
        assert_ne!(
            CYCLONEDX_BOM_V1_5_PREDICATE_TYPE, SPDX_DOCUMENT_V2_3_PREDICATE_TYPE,
            "CycloneDX and SPDX predicate-type URIs must differ — \
             cross-type rejection in the verifier depends on this."
        );
    }
}
