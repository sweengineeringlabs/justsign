//! Error types for the sign / verify surface.
//!
//! Two top-level enums:
//!
//! * [`SignError`] — surfaced by [`crate::sign_blob`].
//! * [`VerifyError`] — surfaced by [`crate::verify_blob`].
//!
//! Each variant names a precise failure mode so callers can route
//! on it (retry, drop the bundle, escalate, log).

use rekor::RekorError;
use spec::{
    BundleDecodeError, BundleEncodeError, EnvelopeEncodeError, StatementDecodeError,
    StatementEncodeError,
};

/// Failure surface of [`crate::sign_blob`].
///
/// Construction sites are intentionally narrow:
///
/// * `Pae`            — couldn't materialise the DSSE Pre-Auth
///   Encoding bytes (in v0 this is unreachable in practice but the
///   variant gives downstream code a place to surface PAE-shape
///   errors when richer payload-type validation lands).
/// * `Signer`         — the user's [`crate::Signer`] implementation
///   returned an error.
/// * `RekorSubmit`    — the supplied [`rekor::RekorClient`] rejected
///   the submission.
/// * `BundleEncode`   — internal: building the [`spec::Bundle`] hit
///   an encode error (e.g. JSON serialisation of a TimestampVerificationData).
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// Building the DSSE PAE bytes failed. Held as a string so we
    /// don't leak whatever future PAE-validator type we wire in.
    #[error("dsse pae construction: {0}")]
    Pae(String),

    /// User-supplied signer rejected the PAE bytes.
    #[error("signer error: {0}")]
    Signer(String),

    /// Rekor submission failed — bubble through the underlying
    /// rekor error so callers can match on its variants.
    #[error("rekor submit: {0}")]
    RekorSubmit(#[from] RekorError),

    /// Internal: bundle encode failed. Surfacing this as a typed
    /// variant means callers can still distinguish wire-shape bugs
    /// from real signing failures.
    #[error("bundle encode: {0}")]
    BundleEncode(#[from] BundleEncodeError),

    /// OCI manifest construction (issue #6 surface) failed. Held
    /// as its own variant so blob and OCI flows stay
    /// distinguishable in callers.
    #[error("oci: {0}")]
    Oci(#[from] OciError),

    /// Internal: in-toto Statement JSON serialisation failed.
    /// Surfaced by [`crate::attest`] when the predicate `Value` can't
    /// be serialised (e.g. it contains a non-UTF-8 string handed in
    /// via `serde_json::Value::String` — possible only via unsafe
    /// construction). Kept as a typed variant so caller code can
    /// distinguish a malformed-predicate bug from a signer failure.
    #[error("statement encode: {0}")]
    StatementEncode(#[from] StatementEncodeError),

    /// Caller passed an empty cert chain to [`crate::sign_blob_keyless`].
    /// Mirrors [`VerifyError::EmptyCertChain`] on the verifier side:
    /// keyless bundles need at least the leaf, so we reject upfront
    /// rather than emit a structurally-valid bundle whose
    /// `verification_material.certificate.certificates` is empty
    /// (which the keyless verifier would later reject as
    /// `EmptyCertChain` anyway). Caught at the producer boundary so
    /// callers see the same typed error on both sides of the loop.
    #[error("cert chain is empty (keyless signing requires a leaf cert)")]
    EmptyCertChain,

    /// Internal: encoding the DSSE envelope JSON failed while
    /// building the `dsse` rekor entry. Surfaced (instead of
    /// being collapsed into [`SignError::BundleEncode`]) because
    /// envelope-encode and bundle-encode are different
    /// construction sites: a regression in DSSE serialisation
    /// shouldn't masquerade as a bundle-shape failure.
    #[error("dsse envelope encode for rekor: {0}")]
    EnvelopeEncode(#[from] EnvelopeEncodeError),
}

/// Failure surface of [`crate::verify_blob`].
///
/// Variants spell out the SPECIFIC reason verification failed —
/// "signature didn't validate" is distinct from "we never had an
/// envelope to check" or "rekor proof rejected the leaf" because
/// downstream policy treats them differently.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Bundle's content variant is `MessageSignature`, not the DSSE
    /// envelope this v0 verifier expects. Held as its own variant
    /// because it's a shape mismatch, not a bad-signature error.
    #[error("bundle has no DSSE envelope (message-signature variant set)")]
    EnvelopeMissing,

    /// Some signature in the envelope failed to validate against
    /// any trusted key. `keyid` is the DSSE `keyid` field if the
    /// failing signature carried one — useful for diagnosing which
    /// key the signer claimed.
    #[error("signature invalid (keyid = {keyid:?})")]
    SignatureInvalid {
        /// DSSE keyid of the failing signature, if present.
        keyid: Option<String>,
    },

    /// Caller asked for transparency-log verification but the
    /// bundle has no `tlog_entries`. Distinct from "no rekor client
    /// supplied" — that path skips proof verification entirely.
    #[error("bundle has no tlog entries to verify against")]
    NoTlogEntry,

    /// Rekor inclusion proof verification rejected the entry.
    #[error("rekor verify: {0}")]
    RekorVerify(#[from] RekorError),

    /// Internal: bundle decode failed (e.g. when verifying a bundle
    /// produced by a malformed encoder).
    #[error("bundle decode: {0}")]
    BundleDecode(#[from] BundleDecodeError),

    // ───────────────────────────────────────────────────────────
    // Keyless / cert-chain variants — appended for issue #5.
    //
    // Surface area for `crate::verify_blob_keyless`. Each variant
    // names a distinct keyless-specific failure so policy can route:
    // a missing chain is operator-fixable; a SAN mismatch is
    // identity-policy-fixable; an expired cert is clock-fixable.
    // ───────────────────────────────────────────────────────────
    /// Bundle's `verification_material.certificate` is `None` or
    /// holds a zero-length cert chain. Keyless verification needs
    /// at least the leaf — surface this distinctly from a generic
    /// "chain broken" error so callers can tell "you sent the wrong
    /// kind of bundle" apart from "your chain didn't verify".
    #[error("bundle has no cert chain (keyless verification requires a leaf)")]
    EmptyCertChain,

    /// Cert-chain walking rejected the chain. Wraps the underlying
    /// [`crate::cert_chain::ChainError`] so callers can match on
    /// specifics (broken signature at known index, root not in
    /// anchors, unsupported algorithm).
    #[error("cert chain broken: {0}")]
    ChainBroken(#[from] crate::cert_chain::ChainError),

    /// The leaf's SubjectAltName entries don't include the
    /// `expected_san` the caller required. `actual` echoes what the
    /// cert DID carry so the operator can see the drift (e.g. a
    /// CI-provider identity vs the user identity policy expected).
    #[error("SAN mismatch: expected {expected:?}, leaf SAN = {actual:?}")]
    SanMismatch {
        /// The exact SAN string the policy required.
        expected: String,
        /// All SAN entries (rfc822 + URI) the leaf actually
        /// carried, in source order.
        actual: Vec<String>,
    },

    /// Some cert in the chain has `notAfter` in the past per the
    /// active [`spec::Clock`]. Surfaces a stolen-leaf replay attempt:
    /// a signed bundle whose embedded Fulcio leaf was rotated long
    /// ago is rejected at verify time even when the cryptographic
    /// signature still nominally checks out.
    #[error("certificate expired (notAfter = {not_after})")]
    CertExpired {
        /// Unix epoch seconds parsed from the cert's `notAfter`.
        /// Held as `i64` so pre-1970 values (legal in DER, vanishing
        /// in practice) round-trip without truncation.
        not_after: i64,
    },

    /// Some cert in the chain has `notBefore` strictly after the
    /// active [`spec::Clock`]. Catches the OTHER direction of
    /// clock-skew: a producer running on a host with a fast clock
    /// can mint certs that no verifier on a normal clock will accept
    /// until time catches up. Surfaced distinctly from `CertExpired`
    /// so operators can tell "your producer's clock is fast" from
    /// "your producer's cert is stale".
    #[error("certificate not yet valid (notBefore = {not_before})")]
    CertNotYetValid {
        /// Unix epoch seconds parsed from the cert's `notBefore`.
        /// Held as `i64` to match `CertExpired`.
        not_before: i64,
    },

    /// Internal: re-encoding the bundle to compute its layer
    /// digest failed during `verify_oci`. Held separately from
    /// `BundleDecode` because the construction sites differ.
    #[error("bundle re-encode for oci verify: {0}")]
    BundleEncode(#[from] BundleEncodeError),

    /// OCI manifest construction or parsing failed during an
    /// `verify_oci` call. Held as its own variant so the OCI
    /// surface can grow without disturbing the blob verifier.
    #[error("oci: {0}")]
    Oci(#[from] OciError),

    /// Layer descriptor in the OCI referrer manifest doesn't
    /// match the bundle the caller passed in. Distinct from
    /// `Oci(LayerMismatch)` only in v0 — kept fused so the
    /// verifier can route on the typed inner.
    #[error("oci layer digest mismatch: manifest={manifest_layer_digest}, computed={computed_bundle_digest}")]
    OciLayerMismatch {
        /// Digest the manifest claims for the bundle layer.
        manifest_layer_digest: String,
        /// Digest computed from the bundle bytes the caller provided.
        computed_bundle_digest: String,
    },

    /// Bundle's DSSE envelope `payload_type` doesn't match what the
    /// verifier expected. Surfaced by [`crate::verify_attestation`]
    /// when the bundle wraps a non-attestation payload (e.g. a raw
    /// blob with `payload_type = "text/plain"` instead of
    /// `application/vnd.in-toto+json`).
    ///
    /// Held as its own variant — distinct from "signature didn't
    /// validate" — because it's a *category* mismatch: the signer
    /// wrapped the wrong kind of thing, not the wrong bytes.
    #[error("payload type mismatch: expected {expected:?}, found {found:?}")]
    WrongPayloadType {
        /// payload_type the verifier required.
        expected: String,
        /// payload_type the bundle actually carried.
        found: String,
    },

    /// Decoded in-toto Statement's `predicateType` doesn't match the
    /// caller's expected predicate type. Surfaced by
    /// [`crate::verify_attestation`].
    ///
    /// Distinct from `WrongPayloadType` because the DSSE wrapping IS
    /// in-toto — the predicate inside is just the wrong kind (e.g.
    /// SLSA Provenance v0.2 vs v1, or Provenance vs SPDX).
    #[error("predicate type mismatch: expected {expected:?}, found {found:?}")]
    WrongPredicateType {
        /// predicate_type the verifier required.
        expected: String,
        /// predicate_type the Statement actually carried.
        found: String,
    },

    /// Caller pinned an expected `(algo, hex)` digest for the subject
    /// they care about, but no subject in the Statement carries that
    /// (algo, hex) pair. Matches cosign's "any subject" semantics:
    /// an attestation may name multiple subjects (a multi-arch
    /// manifest list, an SBOM covering several artifacts), and the
    /// verifier accepts the bundle as long as ONE subject matches.
    #[error("no subject matches expected digest: {expected_digest}")]
    SubjectMismatch {
        /// `"<algo>:<hex>"` formatted digest the verifier required.
        expected_digest: String,
    },

    /// Decoded DSSE payload was not a valid in-toto Statement v1.
    /// Wraps the spec-crate decode error so callers can route on its
    /// inner variants (wrong `_type`, malformed JSON, etc.).
    #[error("statement decode: {0}")]
    StatementDecode(#[from] StatementDecodeError),

    /// Bundle's content arm doesn't match what the verifier expected.
    /// Surfaced by [`crate::verify_blob_message`] when handed a
    /// `DsseEnvelope`-content bundle (a DSSE attestation routed into
    /// the raw-blob verifier), and symmetric in spirit to
    /// [`Self::EnvelopeMissing`] (which is the DSSE-side equivalent).
    ///
    /// Held distinct from `EnvelopeMissing` because cosign's two
    /// content arms are *functionally* distinct flows: a verifier
    /// that lumped both rejections under one name would mask which
    /// direction the wrong-shape bundle was pointed at, and operators
    /// would have to re-read the verifier source to know whether they
    /// fed `verify-blob` an attestation or `verify-blob-attestation`
    /// a sign-blob bundle.
    #[error("wrong bundle content: expected {expected}, found {found}")]
    WrongContentType {
        /// Content kind the verifier required.
        expected: &'static str,
        /// Content kind the bundle actually carried.
        found: &'static str,
    },

    /// SHA-256 of the caller-supplied payload doesn't match the
    /// `messageDigest.digest` pinned in a `MessageSignature`-content
    /// bundle. Surfaced by [`crate::verify_blob_message`].
    ///
    /// Held distinct from [`Self::SignatureInvalid`] because a digest
    /// mismatch means the *caller* re-fetched the wrong payload (or
    /// the bundle was misrouted), not that the signature itself was
    /// bad. Ops route on the two cases differently — digest mismatch
    /// is a "you fetched the wrong file" hint; signature mismatch is
    /// a "tamper detected" alert.
    #[error("payload digest mismatch: bundle pinned {expected}, computed {computed}")]
    PayloadDigestMismatch {
        /// Hex-encoded digest the bundle pinned in
        /// `messageDigest.digest`.
        expected: String,
        /// Hex-encoded SHA-256 of the payload the verifier was
        /// handed.
        computed: String,
    },

    /// `MessageSignature.messageDigest.algorithm` is not one this
    /// verifier knows how to recompute. v0 supports only `SHA2_256`
    /// — every other algorithm surfaces this typed error rather than
    /// silently accepting (or attempting an undefined recompute).
    ///
    /// Surfaced by [`crate::verify_blob_message`].
    #[error("unsupported messageDigest algorithm: {algorithm}")]
    UnsupportedHashAlgorithm {
        /// The algorithm string from the bundle's `messageDigest`.
        /// Echoed verbatim so operators can see the exact value the
        /// producer claimed (e.g. `SHA2_512`, a typo, an empty
        /// string).
        algorithm: String,
    },
}

/// Failure surface of [`crate::oci`] manifest construction +
/// parsing.
///
/// Construction sites:
///
/// * `Json`              — serde_json round-trip failed (encoding
///   the manifest, or decoding bytes the caller handed us).
/// * `BundleEncode`      — internal: encoding the bundle to bytes
///   to compute the layer digest hit a `BundleEncodeError`.
///   Surfaced as a string so we don't leak the spec error type
///   through `OciError`'s public API.
/// * `BadDigestFormat`   — caller passed a digest that doesn't
///   match `<algo>:<hex>`. Caught early so a typo'd digest
///   doesn't propagate into a manifest that a registry will
///   reject 200 lines later.
/// * `LayerMismatch`     — manifest layer digest didn't match the
///   bundle bytes the verifier was handed. Surfaces tampering or
///   a wrong-bundle-for-this-manifest pairing.
/// * `MissingSubject`    — manifest had no `subject` descriptor;
///   it's not a referrer at all.
/// * `WrongArtifactType` — manifest's `artifactType` isn't the
///   Sigstore bundle media type. cosign uses a fixed string.
/// * `WrongSchemaVersion` — OCI image manifest schemaVersion
///   wasn't 2. v0 only emits/accepts schemaVersion=2.
/// * `WrongLayerCount`   — referrer manifests for Sigstore
///   bundles must carry exactly ONE layer (the bundle blob).
#[derive(Debug, thiserror::Error)]
pub enum OciError {
    /// JSON encode or decode failed.
    #[error("oci manifest json: {0}")]
    Json(#[from] serde_json::Error),

    /// Bundle could not be encoded to compute the layer digest.
    #[error("bundle encode for oci layer: {0}")]
    BundleEncode(String),

    /// Caller-supplied digest doesn't match `<algo>:<hex>`.
    #[error("bad digest format: {value}")]
    BadDigestFormat {
        /// The offending digest string. Echoed back so the caller
        /// can route logging / user-error messages on it.
        value: String,
    },

    /// Manifest layer digest disagrees with the bundle we have.
    #[error("layer digest mismatch: manifest={manifest_layer_digest}, computed={computed_bundle_digest}")]
    LayerMismatch {
        /// Digest the manifest claims for the bundle layer.
        manifest_layer_digest: String,
        /// Digest computed from the bundle bytes we hashed.
        computed_bundle_digest: String,
    },

    /// Manifest decoded fine but had no `subject` field — that's
    /// the field that makes a manifest a referrer.
    #[error("oci referrer manifest missing subject")]
    MissingSubject,

    /// `artifactType` wasn't the Sigstore bundle v0.3 media type.
    #[error("wrong artifactType: found {found:?}, expected {expected:?}")]
    WrongArtifactType {
        /// `artifactType` as it appeared on the wire.
        found: String,
        /// Value we required.
        expected: String,
    },

    /// `schemaVersion` was not 2.
    #[error("wrong schemaVersion: found {found}")]
    WrongSchemaVersion {
        /// `schemaVersion` as it appeared on the wire.
        found: i64,
    },

    /// Manifest had a layer count other than 1.
    #[error("wrong layer count: found {found}, expected 1")]
    WrongLayerCount {
        /// Number of layers in the manifest.
        found: usize,
    },
}
