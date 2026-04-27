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
use spec::{BundleDecodeError, BundleEncodeError};

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

    /// Placeholder for clock-aware expiry enforcement. Defined in v0
    /// so callers can construct it after a caller-side `notAfter`
    /// check; `verify_blob_keyless` itself does NOT enforce expiry
    /// (parity with [`tuf::TufError::Expired`]). v1 wires a clock SPI
    /// and emits this variant directly.
    #[error("certificate expired (notAfter = {not_after})")]
    CertExpired {
        /// Unix epoch seconds parsed from the cert's `notAfter`.
        /// Held as `i64` to match the spec crate's wire shape for
        /// timestamps; negative values are legal in DER but would
        /// only arise from clock-pre-1970 weirdness.
        not_after: i64,
    },
}
