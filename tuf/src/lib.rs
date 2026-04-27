//! TUF metadata verifier + fetcher for justsign — establishes
//! Sigstore root of trust.
//!
//! # Surface
//!
//! Two layers, both shipping today:
//!
//! 1. **Pure verifier** — [`Root`], [`verify_role`],
//!    [`verify_self_signed`]. Caller supplies pre-fetched bytes; we
//!    parse, threshold-verify, and surface typed errors. v0
//!    behaviour, kept as the bottom of the stack.
//! 2. **HTTP fetcher + chained-root walker** — [`TufClient`]. Hits a
//!    Sigstore TUF mirror over HTTPS, walks the root chain
//!    (old-signs-new + new-signs-self per spec §5.3.4), verifies
//!    role signatures over canonical JSON, cross-checks role hashes
//!    (timestamp pins snapshot, snapshot pins targets), enforces
//!    expiry on every role, caches raw metadata bytes to disk so
//!    re-runs don't refetch. See [`TufClient`] docs for the spec
//!    walkthrough.
//!
//! What this crate does:
//!
//! - Parse a TUF root metadata document into a typed [`Root`] (and
//!   timestamp / snapshot / targets via [`types`]).
//! - Verify a list of [`Signature`]s against a named role with at
//!   least the role's threshold of distinct, valid keys.
//! - Walk the chained-root rotation chain ([`TufClient::fetch_root`]).
//! - Fetch + verify timestamp / snapshot / targets
//!   ([`TufClient::fetch_timestamp`] et al.), with hash cross-checks.
//! - Enforce expiry on every role at fetch time ([`expiry`]).
//! - Cache raw wire bytes to disk for re-use across invocations.
//!
//! # Bootstrap
//!
//! Per ADR `docs/3-design/adr/001_sigstore_tuf_bootstrap.md`,
//! the Sigstore production TUF root is bundled into the library at
//! build time (see [`embedded`]). [`TufClient::sigstore`] uses the
//! bundled root by default; [`TufClient::with_initial_root_bytes`]
//! lets air-gapped or custom-mirror callers override.
//!
//! # Out of scope
//!
//! - **Delegations.** No delegated targets traversal —
//!   [`Targets::delegations`] is preserved as raw JSON.
//! - **RSA keys.** Not on the wire for any role this verifier is
//!   asked about; see "Cryptography" below.
//!
//! # Cryptography
//!
//! Two signature schemes are supported. Algorithm dispatch in
//! [`verify_role`] routes on the key's `scheme` field:
//!
//! - **Ed25519** (`scheme = "ed25519"`). `keyval.public` is a
//!   lowercase-hex 32-byte raw public key (TUF convention; not PEM,
//!   not DER, not base64). `signature.sig` is a lowercase-hex
//!   64-byte raw signature.
//! - **ECDSA P-256, SHA-256** (`scheme = "ecdsa-sha2-nistp256"`).
//!   `keyval.public` is either a PEM-encoded `SubjectPublicKeyInfo`
//!   (Sigstore's tuf-on-ci shape, used by the bundled v14 production
//!   root) OR a hex-encoded SEC1 elliptic-curve point (newer
//!   python-tuf shape). `signature.sig` is a lowercase-hex
//!   DER-encoded `ECDSA-Sig-Value`.
//!
//! Any other `scheme` value surfaces [`TufError::UnsupportedKeyType`].
//! The dispatch is exhaustive: there is no silent fall-through to
//! the Ed25519 path on an unrecognised scheme.
//!
//! # Canonical-JSON
//!
//! TUF specifies that signatures cover the **OLPC canonical JSON**
//! form of the `signed` object, not arbitrary serde-emitted JSON.
//! Real TUF clients re-canonicalise `signed` before hashing.
//!
//! [`verify_role`] still takes a `signed_bytes: &[u8]` and treats
//! it as opaque — synthesised tests pass pre-canonicalised bytes
//! and control both sides. The [`canonical`] module provides the
//! canonicaliser callers will use to compute those bytes from a
//! parsed `signed` value when verifying live Sigstore metadata
//! (the metadata fetcher in #3 wires it up). See
//! [`canonical::canonicalize`] for the encoding rules and the
//! reasoning behind the (a) re-canonicalise / (b) span-preserving
//! parse trade-off.

pub mod canonical;
pub mod client;
pub mod embedded;
pub mod expiry;
mod root;
pub mod span;
pub mod types;

pub use canonical::{canonicalize, CanonicalizationError};
pub use client::TufClient;
pub use embedded::{
    SIGSTORE_PRODUCTION_ROOT_BYTES, SIGSTORE_PRODUCTION_ROOT_FETCHED_AT,
    SIGSTORE_PRODUCTION_ROOT_SHA256, SIGSTORE_PRODUCTION_ROOT_SOURCE,
    SIGSTORE_PRODUCTION_ROOT_VERSION,
};
pub use expiry::{format_rfc3339_utc, is_expired, ExpiryParseError};
pub use root::{
    verify_role, verify_self_signed, Key, KeyId, KeyVal, Role, RoleName, Root, Signature, TufError,
};
pub use span::{parse_with_signed_span, SpanParseError, SpannedSignedEnvelope};
#[allow(deprecated)]
pub use types::parse_signed_envelope;
pub use types::{MetaInfo, Signed, Snapshot, Targets, Timestamp};

// ─── Issue #26: Clock SPI re-exports ────────────────────────────────
//
// `spec::Clock` is the canonical home of the trait so `tuf` and `sign`
// can both consume it without `tuf` taking a `sign` dep. Re-exported
// from `tuf` here so callers building `TufClient::with_clock(...)`
// don't have to add `swe_justsign_spec` directly to their dep graph.
pub use spec::{Clock, FixedClock, SystemClock};
