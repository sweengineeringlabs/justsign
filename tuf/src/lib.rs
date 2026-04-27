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
//! # Out of scope
//!
//! - **Bootstrap.** The caller supplies the trusted initial root.
//!   Baking a Sigstore root into the binary is a separate
//!   attack-surface decision tracked elsewhere.
//! - **Delegations.** No delegated targets traversal —
//!   [`Targets::delegations`] is preserved as raw JSON.
//! - **ECDSA / RSA keys.** Ed25519-only, mirroring Sigstore's
//!   deployed shape.
//!
//! # Cryptography
//!
//! v0 supports **Ed25519 only**.
//!
//! - `keytype = "ed25519"`, `scheme = "ed25519"`
//! - `keyval.public` is a hex-encoded 32-byte Ed25519 public key
//!   (lowercase hex, no `0x` prefix — TUF convention).
//!
//! ECDSA roots (`keytype = "ecdsa-sha2-nistp256"`) are rejected with
//! [`TufError::UnsupportedKeyType`]. Sigstore's current TUF root is
//! Ed25519, so this matches the deployed shape; ECDSA support would
//! land alongside chained-root verification in v1.
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
pub mod expiry;
mod root;
pub mod types;

pub use canonical::{canonicalize, CanonicalizationError};
pub use client::TufClient;
pub use expiry::{format_rfc3339_utc, is_expired, ExpiryParseError};
pub use root::{
    verify_role, verify_self_signed, Key, KeyId, KeyVal, Role, RoleName, Root, Signature, TufError,
};
pub use types::{MetaInfo, Signed, Snapshot, Targets, Timestamp};
