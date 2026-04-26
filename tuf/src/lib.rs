//! TUF metadata verifier for justsign — establishes Sigstore root of
//! trust.
//!
//! # v0 scope
//!
//! Verification-only. Pure structs + a verifier; the caller supplies
//! `root.json` bytes (and the raw `signed` slice — see below) however
//! they like (filesystem read, embedded asset, network fetch).
//!
//! What v0 does:
//!
//! - Parse a TUF root metadata document into a typed [`Root`].
//! - Verify a list of [`Signature`]s against a named role with at
//!   least the role's threshold of distinct, valid keys.
//! - In particular, check that a `root.json` is *self-signed* — i.e.
//!   `root.signatures[]` validate against the keys named in
//!   `root.signed.roles.root.keyids` to at least the root role's
//!   threshold. This is the recursive trust establishment a TUF
//!   client performs at boot.
//!
//! # Out of v0 scope
//!
//! - **Rotation / rollback.** Chained-root verification (N+1 root
//!   signed by N's root keys) is not implemented.
//! - **Targets / snapshot / timestamp roles.** Only the root role's
//!   self-signature is checked.
//! - **Delegations.** No delegated targets traversal.
//! - **Expiry enforcement.** [`TufError::Expired`] is defined for
//!   callers who want to enforce it; the verifier itself does *not*
//!   reject expired metadata. Caller decides.
//! - **Fetching.** No HTTP, no filesystem, no caching.
//! - **Hashing.** v0 verifies signatures over caller-supplied raw
//!   bytes; the caller is responsible for producing those bytes from
//!   the `signed` field of `root.json` (see [`signature`] module
//!   docs for what TUF expects here).
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
//! # Canonical-JSON disclaimer
//!
//! TUF specifies that signatures cover the **OLPC canonical JSON**
//! form of the `signed` object, not arbitrary serde-emitted JSON.
//! Real TUF clients re-canonicalise `signed` before hashing.
//!
//! v0 sidesteps this by **letting the caller supply the exact bytes
//! that were signed**: [`verify_role`] takes a `signed_bytes`
//! parameter and treats it as opaque. For unit tests we synthesise
//! roots where we control both signing and verification, so the
//! canonical-JSON ambiguity does not bite. A v1 that ingests live
//! Sigstore metadata will need to either (a) implement OLPC
//! canonical JSON or (b) re-extract the `signed` byte slice from the
//! original document via a streaming JSON parser.

mod root;

pub use root::{
    verify_role, verify_self_signed, Key, KeyId, KeyVal, Role, RoleName, Root, Signature, TufError,
};
