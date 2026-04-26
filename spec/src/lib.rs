//! Wire formats for Sigstore-shaped signing.
//!
//! This crate is a primitive: pure structs + serde, no IO. Higher-
//! level signing/verification lives in `swe_justsign_sign`; cert +
//! transparency clients in `swe_justsign_fulcio` /
//! `swe_justsign_rekor` / `swe_justsign_tuf`.
//!
//! v0 covers the DSSE envelope (the bytes every Sigstore signature
//! lives in). In-toto attestation predicates, the Sigstore bundle
//! JSON, and Rekor entry types land in subsequent slices.

pub mod dsse;

pub use dsse::{
    pae, Envelope, EnvelopeDecodeError, EnvelopeEncodeError, Signature, DSSE_PAE_PREFIX,
};
