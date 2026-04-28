//! Wire formats for Sigstore-shaped signing.
//!
//! This crate is a primitive: pure structs + serde, no IO. Higher-
//! level signing/verification lives in `swe_justsign_sign`; cert +
//! transparency clients in `swe_justsign_fulcio` /
//! `swe_justsign_rekor` / `swe_justsign_tuf`.
//!
//! v0 covers:
//! - [`dsse`] — Dead Simple Signing Envelope (the bytes every
//!   Sigstore signature lives in).
//! - [`in_toto`] — in-toto Statement v1 (the JSON wrapped inside
//!   DSSE for attestations).
//! - [`sigstore_bundle`] — Sigstore bundle v0.3 JSON (the all-in-one
//!   verification artifact: signature + cert chain + Rekor entries).
//!
//! Rekor entry types land in a subsequent slice.

pub mod clock;
pub mod dsse;
pub mod in_toto;
pub mod sbom;
pub mod sigstore_bundle;
pub mod slsa;

pub use clock::{Clock, FixedClock, SystemClock};

pub use dsse::{
    pae, Envelope, EnvelopeDecodeError, EnvelopeEncodeError, Signature, DSSE_PAE_PREFIX,
};

pub use in_toto::{
    Statement, StatementDecodeError, StatementEncodeError, Subject, IN_TOTO_STATEMENT_V1_TYPE,
};

pub use sbom::{CYCLONEDX_BOM_V1_5_PREDICATE_TYPE, SPDX_DOCUMENT_V2_3_PREDICATE_TYPE};

pub use sigstore_bundle::{
    Bundle, BundleContent, BundleContentKind, BundleDecodeError, BundleEncodeError, Certificate,
    Checkpoint, HashOutput, InclusionPromise, InclusionProof, KindVersion, LogId, MessageSignature,
    TimestampVerificationData, TlogEntry, VerificationMaterial, SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE,
};

pub use slsa::{
    BuildDefinition, BuildMetadata, Builder, ResourceDescriptor, RunDetails, SlsaProvenanceV1,
    SLSA_PROVENANCE_V1_PREDICATE_TYPE,
};
