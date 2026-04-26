//! High-level sign / verify API.
//!
//! Stub crate. The blob / OCI artifact / attestation
//! sign + verify orchestration lands in subsequent slices.
//!
//! Reference re-exports (so callers can pull the whole stack
//! through `sign`):
pub use fulcio;
pub use rekor;
pub use spec;
pub use tuf;
