//! Cloud KMS signer surfaces — typed v0 stubs.
//!
//! Real Sigstore deployments commonly back signing keys with a
//! cloud KMS (AWS KMS, GCP KMS, Azure Key Vault) or HashiCorp
//! Vault's Transit secrets engine rather than file-based keys.
//! The [`crate::Signer`] trait is already in place; this module
//! adds the four canonical providers behind per-provider feature
//! flags.
//!
//! ## v0 posture: typed stubs, not real SDK calls
//!
//! Real KMS SDKs (`aws-sdk-kms`, `azure_security_keyvault`,
//! `google-cloud-kms`) are large async / tokio crates that would
//! pull ~200 transitive dependencies each into justsign. The
//! [`crate::Signer`] trait is synchronous, so a real impl would
//! also have to bridge async-to-sync per call.
//!
//! For v0 of #10 we deliberately ship **typed stubs**:
//!
//! * The config types are real (e.g. [`aws::AwsKmsSigner`] holds
//!   `key_arn` + `region`). Downstream callers can declare a KMS
//!   signer in their code today.
//! * `Signer::key_id` is real — it returns the stable identifier
//!   (ARN / GCP resource name / Key Vault URL+name+version /
//!   Vault key path).
//! * `Signer::sign` returns [`crate::SignerError::Stubbed`] with
//!   a message naming the provider, the configured identifier,
//!   the payload byte-length the caller passed in, and the
//!   follow-up issue number.
//!
//! ## Follow-up issues (one per provider)
//!
//! * AWS KMS — justsign#17
//! * GCP KMS — justsign#18
//! * Azure Key Vault — justsign#19
//! * HashiCorp Vault Transit — justsign#20
//!
//! Each follow-up replaces its provider's stub with a real
//! `Signer::sign` impl that drives the SDK (or, for Vault,
//! a hand-rolled HTTP call) via a per-call tokio runtime. The
//! stub-error test in each module fails as soon as the real
//! impl lands, forcing the integration PR to update tests.
//!
//! ## Why a single module
//!
//! All four providers share the same shape — config struct, trait
//! impl, three tests asserting the stub error path — so they live
//! side-by-side under `kms::`. The trait-bound is independent per
//! provider; there is no shared runtime state, so no shared
//! helpers are warranted yet.

#[cfg(feature = "aws-kms")]
pub mod aws;

#[cfg(feature = "gcp-kms")]
pub mod gcp;

#[cfg(feature = "azure-kv")]
pub mod azure;

#[cfg(feature = "vault-transit")]
pub mod vault;
