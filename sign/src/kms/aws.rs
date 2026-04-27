//! AWS KMS signer — typed v0 stub. Real SDK integration: justsign#17.
//!
//! Carries the configuration a real `aws-sdk-kms`-backed signer
//! needs (the KMS key's ARN and the AWS region it lives in) and
//! implements [`crate::Signer`] so callers can already wire it
//! through. [`AwsKmsSigner::sign`] returns
//! [`SignerError::Stubbed`]; [`AwsKmsSigner::key_id`] returns the
//! configured ARN.

use crate::{Signer, SignerError};

/// Signs DSSE PAE bytes via an AWS KMS asymmetric key.
///
/// v0 is a **typed stub** — see [module docs][crate::kms] for the
/// scope decision and the follow-up issue (justsign#17) that
/// replaces the stub with a real `aws-sdk-kms` call.
///
/// Construction is intentionally cheap: holding two `String`s
/// and nothing else means a caller can declare an `AwsKmsSigner`
/// next to a file-key signer without paying for an SDK client
/// handle until the real integration lands.
#[derive(Debug, Clone)]
pub struct AwsKmsSigner {
    /// Full KMS key ARN, e.g.
    /// `arn:aws:kms:us-east-1:123456789012:key/abcd1234-...`.
    /// Returned verbatim by [`Signer::key_id`].
    pub key_arn: String,

    /// AWS region the key lives in, e.g. `us-east-1`. Held as a
    /// separate field (not parsed out of the ARN) because the
    /// SDK's region resolution chain is independent of the ARN
    /// string and operators sometimes deliberately point a
    /// signer at a different regional endpoint.
    pub region: String,
}

impl AwsKmsSigner {
    /// Construct a stub signer with the given KMS key ARN and
    /// AWS region.
    pub fn new(key_arn: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            key_arn: key_arn.into(),
            region: region.into(),
        }
    }
}

impl Signer for AwsKmsSigner {
    fn key_id(&self) -> Option<String> {
        Some(self.key_arn.clone())
    }

    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        // v0 stub. The real impl (justsign#17) calls
        // `aws_sdk_kms::Client::sign` with `MessageType::Digest`
        // and returns DER-encoded ECDSA bytes. Echoing the payload
        // length here lets caller-side wiring diagnostics confirm
        // the signer was reached with the bytes they expected.
        Err(SignerError::Stubbed(format!(
            "AwsKmsSigner is a v0 typed stub; SDK integration tracked in justsign#17. \
             would have signed {} bytes against key_arn={} in region={}",
            pae_bytes.len(),
            self.key_arn,
            self.region
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bug it catches: a regression that silently lands a real
    /// SDK call before the follow-up integration ships would not
    /// return `Stubbed` here, breaking this assertion.
    #[test]
    fn test_sign_returns_stubbed_when_called_payload_length_in_message() {
        let signer = AwsKmsSigner::new(
            "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
            "us-east-1",
        );
        let payload = b"pae-bytes-of-some-length";

        match signer.sign(payload) {
            Err(SignerError::Stubbed(msg)) => {
                assert!(
                    msg.contains("justsign#17"),
                    "stub error must cite follow-up issue, got: {msg}"
                );
                assert!(
                    msg.contains(&format!("{} bytes", payload.len())),
                    "stub error must echo payload length, got: {msg}"
                );
                assert!(
                    msg.contains("arn:aws:kms:us-east-1:123456789012:key/abcd-1234"),
                    "stub error must echo configured key_arn, got: {msg}"
                );
                assert!(
                    msg.contains("us-east-1"),
                    "stub error must echo configured region, got: {msg}"
                );
            }
            Err(other) => panic!("expected SignerError::Stubbed, got {other:?}"),
            Ok(_) => panic!("v0 AwsKmsSigner must NOT return Ok — it has no real SDK wired"),
        }
    }

    /// Bug it catches: a refactor that drops the configured ARN
    /// from `key_id()` (e.g. someone returning `None` to mean
    /// "keyless") would silently break DSSE `keyid` propagation
    /// for AWS-KMS-signed bundles.
    #[test]
    fn test_key_id_returns_some_with_configured_arn_when_constructed() {
        let signer = AwsKmsSigner::new(
            "arn:aws:kms:eu-west-1:000000000000:key/zzzz-9999",
            "eu-west-1",
        );

        assert_eq!(
            signer.key_id(),
            Some("arn:aws:kms:eu-west-1:000000000000:key/zzzz-9999".to_string())
        );
    }

    /// Bug it catches: a `new()` that drops or swaps fields
    /// (region in place of arn, etc.) would not round-trip the
    /// caller's intent into the `Stubbed` diagnostic string.
    #[test]
    fn test_new_round_trips_arn_and_region_into_stub_message() {
        let signer = AwsKmsSigner::new("arn:aws:kms:ap-south-1:111:key/xyz", "ap-south-1");
        let err = signer.sign(b"").unwrap_err();
        let SignerError::Stubbed(msg) = err else {
            panic!("expected Stubbed");
        };
        assert!(msg.contains("arn:aws:kms:ap-south-1:111:key/xyz"));
        assert!(msg.contains("ap-south-1"));
        assert!(msg.contains("0 bytes"));
    }
}
