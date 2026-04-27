//! GCP KMS signer — typed v0 stub. Real SDK integration: justsign#18.
//!
//! Carries the full GCP KMS resource name (project / location /
//! keyring / key / version) and implements [`crate::Signer`] so
//! callers can already wire it through. [`GcpKmsSigner::sign`]
//! returns [`SignerError::Stubbed`]; [`GcpKmsSigner::key_id`]
//! returns the configured resource name.

use crate::{Signer, SignerError};

/// Signs DSSE PAE bytes via a GCP KMS asymmetric key version.
///
/// v0 is a **typed stub** — see [module docs][crate::kms] for the
/// scope decision and the follow-up issue (justsign#18) that
/// replaces the stub with a real GCP KMS client call.
///
/// One field on purpose: GCP KMS resource names already encode
/// the project, location, keyring, key, AND key-version, so a
/// single `String` is the caller's natural unit of configuration.
#[derive(Debug, Clone)]
pub struct GcpKmsSigner {
    /// Full GCP KMS key version resource name, e.g.
    /// `projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1`.
    /// Returned verbatim by [`Signer::key_id`].
    pub key_resource_name: String,
}

impl GcpKmsSigner {
    /// Construct a stub signer with the given GCP KMS resource
    /// name. The string MUST point at a *key version*, not a key
    /// — GCP's `AsymmetricSign` API operates per-version.
    pub fn new(key_resource_name: impl Into<String>) -> Self {
        Self {
            key_resource_name: key_resource_name.into(),
        }
    }
}

impl Signer for GcpKmsSigner {
    fn key_id(&self) -> Option<String> {
        Some(self.key_resource_name.clone())
    }

    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        // v0 stub. The real impl (justsign#18) calls
        // `KeyManagementServiceClient::asymmetric_sign` with the
        // SHA-256 digest of `pae_bytes` and returns DER-encoded
        // ECDSA bytes.
        Err(SignerError::Stubbed(format!(
            "GcpKmsSigner is a v0 typed stub; SDK integration tracked in justsign#18. \
             would have signed {} bytes against key_resource_name={}",
            pae_bytes.len(),
            self.key_resource_name
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
        let signer = GcpKmsSigner::new(
            "projects/example/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        );
        let payload = b"hello-payload";

        match signer.sign(payload) {
            Err(SignerError::Stubbed(msg)) => {
                assert!(
                    msg.contains("justsign#18"),
                    "stub error must cite follow-up issue, got: {msg}"
                );
                assert!(
                    msg.contains(&format!("{} bytes", payload.len())),
                    "stub error must echo payload length, got: {msg}"
                );
                assert!(
                    msg.contains(
                        "projects/example/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
                    ),
                    "stub error must echo configured resource name, got: {msg}"
                );
            }
            Err(other) => panic!("expected SignerError::Stubbed, got {other:?}"),
            Ok(_) => panic!("v0 GcpKmsSigner must NOT return Ok — it has no real SDK wired"),
        }
    }

    /// Bug it catches: a refactor that drops the configured
    /// resource name from `key_id()` (e.g. returning `None` to
    /// mean "keyless") would silently break DSSE `keyid`
    /// propagation for GCP-KMS-signed bundles.
    #[test]
    fn test_key_id_returns_some_with_configured_resource_name_when_constructed() {
        let signer = GcpKmsSigner::new(
            "projects/p/locations/us/keyRings/kr/cryptoKeys/k/cryptoKeyVersions/2",
        );

        assert_eq!(
            signer.key_id(),
            Some(
                "projects/p/locations/us/keyRings/kr/cryptoKeys/k/cryptoKeyVersions/2".to_string()
            )
        );
    }

    /// Bug it catches: a `new()` that drops the resource name
    /// (or stores it under the wrong field) would not surface
    /// the caller's configuration in the `Stubbed` diagnostic.
    #[test]
    fn test_new_round_trips_resource_name_into_stub_message() {
        let signer = GcpKmsSigner::new(
            "projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/9",
        );
        let err = signer.sign(b"abc").unwrap_err();
        let SignerError::Stubbed(msg) = err else {
            panic!("expected Stubbed");
        };
        assert!(msg.contains("projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/9"));
        assert!(msg.contains("3 bytes"));
    }
}
