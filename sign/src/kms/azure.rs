//! Azure Key Vault signer — typed v0 stub. Real SDK integration: justsign#19.
//!
//! Carries the vault URL, key name, and key version Azure Key
//! Vault's `Sign` API needs and implements [`crate::Signer`] so
//! callers can already wire it through.
//! [`AzureKeyVaultSigner::sign`] returns [`SignerError::Stubbed`];
//! [`AzureKeyVaultSigner::key_id`] returns a stable
//! `<vault_url>/keys/<key_name>/<key_version>` identifier.

use crate::{Signer, SignerError};

/// Signs DSSE PAE bytes via an Azure Key Vault key version.
///
/// v0 is a **typed stub** — see [module docs][crate::kms] for the
/// scope decision and the follow-up issue (justsign#19) that
/// replaces the stub with a real `azure_security_keyvault` call.
///
/// Three fields by design: Azure Key Vault key URLs are formed
/// as `{vault_url}/keys/{name}/{version}`. Pinning the version
/// at construction time makes the signer deterministic — auto-
/// rotation surfaces as a NEW signer instance, not a silent
/// algorithm/key change in the middle of a long-lived process.
#[derive(Debug, Clone)]
pub struct AzureKeyVaultSigner {
    /// Vault base URL, e.g. `https://my-vault.vault.azure.net`.
    pub vault_url: String,

    /// Key name within the vault, e.g. `signing-key`.
    pub key_name: String,

    /// Specific key version (a hex object identifier produced by
    /// Azure on rotation). Pinned per signer instance.
    pub key_version: String,
}

impl AzureKeyVaultSigner {
    /// Construct a stub signer pinned to the given vault URL,
    /// key name, and key version.
    pub fn new(
        vault_url: impl Into<String>,
        key_name: impl Into<String>,
        key_version: impl Into<String>,
    ) -> Self {
        Self {
            vault_url: vault_url.into(),
            key_name: key_name.into(),
            key_version: key_version.into(),
        }
    }

    /// Stable identifier for this signer in the canonical
    /// Key-Vault URL shape: `{vault_url}/keys/{name}/{version}`.
    /// Held as a method (not a field) because it's deterministic
    /// from the three configured pieces and we don't want it to
    /// drift if a caller mutates the struct fields directly.
    fn full_key_url(&self) -> String {
        format!(
            "{}/keys/{}/{}",
            self.vault_url.trim_end_matches('/'),
            self.key_name,
            self.key_version
        )
    }
}

impl Signer for AzureKeyVaultSigner {
    fn key_id(&self) -> Option<String> {
        Some(self.full_key_url())
    }

    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        // v0 stub. The real impl (justsign#19) calls Key Vault's
        // `Sign` REST endpoint with `alg=ES256` and a SHA-256
        // digest, then transcodes the returned r||s pair to DER
        // so it matches `EcdsaP256Signer`'s output shape.
        Err(SignerError::Stubbed(format!(
            "AzureKeyVaultSigner is a v0 typed stub; SDK integration tracked in justsign#19. \
             would have signed {} bytes against key_url={}",
            pae_bytes.len(),
            self.full_key_url()
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
        let signer = AzureKeyVaultSigner::new(
            "https://my-vault.vault.azure.net",
            "signing-key",
            "abcdef0123456789",
        );
        let payload = b"some-pae";

        match signer.sign(payload) {
            Err(SignerError::Stubbed(msg)) => {
                assert!(
                    msg.contains("justsign#19"),
                    "stub error must cite follow-up issue, got: {msg}"
                );
                assert!(
                    msg.contains(&format!("{} bytes", payload.len())),
                    "stub error must echo payload length, got: {msg}"
                );
                assert!(
                    msg.contains(
                        "https://my-vault.vault.azure.net/keys/signing-key/abcdef0123456789"
                    ),
                    "stub error must echo full configured key URL, got: {msg}"
                );
            }
            Err(other) => panic!("expected SignerError::Stubbed, got {other:?}"),
            Ok(_) => panic!("v0 AzureKeyVaultSigner must NOT return Ok — it has no real SDK wired"),
        }
    }

    /// Bug it catches: a refactor that drops a field from the
    /// composed `key_id()` (e.g. omitting the version, which would
    /// make the keyid non-unique across rotations) would silently
    /// break DSSE `keyid` propagation for Key-Vault-signed bundles.
    #[test]
    fn test_key_id_returns_full_composed_key_url_when_constructed() {
        let signer =
            AzureKeyVaultSigner::new("https://kv.example.vault.azure.net", "build-signer", "ver1");

        assert_eq!(
            signer.key_id(),
            Some("https://kv.example.vault.azure.net/keys/build-signer/ver1".to_string())
        );
    }

    /// Bug it catches: a `new()` that strips trailing slashes
    /// inconsistently (or fails to) would produce a malformed
    /// `key_id()` like `.../keys//build-signer/ver1`. We assert the
    /// canonical shape regardless of whether the caller hands us
    /// `https://kv/` or `https://kv`.
    #[test]
    fn test_new_normalises_trailing_slash_on_vault_url_in_composed_key_id() {
        let with_slash = AzureKeyVaultSigner::new(
            "https://kv.example.vault.azure.net/",
            "build-signer",
            "ver1",
        );
        let without_slash =
            AzureKeyVaultSigner::new("https://kv.example.vault.azure.net", "build-signer", "ver1");

        assert_eq!(with_slash.key_id(), without_slash.key_id());
        assert_eq!(
            with_slash.key_id(),
            Some("https://kv.example.vault.azure.net/keys/build-signer/ver1".to_string())
        );
    }
}
