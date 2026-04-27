//! HashiCorp Vault Transit signer — typed v0 stub. Real impl: justsign#20.
//!
//! Carries the Vault base address, mount path of the Transit
//! secrets engine, and the named key under that mount.
//! Implements [`crate::Signer`] so callers can already wire it
//! through. [`VaultTransitSigner::sign`] returns
//! [`SignerError::Stubbed`]; [`VaultTransitSigner::key_id`]
//! returns a stable `<vault_addr>/v1/<mount_path>/keys/<key_name>`
//! identifier matching the URL of Vault's `keys/<name>` read API.

use crate::{Signer, SignerError};

/// Signs DSSE PAE bytes via HashiCorp Vault's Transit secrets
/// engine.
///
/// v0 is a **typed stub** — see [module docs][crate::kms] for the
/// scope decision and the follow-up issue (justsign#20) that
/// replaces the stub with a hand-rolled HTTP call to
/// `POST /v1/{mount_path}/sign/{key_name}`.
///
/// Three fields by design: Vault Transit allows multiple mounts
/// of the secrets engine on the same server, each with its own
/// keyspace. Pinning the mount path explicitly avoids the
/// ambiguity of "which `transit/` did the operator mean".
#[derive(Debug, Clone)]
pub struct VaultTransitSigner {
    /// Vault server base address, e.g. `https://vault.example.com:8200`.
    pub vault_addr: String,

    /// Mount path of the Transit secrets engine. Vault's default
    /// is `transit`, but operators frequently run multiple mounts
    /// (e.g. `transit-prod`, `transit-staging`).
    pub mount_path: String,

    /// Named key within the Transit mount, e.g. `release-signer`.
    pub key_name: String,
}

impl VaultTransitSigner {
    /// Construct a stub signer with the given Vault address,
    /// Transit mount path, and key name.
    pub fn new(
        vault_addr: impl Into<String>,
        mount_path: impl Into<String>,
        key_name: impl Into<String>,
    ) -> Self {
        Self {
            vault_addr: vault_addr.into(),
            mount_path: mount_path.into(),
            key_name: key_name.into(),
        }
    }

    /// Stable identifier in the canonical Vault Transit key URL
    /// shape. Held as a method (not a field) so it stays
    /// derivative of the three configured pieces — same rationale
    /// as [`super::azure::AzureKeyVaultSigner::key_id`].
    fn full_key_url(&self) -> String {
        format!(
            "{}/v1/{}/keys/{}",
            self.vault_addr.trim_end_matches('/'),
            self.mount_path.trim_matches('/'),
            self.key_name
        )
    }
}

impl Signer for VaultTransitSigner {
    fn key_id(&self) -> Option<String> {
        Some(self.full_key_url())
    }

    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        // v0 stub. The real impl (justsign#20) POSTs the SHA-256
        // digest to `/v1/{mount_path}/sign/{key_name}` with
        // `prehashed=true`, strips the `vault:v1:` prefix from
        // the returned signature, base64-decodes, and transcodes
        // to DER so it matches `EcdsaP256Signer`'s output shape.
        Err(SignerError::Stubbed(format!(
            "VaultTransitSigner is a v0 typed stub; SDK integration tracked in justsign#20. \
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
    /// HTTP call before the follow-up integration ships would not
    /// return `Stubbed` here, breaking this assertion.
    #[test]
    fn test_sign_returns_stubbed_when_called_payload_length_in_message() {
        let signer = VaultTransitSigner::new(
            "https://vault.example.com:8200",
            "transit",
            "release-signer",
        );
        let payload = b"vault-transit-pae";

        match signer.sign(payload) {
            Err(SignerError::Stubbed(msg)) => {
                assert!(
                    msg.contains("justsign#20"),
                    "stub error must cite follow-up issue, got: {msg}"
                );
                assert!(
                    msg.contains(&format!("{} bytes", payload.len())),
                    "stub error must echo payload length, got: {msg}"
                );
                assert!(
                    msg.contains("https://vault.example.com:8200/v1/transit/keys/release-signer"),
                    "stub error must echo composed key URL, got: {msg}"
                );
            }
            Err(other) => panic!("expected SignerError::Stubbed, got {other:?}"),
            Ok(_) => {
                panic!("v0 VaultTransitSigner must NOT return Ok — it has no real impl wired")
            }
        }
    }

    /// Bug it catches: a refactor that drops the mount path from
    /// `key_id()` (e.g. assuming the default `transit` mount and
    /// hard-coding it) would silently misidentify keys when
    /// operators run multiple Transit mounts.
    #[test]
    fn test_key_id_returns_full_composed_key_url_when_constructed() {
        let signer = VaultTransitSigner::new(
            "https://vault.example.com:8200",
            "transit-prod",
            "release-signer",
        );

        assert_eq!(
            signer.key_id(),
            Some("https://vault.example.com:8200/v1/transit-prod/keys/release-signer".to_string())
        );
    }

    /// Bug it catches: inconsistent slash-trimming would produce
    /// a malformed `key_id()` like `.../v1//transit/keys/...`.
    /// We assert the canonical URL shape regardless of whether
    /// the operator hands us trailing slashes on either input.
    #[test]
    fn test_new_normalises_trailing_slashes_in_composed_key_id() {
        let messy = VaultTransitSigner::new(
            "https://vault.example.com:8200/",
            "/transit/",
            "release-signer",
        );
        let clean = VaultTransitSigner::new(
            "https://vault.example.com:8200",
            "transit",
            "release-signer",
        );

        assert_eq!(messy.key_id(), clean.key_id());
        assert_eq!(
            clean.key_id(),
            Some("https://vault.example.com:8200/v1/transit/keys/release-signer".to_string())
        );
    }
}
