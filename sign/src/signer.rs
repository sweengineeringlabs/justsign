//! [`Signer`] trait + concrete implementations.
//!
//! The trait is deliberately narrow: it does NOT take `&mut self`,
//! which lets callers wrap a signer in `Arc<dyn Signer>` and share
//! it across threads / async tasks. Holding mutable state inside the
//! signer is an anti-pattern — keys should be immutable for their
//! lifetime, and counters/audits belong outside the SPI.
//!
//! v0 ships:
//!
//! * [`Signer`] — the contract.
//! * [`EcdsaP256Signer`] — wraps a `p256::ecdsa::SigningKey`. The
//!   real signer the library uses for keypair-based flows.
//! * [`MockSigner`] — returns canned bytes regardless of input.
//!   Indispensable for tests that need to round-trip a bundle
//!   through the encoder/decoder without depending on a real key.

use std::sync::Arc;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey};

/// Failure surface of a [`Signer`] implementation.
///
/// Held separately from [`crate::SignError`] so a custom signer
/// (HSM-backed, KMS-backed, etc.) can surface its own failures
/// without depending on the rest of the library's error tree.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// Catch-all surface for signer implementations that don't
    /// have richer error types of their own. The string is
    /// passed straight through to [`crate::SignError::Signer`] so
    /// it shows up in operator logs verbatim.
    #[error("signer: {0}")]
    Other(String),

    /// Returned by a v0 typed-stub signer whose real SDK
    /// integration is tracked in a follow-up issue (the cloud
    /// KMS signers in [`crate::kms`]). Holds an operator-facing
    /// message that names the provider, the configured key
    /// identifier, the payload byte-length the caller passed in,
    /// and the follow-up issue number.
    ///
    /// Held as a distinct variant — not folded into [`Self::Other`]
    /// — so callers can match on it and route differently (e.g.
    /// emit a "stub signer wired in production" alert instead of
    /// treating it as a generic signing failure).
    #[error("signer stub: {0}")]
    Stubbed(String),

    /// Loading a PKCS#11 provider shared library failed. `path`
    /// echoes the exact module path the caller asked us to load —
    /// a wrong path is the single most common operator mistake on
    /// this surface (typo, missing package, wrong arch), and a
    /// failure that swallows the path is undiagnosable from logs
    /// alone. `cause` carries the underlying loader error
    /// message (varies by OS — `libloading`'s `dlopen` /
    /// `LoadLibraryW` text). String-typed because PKCS#11 backends
    /// surface error chains differently across versions and we
    /// don't want to leak `cryptoki`'s error tree through this
    /// crate's public API. (Field is named `cause` rather than
    /// `source` to avoid `thiserror`'s implicit `Error::source()`
    /// wiring, which requires the field to implement
    /// `std::error::Error` — `String` does not.)
    #[error("pkcs11 module load failed: path={path}: {cause}")]
    ModuleLoad {
        /// Module path the caller passed in (e.g.
        /// `/usr/lib/softhsm/libsofthsm2.so`,
        /// `C:\\Program Files\\YubiKey PIV\\libykcs11.dll`).
        path: String,
        /// Underlying loader error message.
        cause: String,
    },

    /// A PKCS#11 call after the module was loaded returned an
    /// error. Construction sites: `C_Initialize`, `C_OpenSession`,
    /// `C_Login`, `C_FindObjectsInit/C_FindObjects`, `C_SignInit`,
    /// `C_Sign`. The `cause` string is the cryptoki-formatted
    /// message — it includes the failing function name and the
    /// PKCS#11 return code (e.g. `Function::Sign: PKCS11 error:
    /// CKR_DATA_LEN_RANGE`), which is the minimum operators need
    /// to route a token-side failure.
    #[error("pkcs11: {cause}")]
    Pkcs11 {
        /// Underlying cryptoki error message (function + return code).
        cause: String,
    },

    /// `C_FindObjects` returned zero matches for the configured
    /// `CKA_LABEL`. Distinct from [`SignerError::Pkcs11`] because
    /// it's an operator-fixable identity / configuration error,
    /// not a token-state error: the caller asked us to sign with
    /// a key the token doesn't carry. Echoing the label back means
    /// a typo in config surfaces immediately.
    #[error("pkcs11: no key found with label {label:?}")]
    KeyNotFound {
        /// The label the caller configured.
        label: String,
    },
}

/// Contract a key-bearing signer must satisfy.
///
/// Implementations:
///
/// * receive the raw PAE bytes ([`spec::pae`] output) — they are
///   responsible for hashing those bytes with whatever digest the
///   key's algorithm requires (SHA-256 for ECDSA-P256).
/// * MUST be `Send + Sync` so callers can hold them behind an
///   `Arc` and share across threads.
/// * MUST NOT take `&mut self` — see module docs.
pub trait Signer: Send + Sync {
    /// Stable identifier callers may attach to the DSSE
    /// `signatures[*].keyid` field. `None` means "the verifier
    /// already has the key out-of-band" — a common keyless flow.
    fn key_id(&self) -> Option<String>;

    /// Sign the given Pre-Authentication Encoding bytes. The
    /// caller has already concatenated the DSSE `payloadType` +
    /// `payload`; the signer hashes those bytes with the digest
    /// its algorithm requires and returns the raw signature
    /// bytes.
    ///
    /// Returning `Vec<u8>` means we don't pin a particular
    /// signature encoding — ECDSA returns DER, Ed25519 returns
    /// raw `r||s`. Verifiers downstream must know which is which
    /// from the key's algorithm.
    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError>;
}

// Blanket impl so `Arc<dyn Signer>` and `Arc<EcdsaP256Signer>`
// both work as `&dyn Signer` callers.
impl<T: Signer + ?Sized> Signer for Arc<T> {
    fn key_id(&self) -> Option<String> {
        (**self).key_id()
    }
    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        (**self).sign(pae_bytes)
    }
}

/// ECDSA-with-SHA256 signer over the P-256 curve.
///
/// This is the "realistic" signer the library uses for keypair-
/// based blob signing. Wraps a `p256::ecdsa::SigningKey`. The
/// `signature::Signer` impl from the `p256` crate already hashes
/// the input with SHA-256, so callers hand us PAE bytes and we
/// hand back DER-encoded signature bytes.
///
/// Holding the key by value (not `Arc`-internally) keeps the
/// signer itself cheap to construct. Callers wanting share-ability
/// should wrap in `Arc<EcdsaP256Signer>` themselves.
pub struct EcdsaP256Signer {
    key: SigningKey,
    key_id: Option<String>,
}

impl EcdsaP256Signer {
    /// Construct from an already-loaded `SigningKey`. The signer
    /// has no opinion on how the key was materialised — random,
    /// PEM-loaded, HSM-backed-then-extracted; that's the caller's
    /// job.
    pub fn new(key: SigningKey, key_id: Option<String>) -> Self {
        Self { key, key_id }
    }
}

impl std::fmt::Debug for EcdsaP256Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't surface the secret key in Debug output. Operators
        // log signer instances and we don't want a key in a log
        // file by accident.
        f.debug_struct("EcdsaP256Signer")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Signer for EcdsaP256Signer {
    fn key_id(&self) -> Option<String> {
        self.key_id.clone()
    }

    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        // `p256::ecdsa::SigningKey: signature::Signer` already runs
        // SHA-256 over the input internally before producing the
        // signature, so we hand it the raw PAE bytes directly.
        // Returning DER preserves the standard wire encoding for
        // ECDSA — verifiers reconstruct via `Signature::from_der`.
        let sig: P256Signature = self.key.sign(pae_bytes);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// Test-only signer that returns canned bytes.
///
/// `MockSigner::new(canned)` always returns `canned.clone()` from
/// `sign(_)` regardless of input. Use it when a test needs to
/// drive [`crate::sign_blob`] without depending on a real keypair.
///
/// Pairs naturally with verifying-side test code that uses the
/// SAME canned bytes to "verify" — i.e. byte-equality of the
/// returned signature, not real cryptographic verification.
#[derive(Debug, Clone)]
pub struct MockSigner {
    canned: Vec<u8>,
    key_id: Option<String>,
}

impl MockSigner {
    /// Construct with the bytes every call to `sign` should
    /// return.
    pub fn new(canned: Vec<u8>, key_id: Option<String>) -> Self {
        Self { canned, key_id }
    }
}

impl Signer for MockSigner {
    fn key_id(&self) -> Option<String> {
        self.key_id.clone()
    }

    fn sign(&self, _pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.canned.clone())
    }
}

// ---------------------------------------------------------------
// Additional algorithm signers (issue #12).
//
// Each one mirrors `EcdsaP256Signer`'s shape exactly: hold the
// signing key by value + an optional `key_id`, expose `new`, redact
// the key in `Debug`, and produce raw signature bytes from the
// PAE. Verifiers in `crate::lib::verify_blob` route by matching the
// `VerifyingKey` enum variant — see that function for the wire
// shape each algorithm produces (DER for ECDSA P-384 / secp256k1,
// raw 64-byte for Ed25519).
// ---------------------------------------------------------------

/// Ed25519 signer over the PureEd25519 scheme (RFC 8032).
///
/// Wraps `ed25519_dalek::SigningKey`. The signer itself does NOT
/// pre-hash — Ed25519's signing path consumes the message bytes
/// directly and runs SHA-512 internally as part of the
/// deterministic-nonce derivation. We hand it the raw PAE bytes,
/// matching what every other DSSE Ed25519 signer in the wider
/// ecosystem (cosign, in-toto-attestation Go libs) does.
///
/// Returns the raw 64-byte signature (`r || s`). Verifiers in
/// [`crate::verify_blob`] reconstruct via
/// `ed25519_dalek::Signature::from_bytes`.
#[cfg(feature = "ed25519")]
pub struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
    key_id: Option<String>,
}

#[cfg(feature = "ed25519")]
impl Ed25519Signer {
    /// Construct from an already-loaded `SigningKey`. As with
    /// [`EcdsaP256Signer::new`], the signer has no opinion on how
    /// the key was materialised — random, PKCS#8-loaded, or
    /// extracted from another flow.
    pub fn new(key: ed25519_dalek::SigningKey, key_id: Option<String>) -> Self {
        Self { key, key_id }
    }
}

#[cfg(feature = "ed25519")]
impl std::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Same redaction rule as EcdsaP256Signer — never log secret
        // material, even at Debug level.
        f.debug_struct("Ed25519Signer")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "ed25519")]
impl Signer for Ed25519Signer {
    fn key_id(&self) -> Option<String> {
        self.key_id.clone()
    }

    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        // `ed25519_dalek::SigningKey` implements `signature::Signer`
        // for the PureEd25519 scheme — it consumes the message
        // bytes directly. Returning raw `r||s` (64 bytes) keeps the
        // wire encoding aligned with what cosign + in-toto-attestation
        // emit; the verifier reconstructs via `Signature::from_bytes`.
        use ed25519_dalek::Signer as _;
        let sig: ed25519_dalek::Signature = self.key.sign(pae_bytes);
        Ok(sig.to_bytes().to_vec())
    }
}

/// ECDSA-with-SHA384 signer over the P-384 curve.
///
/// Wraps `p384::ecdsa::SigningKey`. Mirrors [`EcdsaP256Signer`]
/// byte-for-byte: the `signature::Signer` impl runs SHA-384 over
/// the input internally, and we return DER-encoded signature
/// bytes so verifiers can reconstruct via
/// `p384::ecdsa::Signature::from_der`.
#[cfg(feature = "ecdsa-p384")]
pub struct EcdsaP384Signer {
    key: p384::ecdsa::SigningKey,
    key_id: Option<String>,
}

#[cfg(feature = "ecdsa-p384")]
impl EcdsaP384Signer {
    /// Construct from an already-loaded `SigningKey`. See
    /// [`EcdsaP256Signer::new`] — the contract is identical.
    pub fn new(key: p384::ecdsa::SigningKey, key_id: Option<String>) -> Self {
        Self { key, key_id }
    }
}

#[cfg(feature = "ecdsa-p384")]
impl std::fmt::Debug for EcdsaP384Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaP384Signer")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "ecdsa-p384")]
impl Signer for EcdsaP384Signer {
    fn key_id(&self) -> Option<String> {
        self.key_id.clone()
    }

    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        // P-384's `signature::Signer` impl runs SHA-384 internally,
        // mirroring the P-256/SHA-256 contract one curve up. DER
        // encoding stays standard for ECDSA signatures.
        use p384::ecdsa::signature::Signer as _;
        let sig: p384::ecdsa::Signature = self.key.sign(pae_bytes);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// ECDSA-with-SHA256 signer over the secp256k1 curve.
///
/// Wraps `k256::ecdsa::SigningKey`. Same shape as
/// [`EcdsaP256Signer`]: SHA-256 is run internally by the
/// `signature::Signer` impl, output is DER-encoded. The curve
/// differs (Bitcoin / Ethereum default) but the wire encoding for
/// the signature is identical — verifiers reconstruct via
/// `k256::ecdsa::Signature::from_der`.
#[cfg(feature = "secp256k1")]
pub struct Secp256k1Signer {
    key: k256::ecdsa::SigningKey,
    key_id: Option<String>,
}

#[cfg(feature = "secp256k1")]
impl Secp256k1Signer {
    /// Construct from an already-loaded `SigningKey`. See
    /// [`EcdsaP256Signer::new`] — the contract is identical.
    pub fn new(key: k256::ecdsa::SigningKey, key_id: Option<String>) -> Self {
        Self { key, key_id }
    }
}

#[cfg(feature = "secp256k1")]
impl std::fmt::Debug for Secp256k1Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secp256k1Signer")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "secp256k1")]
impl Signer for Secp256k1Signer {
    fn key_id(&self) -> Option<String> {
        self.key_id.clone()
    }

    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        // secp256k1's `signature::Signer` impl runs SHA-256 over
        // the input internally; DER encoding is the standard wire
        // form for ECDSA. Same shape as EcdsaP256Signer.
        use k256::ecdsa::signature::Signer as _;
        let sig: k256::ecdsa::Signature = self.key.sign(pae_bytes);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}
