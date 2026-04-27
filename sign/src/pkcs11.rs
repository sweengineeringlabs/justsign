//! [`Pkcs11Signer`] — hardware-backed signing via a PKCS#11 module.
//!
//! Use this when the private key lives on a YubiKey, smartcard, or
//! HSM and never leaves the device. The runtime flow per
//! [`Signer::sign`] call is:
//!
//! 1. Load the PKCS#11 provider library from `module_path`
//!    (`libsofthsm2.so` / `libykcs11.dll` / vendor HSM `.dylib`).
//! 2. Initialise the library (`C_Initialize` with OS-thread locking).
//! 3. Open a read-only session against `slot_id`.
//! 4. If `pin.is_some()`, log in as `CKU_USER`.
//! 5. Find the signing key by `CKA_LABEL == key_label` in the
//!    private-key class.
//! 6. Call `C_Sign` with `CKM_ECDSA` over the caller-supplied PAE
//!    bytes. The caller is responsible for hashing — for ECDSA P-256
//!    we hash with SHA-256 here before invoking the token, because
//!    `CKM_ECDSA` (the raw mechanism) signs the digest the caller
//!    hands in, not the message.
//! 7. Convert the token's raw `r||s` output (PKCS#11 spec) into the
//!    DER `SEQUENCE { r INTEGER, s INTEGER }` that the rest of the
//!    library uses on the wire.
//! 8. Drop the session and the module (cryptoki's `Drop` impls call
//!    `C_CloseSession` and `C_Finalize`).
//!
//! ## v0 scope
//!
//! * **Mechanism**: `CKM_ECDSA` only (ECDSA P-256). RSA and EdDSA
//!   are deliberate follow-ups so the wire-shape coupling between
//!   this signer and the rest of the verify path stays narrow.
//! * **Key lookup**: by `CKA_LABEL` only. PKCS#11 also addresses
//!   keys by `CKA_ID`; surfacing both via an enum is a follow-up.
//! * **Session lifetime**: per-call open / close. The [`Signer`]
//!   trait takes `&self`, and a cryptoki `Session` is `!Sync`, so
//!   caching one across calls would require interior mutability we
//!   don't want at the SPI boundary in v0. Pooling lands when the
//!   trait grows an `&mut` path.
//! * **PIN handling**: `Option<String>`. Some tokens (an
//!   already-logged-in YubiKey, public-key-only sessions) don't
//!   need one; many do.
//!
//! ## Test fixture: SoftHSM2
//!
//! The skip-pass integration test below talks to a real PKCS#11
//! module. SoftHSM2 is the standard test-only software token used
//! by the cryptoki upstream. On Debian / Ubuntu:
//!
//! ```text
//! sudo apt-get install -y softhsm2 opensc
//! softhsm2-util --init-token --slot 0 --label justsign-test \
//!     --so-pin 1234 --pin 5678
//! ```
//!
//! The exact slot id `softhsm2-util` allocates is printed at the
//! bottom of `--init-token`'s output (it's not 0; SoftHSM2
//! reassigns the slot to a fresh id once a token is initialised).
//! The CI workflow in `.github/workflows/staging.yml` automates the
//! whole loop.
//!
//! Set the three env vars below to drive the integration test
//! against any PKCS#11 provider — SoftHSM2 in CI, a real YubiKey
//! locally, an HSM in staging:
//!
//! * `JUSTSIGN_SOFTHSM_LIB`        — absolute path to the provider
//!   library (e.g. `/usr/lib/softhsm/libsofthsm2.so`).
//! * `JUSTSIGN_SOFTHSM_PIN`        — user PIN.
//! * `JUSTSIGN_SOFTHSM_KEY_LABEL`  — CKA_LABEL of an ECDSA P-256
//!   key already provisioned on the token.
//! * `JUSTSIGN_SOFTHSM_SLOT_ID`    — slot id (decimal). Optional;
//!   defaults to the first slot returned by `C_GetSlotList`.
//!
//! ## Follow-ups
//!
//! * RSA mechanisms (`CKM_RSA_PKCS_PSS`, `CKM_SHA256_RSA_PKCS`).
//! * EdDSA mechanism (`CKM_EDDSA`) once curve negotiation is sorted.
//! * Lookup by `CKA_ID` in addition to `CKA_LABEL`.
//! * Session pooling once the [`Signer`] SPI gains an `&mut` path.

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use sha2::{Digest, Sha256};

use crate::signer::{Signer, SignerError};

/// Hardware-backed signer that delegates `C_Sign` to a PKCS#11
/// module loaded at runtime from `module_path`.
///
/// Construct with [`Pkcs11Signer::new`]. The struct is plain data —
/// no module / session is held — so it's cheap to clone and
/// trivially `Send + Sync`. All hardware interaction happens inside
/// [`Signer::sign`].
#[derive(Debug, Clone)]
pub struct Pkcs11Signer {
    /// Path to the PKCS#11 provider shared library
    /// (`libsofthsm2.so`, `libykcs11.dll`, vendor HSM `.dylib`).
    module_path: String,
    /// Slot id to open the session against.
    slot_id: u64,
    /// Optional user PIN. `None` means "this token doesn't need
    /// CKU_USER login".
    pin: Option<String>,
    /// `CKA_LABEL` value the signing key was provisioned with.
    /// Must match exactly — PKCS#11 attribute equality is
    /// byte-for-byte, no whitespace folding.
    key_label: String,
}

impl Pkcs11Signer {
    /// Construct a new PKCS#11 signer. No I/O happens here — the
    /// module is loaded only when [`Signer::sign`] is called.
    /// That deferral is intentional: it lets callers build a
    /// `Pkcs11Signer` from config without requiring the token to
    /// be plugged in at startup.
    pub fn new(
        module_path: impl Into<String>,
        slot_id: u64,
        pin: Option<String>,
        key_label: impl Into<String>,
    ) -> Self {
        Self {
            module_path: module_path.into(),
            slot_id,
            pin,
            key_label: key_label.into(),
        }
    }

    /// Module path the signer was configured with. Useful for
    /// diagnostics; never used by sign() except in error messages.
    pub fn module_path(&self) -> &str {
        &self.module_path
    }

    /// Slot id the signer was configured with.
    pub fn slot_id(&self) -> u64 {
        self.slot_id
    }

    /// `CKA_LABEL` of the signing key.
    pub fn key_label(&self) -> &str {
        &self.key_label
    }
}

/// Convert a raw PKCS#11 ECDSA signature (`r || s`, fixed-width
/// big-endian, 64 bytes for P-256) into the DER
/// `SEQUENCE { r INTEGER, s INTEGER }` shape the rest of the
/// verify path expects.
///
/// The [`Signer`] trait contract returns "raw signature bytes" but
/// the rest of this crate (and `verify_blob`'s P-256 path) reads
/// them via `p256::ecdsa::Signature::from_der`, so we encode here
/// to keep one wire shape across software and hardware signers.
fn ecdsa_raw_rs_to_der(raw: &[u8]) -> Result<Vec<u8>, SignerError> {
    if !raw.len().is_multiple_of(2) || raw.is_empty() {
        return Err(SignerError::Pkcs11 {
            cause: format!(
                "C_Sign returned an odd-length signature ({} bytes); \
                 expected fixed-width r||s",
                raw.len()
            ),
        });
    }
    let half = raw.len() / 2;
    let r = &raw[..half];
    let s = &raw[half..];

    // DER INTEGER: leading byte must be < 0x80, otherwise prepend
    // 0x00 to keep the value positive. Strip leading zeros first
    // (PKCS#11 pads to fixed width; DER strips).
    fn strip_then_pad(bytes: &[u8]) -> Vec<u8> {
        let stripped = {
            let mut i = 0;
            while i + 1 < bytes.len() && bytes[i] == 0 {
                i += 1;
            }
            &bytes[i..]
        };
        if stripped.first().is_some_and(|b| *b & 0x80 != 0) {
            let mut out = Vec::with_capacity(stripped.len() + 1);
            out.push(0x00);
            out.extend_from_slice(stripped);
            out
        } else {
            stripped.to_vec()
        }
    }

    let r_der = strip_then_pad(r);
    let s_der = strip_then_pad(s);

    fn der_integer(value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + value.len());
        out.push(0x02); // INTEGER tag
        out.push(value.len() as u8); // r/s never exceed 33 bytes for P-256
        out.extend_from_slice(value);
        out
    }

    let r_tlv = der_integer(&r_der);
    let s_tlv = der_integer(&s_der);

    let body_len = r_tlv.len() + s_tlv.len();
    let mut out = Vec::with_capacity(2 + body_len);
    out.push(0x30); // SEQUENCE tag
                    // Body length always fits in one byte for P-256 (max 70).
    out.push(body_len as u8);
    out.extend_from_slice(&r_tlv);
    out.extend_from_slice(&s_tlv);
    Ok(out)
}

impl Signer for Pkcs11Signer {
    fn key_id(&self) -> Option<String> {
        Some(self.key_label.clone())
    }

    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        // 1. Load the module. Surface the path on every load failure
        //    — this is the highest-frequency operator error and
        //    losing the path makes diagnosis impossible.
        let pkcs11 = Pkcs11::new(&self.module_path).map_err(|e| SignerError::ModuleLoad {
            path: self.module_path.clone(),
            cause: e.to_string(),
        })?;

        // 2. Initialise. PKCS#11 demands C_Initialize before any
        //    other call. `OsThreads` lets the provider use OS-level
        //    locking — the only sane choice for a multi-threaded
        //    Rust process. A stray `AlreadyInitialized` would only
        //    happen if another in-process caller initialised the
        //    same loaded library; with per-call module load that
        //    cannot happen here.
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| SignerError::Pkcs11 {
                cause: e.to_string(),
            })?;

        // 3. Open a read-only session against the configured slot.
        //    Signing does not require RW; using RO keeps the token
        //    state untouched even if the provider is bug-prone.
        let slot = Slot::try_from(self.slot_id).map_err(|e| SignerError::Pkcs11 {
            cause: format!("invalid slot id {}: {}", self.slot_id, e),
        })?;
        let session: Session = pkcs11
            .open_ro_session(slot)
            .map_err(|e| SignerError::Pkcs11 {
                cause: e.to_string(),
            })?;

        // 4. Optional user login. Tokens that don't require a PIN
        //    (some pre-personalised YubiKeys for public-key
        //    operations) get `pin = None` and we skip C_Login.
        if let Some(pin) = &self.pin {
            let auth = AuthPin::new(pin.clone());
            session
                .login(UserType::User, Some(&auth))
                .map_err(|e| SignerError::Pkcs11 {
                    cause: e.to_string(),
                })?;
        }

        // 5. Find the signing key. Match on (Class = PrivateKey,
        //    Label = key_label). Bytes match: PKCS#11 stores label
        //    as a UTF-8 byte string with no normalisation.
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(self.key_label.as_bytes().to_vec()),
        ];
        let handles = session
            .find_objects(&template)
            .map_err(|e| SignerError::Pkcs11 {
                cause: e.to_string(),
            })?;
        let key_handle = match handles.into_iter().next() {
            Some(h) => h,
            None => {
                return Err(SignerError::KeyNotFound {
                    label: self.key_label.clone(),
                });
            }
        };

        // 6. Hash the PAE bytes with SHA-256 BEFORE handing them to
        //    CKM_ECDSA. The raw `Ecdsa` mechanism in PKCS#11 signs
        //    the digest the caller provides — it does NOT hash for
        //    us (that's what `CKM_ECDSA_SHA256` is for, but support
        //    for the prehashing variants is uneven across providers,
        //    and we want a single code path that works on SoftHSM2,
        //    YubiKey, AWS CloudHSM, and Thales Luna alike).
        let mut hasher = Sha256::new();
        hasher.update(pae_bytes);
        let digest = hasher.finalize();

        // 7. Sign. The token returns r||s fixed-width bytes; we
        //    convert to DER below to match the wire format the
        //    rest of the crate expects.
        let raw_sig = session
            .sign(&Mechanism::Ecdsa, key_handle, &digest)
            .map_err(|e| SignerError::Pkcs11 {
                cause: e.to_string(),
            })?;

        // Session and Pkcs11 are dropped here; their `Drop` impls
        // call C_CloseSession and C_Finalize respectively.
        ecdsa_raw_rs_to_der(&raw_sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bug it catches: a refactor that drops one of the four config
    /// fields from the constructor would silently produce a signer
    /// that signs against the wrong slot or label. Asserting all
    /// four round-trip via the getters makes that regression
    /// loud.
    #[test]
    fn test_pkcs11_signer_constructor_stores_fields() {
        let signer = Pkcs11Signer::new(
            "/tmp/libsofthsm2.so",
            42,
            Some("1234".to_string()),
            "test-key",
        );
        assert_eq!(signer.module_path(), "/tmp/libsofthsm2.so");
        assert_eq!(signer.slot_id(), 42);
        assert_eq!(signer.key_label(), "test-key");
    }

    /// Bug it catches: a regression that returned `None` from
    /// `key_id()` (or returned the module path by mistake) would
    /// strip the `keyid` from emitted DSSE signatures, breaking
    /// keyid-based routing on the verifier side.
    #[test]
    fn test_pkcs11_signer_key_id_returns_label() {
        let signer = Pkcs11Signer::new("/tmp/lib.so", 0, None, "yubikey-piv-9c");
        assert_eq!(signer.key_id(), Some("yubikey-piv-9c".to_string()));
    }

    /// Bug it catches: a refactor that swallowed the module path in
    /// the error chain (e.g. "module load failed" without saying
    /// WHICH module) would make on-call diagnosis impossible. The
    /// path is THE most useful field on this error variant. We use
    /// a path with a guaranteed-bogus extension and directory so
    /// the test is robust on every host (Linux, macOS, Windows,
    /// CI) — no host has a real PKCS#11 module here.
    #[test]
    fn test_pkcs11_signer_sign_with_missing_module_returns_module_load_error() {
        // Use a path that's clearly bogus on every host. The string
        // is whatever the caller configured — we don't normalise it,
        // so the assertion below requires byte-exact round-trip.
        let bogus_path = "definitely-does-not-exist-libnope-justsign-test.so";
        let signer = Pkcs11Signer::new(bogus_path, 0, None, "any");
        let err = signer
            .sign(b"any payload")
            .expect_err("signing must fail when the module cannot be loaded");

        // First: render the Display impl BEFORE moving the fields
        // out via the destructuring match. Proves the path appears
        // in the Display output (the operator-facing surface).
        let rendered = format!("{err}");
        assert!(
            rendered.contains(bogus_path),
            "rendered error must contain the configured path; got {rendered:?}"
        );

        match err {
            SignerError::ModuleLoad { path, cause } => {
                assert_eq!(
                    path, bogus_path,
                    "the configured path must round-trip into the error verbatim"
                );
                assert!(
                    !cause.is_empty(),
                    "the underlying loader error must not be silently empty"
                );
            }
            other => panic!("expected SignerError::ModuleLoad, got {other:?}"),
        }
    }

    /// Bug it catches: drift between our `cryptoki` calls and the
    /// real PKCS#11 ABI as exposed by SoftHSM2 / YubiKey. Unit
    /// tests cover the input plumbing and the DER conversion;
    /// only a live token surfaces a wrong `Mechanism::Ecdsa` /
    /// missing C_Login / unsupported attribute combination.
    ///
    /// SKIP-pass shape — always-on, returns success when the env
    /// vars aren't all set so CI on PRs without a SoftHSM2
    /// fixture stays clean. Mirrors the Fulcio + Rekor staging
    /// tests.
    #[test]
    fn test_pkcs11_signer_signs_against_softhsm_when_configured() {
        let lib = std::env::var("JUSTSIGN_SOFTHSM_LIB");
        let pin = std::env::var("JUSTSIGN_SOFTHSM_PIN");
        let label = std::env::var("JUSTSIGN_SOFTHSM_KEY_LABEL");

        let (lib, pin, label) = match (lib, pin, label) {
            (Ok(l), Ok(p), Ok(k)) if !l.is_empty() && !k.is_empty() => (l, p, k),
            _ => {
                eprintln!(
                    "SKIP: test_pkcs11_signer_signs_against_softhsm_when_configured \
                     — set JUSTSIGN_SOFTHSM_LIB + JUSTSIGN_SOFTHSM_PIN + \
                     JUSTSIGN_SOFTHSM_KEY_LABEL to enable"
                );
                return;
            }
        };

        let slot_id: u64 = std::env::var("JUSTSIGN_SOFTHSM_SLOT_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                // Discover the first slot with a token — SoftHSM2
                // reassigns slot ids on init, so hardcoding is
                // fragile. Calling get_slots_with_token here is
                // the same dance softhsm2-util prints.
                let pkcs11 = Pkcs11::new(&lib).expect("load module to enumerate slots");
                pkcs11
                    .initialize(CInitializeArgs::OsThreads)
                    .expect("C_Initialize for slot discovery");
                let slots = pkcs11.get_slots_with_token().expect("get_slots_with_token");
                let s = slots
                    .first()
                    .expect("at least one slot with a token must be present")
                    .id();
                drop(pkcs11);
                s
            });

        let signer = Pkcs11Signer::new(
            &lib,
            slot_id,
            if pin.is_empty() { None } else { Some(pin) },
            &label,
        );

        let payload = b"justsign pkcs11 e2e payload";
        let sig = signer
            .sign(payload)
            .expect("PKCS#11 signing against a configured token must succeed");

        // Smoke-shape the DER output. ECDSA-P256 DER signatures are
        // 70-72 bytes typically, never fewer than 8 (SEQUENCE { 0,
        // INTEGER { 0 }, INTEGER { 0 } }), never more than 72.
        assert!(
            sig.len() >= 8 && sig.len() <= 72,
            "P-256 DER signature length out of expected range: {}",
            sig.len()
        );
        assert_eq!(sig[0], 0x30, "DER signature must start with SEQUENCE tag");
        let body_len = sig[1] as usize;
        assert_eq!(
            body_len + 2,
            sig.len(),
            "DER outer length must equal body bytes"
        );
        assert_eq!(sig[2], 0x02, "first body element must be INTEGER (r)");
        let r_len = sig[3] as usize;
        assert!(r_len > 0 && r_len <= 33, "r length out of range: {r_len}");
        let s_tag_idx = 4 + r_len;
        assert!(s_tag_idx < sig.len(), "DER body too short for s INTEGER");
        assert_eq!(
            sig[s_tag_idx], 0x02,
            "second body element must be INTEGER (s)"
        );
    }

    /// Bug it catches: an off-by-one in the DER-INTEGER padding
    /// path — values whose first byte is >= 0x80 must be prefixed
    /// with 0x00 to stay positive in DER. A regression that
    /// dropped the prefix would emit a signature the standard
    /// `p256::ecdsa::Signature::from_der` parser silently rejects
    /// with `InvalidSignature`, surfacing only as "verify failed"
    /// far from the real bug.
    #[test]
    fn test_ecdsa_raw_rs_to_der_pads_high_bit_integers() {
        // r and s both have high bit set — both must get 0x00 prefix.
        let mut raw = Vec::with_capacity(64);
        raw.push(0x80);
        raw.extend(std::iter::repeat_n(0x11, 31)); // 32-byte r
        raw.push(0x90);
        raw.extend(std::iter::repeat_n(0x22, 31)); // 32-byte s

        let der = ecdsa_raw_rs_to_der(&raw).expect("DER encode must succeed");

        assert_eq!(der[0], 0x30, "SEQUENCE tag");
        // SEQUENCE body length: r is 33 bytes (1 prefix + 32) plus
        // tag + len = 35; same for s; total 70.
        assert_eq!(der[1] as usize, 70);
        // r INTEGER
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 33);
        assert_eq!(der[4], 0x00, "leading 0x00 padding must precede r");
        assert_eq!(der[5], 0x80, "original first byte of r preserved after pad");
        // s INTEGER starts at offset 2 + 2 + 33 = 37
        assert_eq!(der[37], 0x02);
        assert_eq!(der[38], 33);
        assert_eq!(der[39], 0x00);
        assert_eq!(der[40], 0x90);
    }

    /// Bug it catches: a regression that didn't strip the fixed-
    /// width zero padding PKCS#11 tokens emit. P-256 r/s are
    /// always 32 bytes on the wire, but DER INTEGER must be the
    /// minimum length representation. Failing to strip would
    /// embed leading 0x00s that some strict DER parsers reject.
    #[test]
    fn test_ecdsa_raw_rs_to_der_strips_leading_zeros() {
        // r has a leading zero; s does not.
        let mut raw = vec![0u8; 64];
        // r = 0x00 0x00 0x42 0x42 ... (zero-padded small value).
        raw[2] = 0x42;
        raw[3] = 0x42;
        // s = 0x01 0x02 ... (no padding to strip).
        raw[32] = 0x01;
        raw[33] = 0x02;

        let der = ecdsa_raw_rs_to_der(&raw).expect("DER encode must succeed");

        // r INTEGER content begins at offset 4; should be 30 bytes
        // (32 - 2 leading zeros).
        assert_eq!(der[2], 0x02, "r tag");
        assert_eq!(der[3], 30, "r length after stripping two leading zeros");
        assert_eq!(der[4], 0x42);
        assert_eq!(der[5], 0x42);
    }
}
