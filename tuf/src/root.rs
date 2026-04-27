//! Root metadata parser + threshold-signature verifier.
//!
//! See crate-level docs for v0 scope and constraints.

use std::collections::{BTreeMap, BTreeSet};

// `Verifier` is the `signature::Verifier` trait re-exported by both
// `ed25519_dalek` and `p256::ecdsa::signature`. Importing it through
// `ed25519_dalek` brings the trait into scope for ALL VerifyingKey
// types in this module (Ed25519 + ECDSA P-256), since `signature`
// is a single trait crate that both algorithm crates re-export
// from. A second `use p256::ecdsa::signature::Verifier as _` would
// be redundant and triggers a `unused_imports` warning.
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};

/// Opaque key identifier — TUF uses lowercase hex of a hash over the
/// canonical-JSON form of the public key, but v0 treats it as a
/// string and never re-derives it.
pub type KeyId = String;

/// Role name as it appears in `root.signed.roles` (`"root"`,
/// `"targets"`, `"snapshot"`, `"timestamp"`).
pub type RoleName = String;

/// Top-level TUF root metadata.
///
/// This is the `signed` portion of a `root.json` document — i.e. the
/// fields that signatures cover. Mirrors the TUF spec shape; unknown
/// fields are tolerated (see `serde(deny_unknown_fields = false)`
/// — the default — so future spec additions don't break parsing).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Root {
    /// `_type` in JSON — TUF uses a leading underscore to avoid
    /// colliding with reserved keywords in some target languages.
    /// For root metadata this is always the literal string `"root"`.
    #[serde(rename = "_type")]
    pub type_field: String,

    /// Specification version of the metadata format. Sigstore's
    /// current root is `"1.0.31"` at the time of writing. v0 stores
    /// it but does not act on it.
    #[serde(default)]
    pub spec_version: String,

    /// Monotonically-increasing version of *this* root document.
    /// Each rotation bumps this. v0 stores it but does not enforce
    /// monotonicity (no chained-root verification yet).
    pub version: u32,

    /// ISO 8601 expiry timestamp (e.g. `"2025-12-31T23:59:59Z"`).
    /// Stored as a string to avoid a `chrono` dep — v0 does not
    /// enforce expiry; see [`TufError::Expired`] for the typed error
    /// callers can produce themselves.
    pub expires: String,

    /// All keys referenced by any role, indexed by KeyId.
    pub keys: BTreeMap<KeyId, Key>,

    /// Per-role signing requirements (which keys, how many).
    pub roles: BTreeMap<RoleName, Role>,

    /// Whether targets metadata uses consistent-snapshot URIs. v0
    /// stores it for round-trip preservation; not acted on.
    #[serde(default)]
    pub consistent_snapshot: bool,
}

/// One public key entry in `root.signed.keys`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Key {
    /// Algorithm family. v0 accepts only `"ed25519"`.
    pub keytype: String,

    /// Signature scheme. v0 accepts only `"ed25519"`.
    pub scheme: String,

    /// Container for the actual public-key material.
    pub keyval: KeyVal,
}

/// Public-key material container.
///
/// For Ed25519 keys, `public` is a lowercase-hex encoding of the
/// 32-byte raw public key (TUF convention; not PEM, not DER, not
/// base64).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyVal {
    pub public: String,
}

/// Per-role signing requirements.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Role {
    /// Which key IDs may sign for this role.
    pub keyids: Vec<KeyId>,

    /// How many distinct `keyids` must produce a valid signature
    /// for the role to be considered satisfied. Always at least 1
    /// in well-formed metadata.
    pub threshold: u32,
}

/// One signature attached to a TUF metadata document.
///
/// In `root.json` these live in the top-level `signatures` array
/// (sibling of `signed`), NOT inside `signed`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Signature {
    /// KeyId of the key that produced this signature. Must be
    /// present in `Root::keys` for verification to succeed.
    pub keyid: KeyId,

    /// Lowercase-hex Ed25519 signature (64 bytes → 128 hex chars).
    pub sig: String,
}

/// Errors surfaced by parsing or verifying TUF root metadata.
#[derive(Debug, thiserror::Error)]
pub enum TufError {
    /// JSON shape did not match the expected `root.json` structure.
    #[error("root JSON parse: {0}")]
    Json(#[from] serde_json::Error),

    /// `root.signed.roles` did not contain the role we were asked
    /// to verify against.
    #[error("missing role: {role}")]
    MissingRole { role: String },

    /// A signature referenced a `keyid` not declared in
    /// `root.signed.keys`. Possibly a typo, possibly a forged
    /// signature attempting to bypass threshold checks.
    #[error("unknown keyid: {keyid}")]
    UnknownKeyId { keyid: KeyId },

    /// A signature, public key, or sig payload was not in the
    /// expected encoding (bad hex, wrong length, etc.).
    #[error("bad signature format: {detail}")]
    BadSignatureFormat { detail: String },

    /// Insufficient distinct-keyid valid signatures to meet the
    /// role's threshold.
    #[error("below threshold: required {required}, valid {valid}")]
    BelowThreshold { required: u32, valid: u32 },

    /// `keytype` or `scheme` is not one v0 supports (Ed25519 only).
    #[error("unsupported key type: keytype={keytype} scheme={scheme}")]
    UnsupportedKeyType { keytype: String, scheme: String },

    /// A role's `expires` field is in the past.
    ///
    /// Constructed by [`crate::client::TufClient`] after fetching a
    /// role and rendering "now" against the role's RFC 3339 expiry.
    /// `role` names which document is stale (`"root"`, `"timestamp"`,
    /// `"snapshot"`, `"targets"`) so the caller can route on it.
    #[error("metadata role {role} expired at {expires}")]
    Expired {
        /// The role whose `expires` field is in the past.
        role: String,
        /// The expiry timestamp the role declared.
        expires: String,
    },

    /// Canonical-JSON re-encode failed before signature verification.
    /// Surfaced when a fetched document has a structural shape the
    /// canonicaliser refuses (e.g. a float in a numeric field).
    #[error("canonicalisation: {0}")]
    Canonicalization(#[from] crate::canonical::CanonicalizationError),

    /// HTTP request failure when talking to the TUF mirror.
    #[error("tuf http: {0}")]
    Http(String),

    /// HTTP response indicated a non-success, non-404 status. 404 is
    /// surfaced separately via [`Self::NotFound`] because it is the
    /// expected sentinel that ends the chained-root walk.
    #[error("tuf http status {status}: {body}")]
    HttpStatus {
        /// HTTP status code returned by the mirror.
        status: u16,
        /// Truncated response body, for diagnostics.
        body: String,
    },

    /// HTTP 404 from the mirror. Used by the chained-root walker as
    /// the "no more versions" sentinel — not all 404s are errors
    /// from the caller's perspective.
    #[error("tuf http 404: {url}")]
    NotFound {
        /// URL that returned 404, surfaced for diagnostics.
        url: String,
    },

    /// Filesystem error reading or writing the on-disk metadata
    /// cache.
    #[error("tuf cache io: {0}")]
    Io(String),

    /// A role's hash digest did not match the digest its parent
    /// metadata declared. Examples:
    ///
    /// * `snapshot.json` SHA-256 != `timestamp.snapshot_meta.hashes.sha256`
    /// * `targets.json`  SHA-256 != `snapshot.targets_meta.hashes.sha256`
    ///
    /// The two-level pinning (timestamp pins snapshot, snapshot pins
    /// targets) is what TUF uses to defeat freshness attacks; a
    /// mismatch here means an attacker tried to pair a fresh upper
    /// role with a stale lower one.
    #[error("role {role} hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Which role's hash failed to cross-check.
        role: String,
        /// The digest the parent metadata declared (lowercase hex).
        expected: String,
        /// The digest we computed over the fetched bytes (lowercase
        /// hex).
        actual: String,
    },

    /// A required hash algorithm was missing from the parent's
    /// pointer. v0 only consumes SHA-256; an upstream metadata
    /// document that omits SHA-256 from its `hashes` map is
    /// considered malformed for our purposes.
    #[error("role {role} missing required hash algorithm sha256")]
    MissingHash {
        /// The role we couldn't cross-check.
        role: String,
    },

    /// A version monotonicity check failed during the chained-root
    /// walk: root N+1 must have `version > N`. Defends against an
    /// attacker downgrading the chain by serving an old root.json
    /// from a path the new chain still resolves to.
    #[error("root version regressed: previous {previous}, fetched {fetched}")]
    VersionRegression {
        /// Version of the previously-trusted root.
        previous: u32,
        /// Version of the freshly-fetched root that didn't advance.
        fetched: u32,
    },

    /// Expiry-string parse failure (typed error from
    /// [`crate::expiry::ExpiryParseError`]). Surfaced when a fetched
    /// document carries an `expires` field we can't compare to "now"
    /// — non-UTC offset, truncated, etc.
    #[error("expiry parse: {0}")]
    ExpiryParse(#[from] crate::expiry::ExpiryParseError),

    /// Span-preserving envelope parse failure (typed error from
    /// [`crate::span::SpanParseError`]). Surfaced when the fetched
    /// document is not a well-formed `{signed, signatures}` envelope
    /// or its typed body / signatures vector cannot be deserialised.
    /// Distinct from [`Self::Json`] so callers can distinguish a
    /// shape-level envelope problem from a generic JSON parse error
    /// inside an otherwise-well-formed envelope.
    #[error("envelope span parse: {0}")]
    SpanParse(#[from] crate::span::SpanParseError),

    /// The bundled (or caller-supplied) initial trust root has
    /// already expired relative to the system clock at the time
    /// [`crate::client::TufClient::with_initial_root_bytes`] was
    /// called. This is a different bug class from [`Self::Expired`]:
    /// `Expired` fires after fetching a fresh role from the mirror;
    /// `EmbeddedRootExpired` fires before any network traffic, on
    /// the bootstrap material itself. Distinct so operators can
    /// route on it -- typically the fix is "upgrade justsign" (the
    /// bundled root is stale) or "supply a fresh root via
    /// `with_initial_root_bytes`" (the override path for air-gapped
    /// deploys).
    #[error(
        "embedded TUF trust root has expired: expires_at={expired_at}, now={now_iso8601}; {hint}"
    )]
    EmbeddedRootExpired {
        /// The `signed.expires` timestamp the embedded root declared.
        expired_at: String,
        /// The current time, rendered as RFC 3339 UTC-Z, for the
        /// operator to confirm the system clock is correct.
        now_iso8601: String,
        /// Actionable hint -- usually "upgrade justsign or pass a
        /// fresh root via TufClient::with_initial_root_bytes()".
        hint: String,
    },
}

/// Verify that `signatures` satisfies the named role's threshold
/// over the exact `signed_bytes` the caller supplies.
///
/// `signed_bytes` MUST be the byte sequence the original signers
/// hashed (TUF specifies OLPC canonical JSON of the `signed`
/// object). v0 treats it as opaque — the caller is responsible for
/// producing canonical bytes if interoperating with live metadata;
/// for synthesised tests, the caller controls both sides.
///
/// Verification rules:
///
/// 1. Each `Signature.keyid` must exist in `root.keys`.
/// 2. The named role must exist in `root.roles`, and each accepted
///    signature's `keyid` must be in that role's `keyids` list.
/// 3. Each accepted signature must validate as Ed25519 over
///    `signed_bytes` against the key's hex-decoded public bytes.
/// 4. Distinct-keyid valid signatures must be >= `role.threshold`.
///
/// Duplicate signatures by the same keyid count once: TUF's
/// threshold semantics are over distinct keys, not over signature
/// entries. A malicious signer could otherwise pad the signatures
/// array with the same keyid + sig to fake a threshold.
pub fn verify_role(
    root: &Root,
    role_name: &str,
    signed_bytes: &[u8],
    signatures: &[Signature],
) -> Result<(), TufError> {
    let role = root
        .roles
        .get(role_name)
        .ok_or_else(|| TufError::MissingRole {
            role: role_name.to_string(),
        })?;

    let allowed: BTreeSet<&str> = role.keyids.iter().map(|s| s.as_str()).collect();
    let mut valid_keyids: BTreeSet<&str> = BTreeSet::new();

    for sig in signatures {
        // Skip signatures whose keyid is not authorised for this
        // role — they aren't an error per se (the same `signatures`
        // array is shared across all roles in some TUF documents),
        // they just don't contribute to the threshold count.
        if !allowed.contains(sig.keyid.as_str()) {
            continue;
        }

        // Already counted this keyid — ignore duplicates.
        if valid_keyids.contains(sig.keyid.as_str()) {
            continue;
        }

        let key = root
            .keys
            .get(&sig.keyid)
            .ok_or_else(|| TufError::UnknownKeyId {
                keyid: sig.keyid.clone(),
            })?;

        // Algorithm dispatch. We route on `scheme` because that is
        // the field the TUF spec ties to the verification algorithm
        // (`keytype` is more of a key-family label and varies between
        // producers: python-tuf emits `keytype = "ecdsa-sha2-nistp256"`
        // for the same scheme that Sigstore's tuf-on-ci tooling
        // labels `keytype = "ecdsa"`). Each known scheme gets its
        // own arm; unknown schemes surface a typed error rather than
        // silently falling through to the Ed25519 path.
        let verified = match key.scheme.as_str() {
            "ed25519" => verify_ed25519(key, sig, signed_bytes)?,
            "ecdsa-sha2-nistp256" => verify_ecdsa_p256(key, sig, signed_bytes)?,
            _ => {
                return Err(TufError::UnsupportedKeyType {
                    keytype: key.keytype.clone(),
                    scheme: key.scheme.clone(),
                });
            }
        };

        if verified {
            valid_keyids.insert(sig.keyid.as_str());
        }
        // Bad signature bytes that are syntactically valid (right
        // length, hex-decoded) but don't verify simply don't count
        // — they're not an error, they just don't contribute. This
        // matches how TUF clients tolerate stale signatures during
        // a key rotation window.
    }

    let valid = valid_keyids.len() as u32;
    if valid >= role.threshold {
        Ok(())
    } else {
        Err(TufError::BelowThreshold {
            required: role.threshold,
            valid,
        })
    }
}

/// Run the Ed25519 verify path for one `(key, signature)` pair.
///
/// Returns `Ok(true)` on a syntactically-valid signature that passes
/// verification, `Ok(false)` on a syntactically-valid signature that
/// fails verification (does not count toward threshold but is not a
/// hard error — matches TUF's tolerance of stale-key sigs during
/// rotation), and `Err` on a structurally-broken sig/key (bad hex,
/// wrong length, malformed key bytes).
fn verify_ed25519(key: &Key, sig: &Signature, signed_bytes: &[u8]) -> Result<bool, TufError> {
    let pk_bytes = hex::decode(&key.keyval.public).map_err(|e| TufError::BadSignatureFormat {
        detail: format!("public key hex decode: {e}"),
    })?;
    let pk_array: [u8; 32] =
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| TufError::BadSignatureFormat {
                detail: format!(
                    "ed25519 public key must be 32 bytes, got {}",
                    pk_bytes.len()
                ),
            })?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_array).map_err(|e| TufError::BadSignatureFormat {
            detail: format!("ed25519 public key invalid: {e}"),
        })?;

    let sig_bytes = hex::decode(&sig.sig).map_err(|e| TufError::BadSignatureFormat {
        detail: format!("signature hex decode: {e}"),
    })?;
    let sig_array: [u8; 64] =
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| TufError::BadSignatureFormat {
                detail: format!(
                    "ed25519 signature must be 64 bytes, got {}",
                    sig_bytes.len()
                ),
            })?;
    let signature = Ed25519Signature::from_bytes(&sig_array);
    Ok(verifying_key.verify(signed_bytes, &signature).is_ok())
}

/// Run the ECDSA-P256-SHA256 verify path for one `(key, signature)`
/// pair.
///
/// Wire format expected:
///
/// * `key.keyval.public` is either:
///   1. A PEM-encoded `SubjectPublicKeyInfo` (`-----BEGIN PUBLIC KEY-----`
///      ... `-----END PUBLIC KEY-----`). This is what Sigstore's
///      tuf-on-ci tooling emits, and what the bundled v14
///      production root carries (`keytype = "ecdsa"`,
///      `scheme = "ecdsa-sha2-nistp256"`).
///   2. A lowercase-hex SEC1 elliptic-curve point (typically the
///      uncompressed `0x04 || X || Y` 65-byte form). This is what
///      newer python-tuf metadata uses when it writes
///      `keytype = "ecdsa-sha2-nistp256"`.
///
/// We try (1) first because it's the format the load-bearing
/// bundled root uses; if (1) fails to parse we fall back to (2)
/// so this verifier is interoperable with both major TUF
/// producers.
///
/// * `sig.sig` is a lowercase-hex DER-encoded `ECDSA-Sig-Value`
///   (a SEQUENCE of two INTEGERs). Per the TUF spec ECDSA-SHA256
///   signs over the canonical `signed` bytes; the `p256` crate's
///   `signature::Verifier::verify(msg, &sig)` impl hashes `msg`
///   with SHA-256 internally and verifies the digest, so we hand
///   it the raw `signed_bytes` directly — NOT a pre-computed
///   digest.
///
/// Same return-value contract as [`verify_ed25519`].
fn verify_ecdsa_p256(key: &Key, sig: &Signature, signed_bytes: &[u8]) -> Result<bool, TufError> {
    let public = key.keyval.public.trim();

    // (1) PEM SubjectPublicKeyInfo path — Sigstore tuf-on-ci shape.
    let verifying_key = if public.starts_with("-----BEGIN") {
        P256VerifyingKey::from_public_key_pem(public).map_err(|e| TufError::BadSignatureFormat {
            detail: format!("ecdsa-p256 PEM SPKI public key invalid: {e}"),
        })?
    } else {
        // (2) Hex SEC1 point path — python-tuf shape. We require
        // ASCII hex (TUF convention is lowercase, but `hex::decode`
        // is case-insensitive — we tolerate both since the wire is
        // not under our control).
        let pk_bytes = hex::decode(public).map_err(|e| TufError::BadSignatureFormat {
            detail: format!("ecdsa-p256 SEC1 public key hex decode: {e}"),
        })?;
        P256VerifyingKey::from_sec1_bytes(&pk_bytes).map_err(|e| TufError::BadSignatureFormat {
            detail: format!("ecdsa-p256 SEC1 public key invalid: {e}"),
        })?
    };

    // The TUF wire form for ECDSA signatures is hex-encoded DER. An
    // empty `sig` string is a real shape we see on the wire (an
    // unprovisioned signer in a multi-signer root role) -- treat
    // it as "this signer didn't contribute" rather than "the
    // entire document is malformed", same way an incorrect sig
    // doesn't bubble out of `verify_role`. Only structural-format
    // errors (bad hex, malformed DER) bubble.
    if sig.sig.is_empty() {
        return Ok(false);
    }

    let sig_bytes = hex::decode(&sig.sig).map_err(|e| TufError::BadSignatureFormat {
        detail: format!("ecdsa-p256 signature hex decode: {e}"),
    })?;
    let signature =
        P256Signature::from_der(&sig_bytes).map_err(|e| TufError::BadSignatureFormat {
            detail: format!("ecdsa-p256 DER signature parse: {e}"),
        })?;

    Ok(verifying_key.verify(signed_bytes, &signature).is_ok())
}

/// Convenience: verify a `root.json` is self-signed by the keys
/// declared in its own `roles.root` to threshold.
///
/// Equivalent to `verify_role(root, "root", signed_bytes, signatures)`,
/// kept as a named entry-point because "root self-signs to threshold"
/// is the canonical TUF trust-establishment check.
pub fn verify_self_signed(
    root: &Root,
    signed_bytes: &[u8],
    signatures: &[Signature],
) -> Result<(), TufError> {
    verify_role(root, "root", signed_bytes, signatures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use serde_json::json;

    /// Build a `Root` with `n` Ed25519 keys, threshold `t`, returning
    /// the parsed Root, the canonical `signed` bytes (just
    /// `serde_json::to_vec` of the signed object — fine for tests
    /// because we control both sides), and the signing keys.
    ///
    /// We deliberately do NOT compute TUF-style keyids (sha256 over
    /// canonical-JSON public-key) — synthetic test keyids `"k0"`,
    /// `"k1"`, … suffice for verifying threshold logic.
    fn build_test_root(n: usize, threshold: u32) -> (Root, Vec<u8>, Vec<SigningKey>) {
        let mut rng = OsRng;
        let signing_keys: Vec<SigningKey> =
            (0..n).map(|_| SigningKey::generate(&mut rng)).collect();

        let mut keys = BTreeMap::new();
        let mut keyids = Vec::new();
        for (i, sk) in signing_keys.iter().enumerate() {
            let keyid = format!("k{i}");
            keyids.push(keyid.clone());
            let pk_hex = hex::encode(sk.verifying_key().to_bytes());
            keys.insert(
                keyid,
                Key {
                    keytype: "ed25519".into(),
                    scheme: "ed25519".into(),
                    keyval: KeyVal { public: pk_hex },
                },
            );
        }

        let mut roles = BTreeMap::new();
        roles.insert(
            "root".into(),
            Role {
                keyids: keyids.clone(),
                threshold,
            },
        );

        let root = Root {
            type_field: "root".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-01-01T00:00:00Z".into(),
            keys,
            roles,
            consistent_snapshot: true,
        };

        // We use serde_json's default serialisation as the "canonical"
        // form *for tests only*. The crate-level docs flag this as a
        // v0 limitation; v1 needs OLPC canonical JSON for live
        // metadata.
        let signed_bytes = serde_json::to_vec(&root).unwrap();
        (root, signed_bytes, signing_keys)
    }

    fn sign_with(sk: &SigningKey, keyid: &str, msg: &[u8]) -> Signature {
        let sig = sk.sign(msg);
        Signature {
            keyid: keyid.to_string(),
            sig: hex::encode(sig.to_bytes()),
        }
    }

    /// Smoke: a 1-of-1 self-signed root verifies cleanly.
    ///
    /// Bug it catches: any wiring break between `verify_role` and
    /// the ed25519 verify path — wrong byte slicing, wrong key
    /// decoding, wrong signature decoding.
    #[test]
    fn test_verify_role_one_of_one_well_formed_signature_succeeds() {
        let (root, signed, sks) = build_test_root(1, 1);
        let sig = sign_with(&sks[0], "k0", &signed);
        verify_self_signed(&root, &signed, &[sig]).unwrap();
    }

    /// Negative: tampering one byte of a signature flips verification
    /// to BelowThreshold (no valid sigs against required 1).
    ///
    /// Bug it catches: a verifier that swallows ed25519's verify
    /// failure and counts the signature anyway — would let any
    /// random 64 bytes pass as a valid signature.
    #[test]
    fn test_verify_role_tampered_signature_byte_returns_below_threshold() {
        let (root, signed, sks) = build_test_root(1, 1);
        let mut sig = sign_with(&sks[0], "k0", &signed);
        // Flip one byte in the hex-encoded signature.
        let mut bytes = hex::decode(&sig.sig).unwrap();
        bytes[0] ^= 0xFF;
        sig.sig = hex::encode(bytes);

        let err = verify_self_signed(&root, &signed, &[sig]).unwrap_err();
        assert!(
            matches!(
                err,
                TufError::BelowThreshold {
                    required: 1,
                    valid: 0
                }
            ),
            "got {err:?}"
        );
    }

    /// Negative: a 2-of-3 root with only one valid sig drops below
    /// threshold and surfaces the exact required/valid counts.
    ///
    /// Bug it catches: an off-by-one in the threshold comparison
    /// (`>` vs `>=`) — would either fail the 2-of-2 case (false
    /// negative) or pass this 1-of-3 case (false positive).
    #[test]
    fn test_verify_role_two_of_three_with_one_valid_returns_below_threshold() {
        let (root, signed, sks) = build_test_root(3, 2);
        let sig0 = sign_with(&sks[0], "k0", &signed);
        let err = verify_self_signed(&root, &signed, &[sig0]).unwrap_err();
        match err {
            TufError::BelowThreshold { required, valid } => {
                assert_eq!(required, 2);
                assert_eq!(valid, 1);
            }
            other => panic!("expected BelowThreshold, got {other:?}"),
        }
    }

    /// Positive: a 2-of-3 root with exactly two valid sigs meets
    /// threshold.
    #[test]
    fn test_verify_role_two_of_three_with_two_valid_succeeds() {
        let (root, signed, sks) = build_test_root(3, 2);
        let sig0 = sign_with(&sks[0], "k0", &signed);
        let sig2 = sign_with(&sks[2], "k2", &signed);
        verify_self_signed(&root, &signed, &[sig0, sig2]).unwrap();
    }

    /// Negative: same keyid signing twice does NOT count as two
    /// signatures toward threshold.
    ///
    /// Bug it catches: a verifier that counts signature *entries*
    /// rather than distinct keyids — would let a single signer
    /// fake a 2-of-3 by sending the same sig twice.
    #[test]
    fn test_verify_role_duplicate_keyid_signatures_count_once_below_threshold() {
        let (root, signed, sks) = build_test_root(3, 2);
        let sig_a = sign_with(&sks[0], "k0", &signed);
        let sig_b = sign_with(&sks[0], "k0", &signed); // same key, same msg, identical sig
        let err = verify_self_signed(&root, &signed, &[sig_a, sig_b]).unwrap_err();
        assert!(
            matches!(
                err,
                TufError::BelowThreshold {
                    required: 2,
                    valid: 1
                }
            ),
            "got {err:?}"
        );
    }

    /// Negative: a signature whose keyid is not authorised for the
    /// role does not contribute to the threshold count.
    ///
    /// Bug it catches: an authorisation bypass where a key declared
    /// for a different role (e.g. timestamp) gets accepted toward
    /// the root threshold.
    #[test]
    fn test_verify_role_signature_with_unauthorised_keyid_is_ignored() {
        let (mut root, signed, sks) = build_test_root(2, 1);
        // Restrict the root role to only k0; k1 is a "stranger" key
        // present in `keys` but not in `roles.root.keyids`.
        root.roles.get_mut("root").unwrap().keyids = vec!["k0".into()];

        let stranger_sig = sign_with(&sks[1], "k1", &signed);
        let err = verify_self_signed(&root, &signed, &[stranger_sig]).unwrap_err();
        assert!(
            matches!(
                err,
                TufError::BelowThreshold {
                    required: 1,
                    valid: 0
                }
            ),
            "got {err:?}"
        );
    }

    /// Negative: asking for a role the document doesn't define
    /// surfaces MissingRole, not a panic.
    ///
    /// Bug it catches: an `unwrap()` on the role lookup would panic
    /// in production whenever a verifier asked about a role absent
    /// from a partial-test fixture.
    #[test]
    fn test_verify_role_missing_role_returns_typed_missing_role_error() {
        let (root, signed, _sks) = build_test_root(1, 1);
        let err = verify_role(&root, "snapshot", &signed, &[]).unwrap_err();
        match err {
            TufError::MissingRole { role } => assert_eq!(role, "snapshot"),
            other => panic!("expected MissingRole, got {other:?}"),
        }
    }

    /// Negative: a `scheme` value the verifier does not implement
    /// (e.g. `"rsassa-pss-sha256"`) surfaces a typed
    /// `UnsupportedKeyType` error rather than silently falling
    /// through to one of the supported algorithms.
    ///
    /// Bug it catches: a dispatch that uses `if scheme == "ed25519"
    /// { ... } else { ecdsa path }` would route an unknown scheme to
    /// the ECDSA arm and surface a less-actionable
    /// BadSignatureFormat. The match-with-explicit-default-arm
    /// shape forces every unknown scheme to the typed error.
    #[test]
    fn test_verify_role_unknown_scheme_returns_unsupported_key_type() {
        let (mut root, signed, _sks) = build_test_root(1, 1);
        let key = root.keys.get_mut("k0").unwrap();
        key.keytype = "rsa".into();
        key.scheme = "rsassa-pss-sha256".into();

        // Provide a syntactically-plausible (but irrelevant) sig so
        // the verifier reaches the scheme dispatch.
        let fake_sig = Signature {
            keyid: "k0".into(),
            sig: hex::encode([0u8; 64]),
        };
        let err = verify_self_signed(&root, &signed, &[fake_sig]).unwrap_err();
        match err {
            TufError::UnsupportedKeyType { keytype, scheme } => {
                assert_eq!(keytype, "rsa");
                assert_eq!(scheme, "rsassa-pss-sha256");
            }
            other => panic!("expected UnsupportedKeyType, got {other:?}"),
        }
    }

    /// Negative: signature whose keyid is allowed for the role but
    /// is not declared anywhere in `root.keys` surfaces UnknownKeyId.
    ///
    /// Bug it catches: a verifier that didn't cross-check role
    /// keyids against the keys map would fail with a less
    /// actionable error (or worse, panic on an `unwrap`).
    #[test]
    fn test_verify_role_keyid_in_role_but_missing_from_keys_returns_unknown_keyid() {
        let (mut root, signed, sks) = build_test_root(1, 1);
        // Add a phantom keyid to the role's allowed list, but DO NOT
        // add a Key entry for it — simulates a malformed root.
        root.roles
            .get_mut("root")
            .unwrap()
            .keyids
            .push("phantom".into());
        let phantom_sig = sign_with(&sks[0], "phantom", &signed);

        let err = verify_self_signed(&root, &signed, &[phantom_sig]).unwrap_err();
        match err {
            TufError::UnknownKeyId { keyid } => assert_eq!(keyid, "phantom"),
            other => panic!("expected UnknownKeyId, got {other:?}"),
        }
    }

    /// Negative: malformed signature hex surfaces BadSignatureFormat.
    ///
    /// Bug it catches: any unwrap on the hex decode path would
    /// panic on a malformed `root.json` from a hostile source.
    #[test]
    fn test_verify_role_non_hex_signature_returns_bad_signature_format() {
        let (root, signed, _sks) = build_test_root(1, 1);
        let bad_sig = Signature {
            keyid: "k0".into(),
            sig: "not-hex-at-all".into(),
        };
        let err = verify_self_signed(&root, &signed, &[bad_sig]).unwrap_err();
        assert!(
            matches!(err, TufError::BadSignatureFormat { .. }),
            "got {err:?}"
        );
    }

    /// Negative: signature with correct hex but wrong byte length
    /// (Ed25519 sigs are exactly 64 bytes) surfaces
    /// BadSignatureFormat.
    ///
    /// Bug it catches: feeding a too-short byte slice straight into
    /// `Signature::from_bytes` would panic in older dalek versions;
    /// in 2.x the API takes `&[u8; 64]`, so we must validate length
    /// before constructing. This test enforces that path stays.
    #[test]
    fn test_verify_role_wrong_length_signature_returns_bad_signature_format() {
        let (root, signed, _sks) = build_test_root(1, 1);
        let bad_sig = Signature {
            keyid: "k0".into(),
            sig: hex::encode([0u8; 32]), // half-length
        };
        let err = verify_self_signed(&root, &signed, &[bad_sig]).unwrap_err();
        assert!(
            matches!(err, TufError::BadSignatureFormat { .. }),
            "got {err:?}"
        );
    }

    /// Parse a hand-rolled `root.json` shape end-to-end: the JSON
    /// view → typed Root, then check the typed view round-trips
    /// the threshold + keyids.
    ///
    /// Bug it catches: a serde rename mismatch (`_type` vs `type`,
    /// `keyval` vs `key_val`) would silently produce default
    /// values, breaking verification later with confusing errors.
    #[test]
    fn test_root_parse_from_json_preserves_structural_fields() {
        let doc = json!({
            "_type": "root",
            "spec_version": "1.0.31",
            "version": 7,
            "expires": "2030-01-01T00:00:00Z",
            "keys": {
                "abc": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": { "public": "00".repeat(32) }
                }
            },
            "roles": {
                "root":      { "keyids": ["abc"], "threshold": 1 },
                "snapshot":  { "keyids": ["abc"], "threshold": 1 },
                "targets":   { "keyids": ["abc"], "threshold": 1 },
                "timestamp": { "keyids": ["abc"], "threshold": 1 }
            },
            "consistent_snapshot": true
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        let root: Root = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(root.type_field, "root");
        assert_eq!(root.version, 7);
        assert_eq!(root.roles.get("root").unwrap().threshold, 1);
        assert_eq!(root.roles.get("root").unwrap().keyids, vec!["abc"]);
        assert!(root.consistent_snapshot);
    }

    /// `serde_json::Error` flows through the `?` operator into
    /// `TufError::Json` so callers can route on it.
    ///
    /// We exercise the conversion by parsing junk bytes via
    /// `serde_json::from_slice::<Root>` and then converting the
    /// resulting error into `TufError`. This guards against
    /// dropping the `#[from]` attribute by mistake.
    #[test]
    fn test_tuf_error_from_serde_json_error_preserves_variant() {
        let bad_json = b"not json";
        let serde_err = serde_json::from_slice::<Root>(bad_json).unwrap_err();
        let tuf_err: TufError = serde_err.into();
        assert!(matches!(tuf_err, TufError::Json(_)), "got {tuf_err:?}");
    }

    // ----- ECDSA P-256 dispatch (issue #37) -----------------------

    /// Build a 1-of-1 root whose sole key is an ECDSA P-256 key
    /// supplied by the caller, with the given keytype/scheme labels
    /// and `keyval.public` text. Returns the parsed Root and the
    /// (synthesised) `signed` bytes. Mirrors `build_test_root` for
    /// the ECDSA case but lets each test pick its own wire shape so
    /// we can exercise both the PEM SPKI and the hex SEC1 paths.
    fn build_ecdsa_root(
        keyid: &str,
        keytype: &str,
        scheme: &str,
        public_str: String,
    ) -> (Root, Vec<u8>) {
        let mut keys = BTreeMap::new();
        keys.insert(
            keyid.to_string(),
            Key {
                keytype: keytype.to_string(),
                scheme: scheme.to_string(),
                keyval: KeyVal { public: public_str },
            },
        );
        let mut roles = BTreeMap::new();
        roles.insert(
            "root".into(),
            Role {
                keyids: vec![keyid.to_string()],
                threshold: 1,
            },
        );
        let root = Root {
            type_field: "root".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-01-01T00:00:00Z".into(),
            keys,
            roles,
            consistent_snapshot: true,
        };
        let signed_bytes = serde_json::to_vec(&root).unwrap();
        (root, signed_bytes)
    }

    /// Smoke: existing Ed25519 path is untouched by the ECDSA
    /// dispatch refactor.
    ///
    /// Bug it catches: a refactor that accidentally changed the
    /// Ed25519 verify path while adding ECDSA support — for
    /// example, swapping the `verify_ed25519` helper's return
    /// semantics from "Ok(true) on verify, Ok(false) on bad sig"
    /// to "Err on bad sig" would silently break threshold-tolerance
    /// of stale-key signatures during rotation.
    #[test]
    fn test_verify_role_ed25519_path_still_works_after_ecdsa_refactor() {
        let (root, signed, sks) = build_test_root(1, 1);
        let sig = sign_with(&sks[0], "k0", &signed);
        verify_self_signed(&root, &signed, &[sig]).unwrap();
    }

    /// Positive: an ECDSA P-256 signature over the exact signed
    /// bytes verifies cleanly when the public key is shipped as
    /// PEM-encoded SubjectPublicKeyInfo (the Sigstore tuf-on-ci
    /// shape used by the bundled v14 production root).
    ///
    /// Bug it catches: a verifier that only handled the hex SEC1
    /// public-key shape would reject the bundled root entirely;
    /// this test pins the PEM SPKI parsing path that
    /// `from_public_key_pem` opens up.
    #[test]
    fn test_verify_role_ecdsa_p256_pem_spki_valid_signature_accepted() {
        use p256::ecdsa::signature::Signer as _;
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let mut rng = rand_core::OsRng;
        let sk = SigningKey::random(&mut rng);
        let vk = sk.verifying_key();
        let pem = vk.to_public_key_pem(LineEnding::LF).unwrap();

        let (root, signed) = build_ecdsa_root("k0", "ecdsa", "ecdsa-sha2-nistp256", pem);
        let sig: P256Signature = sk.sign(&signed);
        let sig_hex = hex::encode(sig.to_der().as_bytes());
        let sig = Signature {
            keyid: "k0".into(),
            sig: sig_hex,
        };
        verify_self_signed(&root, &signed, &[sig]).unwrap();
    }

    /// Positive: an ECDSA P-256 signature verifies when the public
    /// key is shipped as a hex-encoded SEC1 uncompressed point (the
    /// python-tuf `keytype = "ecdsa-sha2-nistp256"` shape).
    ///
    /// Bug it catches: a verifier that only handled the PEM SPKI
    /// shape would reject any non-Sigstore TUF root that uses the
    /// python-tuf wire format. This test pins the hex SEC1 path
    /// that `from_sec1_bytes` opens up.
    #[test]
    fn test_verify_role_ecdsa_p256_hex_sec1_valid_signature_accepted() {
        use p256::ecdsa::signature::Signer as _;
        use p256::ecdsa::SigningKey;

        let mut rng = rand_core::OsRng;
        let sk = SigningKey::random(&mut rng);
        let vk = sk.verifying_key();
        // Uncompressed SEC1 form: 0x04 || X || Y, 65 bytes.
        let sec1_hex = hex::encode(vk.to_encoded_point(false).as_bytes());

        let (root, signed) =
            build_ecdsa_root("k0", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256", sec1_hex);
        let sig: P256Signature = sk.sign(&signed);
        let sig_hex = hex::encode(sig.to_der().as_bytes());
        let sig = Signature {
            keyid: "k0".into(),
            sig: sig_hex,
        };
        verify_self_signed(&root, &signed, &[sig]).unwrap();
    }

    /// Negative: an ECDSA P-256 signature over payload A is
    /// rejected when the verifier is asked to check it against
    /// payload B (one byte changed). Verifies that the SHA-256
    /// pre-hash inside `signature::Verifier::verify` actually feeds
    /// the supplied `signed_bytes` into the hash, not some
    /// constant.
    ///
    /// Bug it catches: a verifier that fed the wrong byte slice to
    /// `vk.verify` (e.g. accidentally hashed the role name, or an
    /// empty slice) would accept any signature regardless of
    /// payload.
    #[test]
    fn test_verify_role_ecdsa_p256_tampered_payload_rejected() {
        use p256::ecdsa::signature::Signer as _;
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let mut rng = rand_core::OsRng;
        let sk = SigningKey::random(&mut rng);
        let pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();

        let (root, signed) = build_ecdsa_root("k0", "ecdsa", "ecdsa-sha2-nistp256", pem);
        let sig: P256Signature = sk.sign(&signed);
        let sig_hex = hex::encode(sig.to_der().as_bytes());

        // Tamper the payload AFTER signing -- the signature is over
        // `signed`, but we hand the verifier `tampered`.
        let mut tampered = signed.clone();
        tampered[0] ^= 0xFF;

        let sig = Signature {
            keyid: "k0".into(),
            sig: sig_hex,
        };
        let err = verify_self_signed(&root, &tampered, &[sig]).unwrap_err();
        assert!(
            matches!(
                err,
                TufError::BelowThreshold {
                    required: 1,
                    valid: 0
                }
            ),
            "got {err:?}"
        );
    }

    /// Negative: a signature produced by ECDSA keypair A is
    /// rejected when the role declares ECDSA keypair B's public
    /// key.
    ///
    /// Bug it catches: a verifier that ignored the public key and
    /// only checked sig structural validity would let a signer
    /// without role authority pass the threshold.
    #[test]
    fn test_verify_role_ecdsa_p256_signature_from_wrong_key_rejected() {
        use p256::ecdsa::signature::Signer as _;
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let mut rng = rand_core::OsRng;
        let signer_a = SigningKey::random(&mut rng);
        let signer_b = SigningKey::random(&mut rng);

        // Root authorises only signer_b's public key.
        let pem_b = signer_b
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let (root, signed) = build_ecdsa_root("k0", "ecdsa", "ecdsa-sha2-nistp256", pem_b);

        // But the supplied signature came from signer_a.
        let sig: P256Signature = signer_a.sign(&signed);
        let sig_hex = hex::encode(sig.to_der().as_bytes());
        let sig = Signature {
            keyid: "k0".into(),
            sig: sig_hex,
        };
        let err = verify_self_signed(&root, &signed, &[sig]).unwrap_err();
        assert!(
            matches!(
                err,
                TufError::BelowThreshold {
                    required: 1,
                    valid: 0
                }
            ),
            "got {err:?}"
        );
    }

    /// Positive: a 2-of-2 root with one Ed25519 signer + one ECDSA
    /// P-256 signer succeeds when both contribute valid signatures.
    /// Confirms the per-key dispatch in `verify_role` honours
    /// each entry's own `scheme` rather than picking one for the
    /// whole role.
    ///
    /// Bug it catches: a verifier that snapshotted the first key's
    /// scheme and applied it to every signature would either reject
    /// every ECDSA sig (if Ed25519 was first) or reject every
    /// Ed25519 sig (if ECDSA was first).
    #[test]
    fn test_verify_role_mixed_threshold_with_ed25519_and_ecdsa_p256_succeeds() {
        use ed25519_dalek::SigningKey as Ed25519SigningKey;
        use p256::ecdsa::signature::Signer as P256Signer;
        use p256::ecdsa::SigningKey as P256SigningKey;
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let mut rng = rand_core::OsRng;
        let ed_sk = Ed25519SigningKey::generate(&mut rng);
        let ec_sk = P256SigningKey::random(&mut rng);
        let ec_pem = ec_sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();

        let mut keys = BTreeMap::new();
        keys.insert(
            "ed".into(),
            Key {
                keytype: "ed25519".into(),
                scheme: "ed25519".into(),
                keyval: KeyVal {
                    public: hex::encode(ed_sk.verifying_key().to_bytes()),
                },
            },
        );
        keys.insert(
            "ec".into(),
            Key {
                keytype: "ecdsa".into(),
                scheme: "ecdsa-sha2-nistp256".into(),
                keyval: KeyVal { public: ec_pem },
            },
        );
        let mut roles = BTreeMap::new();
        roles.insert(
            "root".into(),
            Role {
                keyids: vec!["ed".into(), "ec".into()],
                threshold: 2,
            },
        );
        let root = Root {
            type_field: "root".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-01-01T00:00:00Z".into(),
            keys,
            roles,
            consistent_snapshot: true,
        };
        let signed = serde_json::to_vec(&root).unwrap();

        let ed_sig_bytes = ed_sk.sign(&signed).to_bytes();
        let ed_sig = Signature {
            keyid: "ed".into(),
            sig: hex::encode(ed_sig_bytes),
        };
        let ec_sig_value: P256Signature = ec_sk.sign(&signed);
        let ec_sig = Signature {
            keyid: "ec".into(),
            sig: hex::encode(ec_sig_value.to_der().as_bytes()),
        };
        verify_self_signed(&root, &signed, &[ed_sig, ec_sig]).unwrap();
    }

    /// Negative: same mixed 2-of-2 root, but the ECDSA signature
    /// is structurally valid DER over the wrong payload — only the
    /// Ed25519 signer contributes, falling below threshold.
    ///
    /// Bug it catches: a verifier that bailed out on the first
    /// algorithm-mismatch rather than counting per-key would
    /// either fail-open (accept the bad ECDSA sig) or fail-closed
    /// in the wrong place (return UnsupportedKeyType because of
    /// the keytype label rather than BelowThreshold because of the
    /// invalid sig). We want the threshold-arithmetic answer here.
    #[test]
    fn test_verify_role_mixed_threshold_with_one_invalid_ecdsa_sig_below_threshold() {
        use ed25519_dalek::SigningKey as Ed25519SigningKey;
        use p256::ecdsa::signature::Signer as P256Signer;
        use p256::ecdsa::SigningKey as P256SigningKey;
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let mut rng = rand_core::OsRng;
        let ed_sk = Ed25519SigningKey::generate(&mut rng);
        let ec_sk = P256SigningKey::random(&mut rng);
        let ec_pem = ec_sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();

        let mut keys = BTreeMap::new();
        keys.insert(
            "ed".into(),
            Key {
                keytype: "ed25519".into(),
                scheme: "ed25519".into(),
                keyval: KeyVal {
                    public: hex::encode(ed_sk.verifying_key().to_bytes()),
                },
            },
        );
        keys.insert(
            "ec".into(),
            Key {
                keytype: "ecdsa".into(),
                scheme: "ecdsa-sha2-nistp256".into(),
                keyval: KeyVal { public: ec_pem },
            },
        );
        let mut roles = BTreeMap::new();
        roles.insert(
            "root".into(),
            Role {
                keyids: vec!["ed".into(), "ec".into()],
                threshold: 2,
            },
        );
        let root = Root {
            type_field: "root".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-01-01T00:00:00Z".into(),
            keys,
            roles,
            consistent_snapshot: true,
        };
        let signed = serde_json::to_vec(&root).unwrap();

        let ed_sig_bytes = ed_sk.sign(&signed).to_bytes();
        let ed_sig = Signature {
            keyid: "ed".into(),
            sig: hex::encode(ed_sig_bytes),
        };
        // ECDSA sig over a different message -- structurally valid
        // DER, but won't verify against `signed`.
        let ec_sig_value: P256Signature = ec_sk.sign(b"a different payload");
        let ec_sig = Signature {
            keyid: "ec".into(),
            sig: hex::encode(ec_sig_value.to_der().as_bytes()),
        };
        let err = verify_self_signed(&root, &signed, &[ed_sig, ec_sig]).unwrap_err();
        assert!(
            matches!(
                err,
                TufError::BelowThreshold {
                    required: 2,
                    valid: 1
                }
            ),
            "got {err:?}"
        );
    }

    /// Negative: an empty `sig` string on an ECDSA-scheme key
    /// (which appears in real Sigstore root v14 metadata for an
    /// unprovisioned signer slot) does not contribute to threshold,
    /// but ALSO does not bubble out as a hard parse error.
    ///
    /// Bug it catches: an `is_empty` check accidentally placed
    /// after the hex-decode would fail every empty sig with
    /// BadSignatureFormat ("hex decode of empty string"). The
    /// wire-format reality of multi-signer root metadata makes
    /// silent-skip the right answer for this specific shape.
    #[test]
    fn test_verify_role_ecdsa_p256_empty_sig_is_silently_skipped() {
        use p256::ecdsa::signature::Signer as _;
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let mut rng = rand_core::OsRng;
        let sk_a = SigningKey::random(&mut rng);
        let sk_b = SigningKey::random(&mut rng);

        let mut keys = BTreeMap::new();
        keys.insert(
            "a".into(),
            Key {
                keytype: "ecdsa".into(),
                scheme: "ecdsa-sha2-nistp256".into(),
                keyval: KeyVal {
                    public: sk_a
                        .verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .unwrap(),
                },
            },
        );
        keys.insert(
            "b".into(),
            Key {
                keytype: "ecdsa".into(),
                scheme: "ecdsa-sha2-nistp256".into(),
                keyval: KeyVal {
                    public: sk_b
                        .verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .unwrap(),
                },
            },
        );
        let mut roles = BTreeMap::new();
        roles.insert(
            "root".into(),
            Role {
                keyids: vec!["a".into(), "b".into()],
                threshold: 1,
            },
        );
        let root = Root {
            type_field: "root".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-01-01T00:00:00Z".into(),
            keys,
            roles,
            consistent_snapshot: true,
        };
        let signed = serde_json::to_vec(&root).unwrap();

        // `a` contributes a real signature; `b` carries an empty
        // sig string (the unprovisioned-signer shape we see on the
        // Sigstore production root). Threshold 1 must be met by
        // `a` alone.
        let real_sig: P256Signature = sk_a.sign(&signed);
        let real = Signature {
            keyid: "a".into(),
            sig: hex::encode(real_sig.to_der().as_bytes()),
        };
        let empty = Signature {
            keyid: "b".into(),
            sig: "".into(),
        };
        verify_self_signed(&root, &signed, &[real, empty]).unwrap();
    }

    /// LOAD-BEARING: the bundled Sigstore production root v14
    /// (`tuf/assets/sigstore_prod.root.json`, ECDSA P-256, 5 keys,
    /// threshold 3) self-verifies against the canonical-JSON form
    /// of its `signed` object.
    ///
    /// This is the test issue #37 was filed to make pass. If it
    /// fails, the bundled asset is non-functional: any
    /// `TufClient::sigstore()` caller will surface
    /// `TufError::BelowThreshold` (or worse, an algorithm error)
    /// on the very first chain-walk step, blocking every keyless
    /// verification flow that depends on a Sigstore root of trust.
    ///
    /// Bug it catches: a regression where the verifier's ECDSA
    /// wire-shape expectations drift from what Sigstore's
    /// tuf-on-ci tooling emits — e.g. expecting hex SEC1 instead
    /// of PEM SPKI, or refusing `keytype = "ecdsa"` because the
    /// TUF spec uses `"ecdsa-sha2-nistp256"`. The wire bytes for
    /// the bundled root are pretty-printed with two-space indent
    /// (NOT pre-canonicalised), so we re-canonicalise via the
    /// approach-(a) [`crate::canonical::canonicalize`] path before
    /// handing bytes to the verifier; this matches what the
    /// production chain walk does for non-pre-canonicalised wire
    /// payloads.
    #[test]
    fn test_verify_role_against_bundled_sigstore_v14_self_signature() {
        let bytes = crate::embedded::SIGSTORE_PRODUCTION_ROOT_BYTES;
        let envelope: serde_json::Value =
            serde_json::from_slice(bytes).expect("bundled root parses as JSON");
        let signed_value = envelope
            .get("signed")
            .cloned()
            .expect("envelope has `signed`");
        let signatures: Vec<Signature> = serde_json::from_value(
            envelope
                .get("signatures")
                .cloned()
                .expect("envelope has `signatures`"),
        )
        .expect("signatures vector deserialises");
        let canonical_bytes =
            crate::canonical::canonicalize(&signed_value).expect("bundled signed canonicalises");
        let root: Root = serde_json::from_value(signed_value).expect("signed deserialises as Root");
        verify_role(&root, "root", &canonical_bytes, &signatures).expect(
            "bundled Sigstore production root v14 must self-verify against \
             its own canonical-JSON `signed` form; if this assertion fires, \
             the embedded asset is malformed or the verifier's ECDSA \
             wire-shape expectations have drifted",
        );
    }
}
