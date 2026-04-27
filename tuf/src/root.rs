//! Root metadata parser + threshold-signature verifier.
//!
//! See crate-level docs for v0 scope and constraints.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
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

        // v0: Ed25519 only. ECDSA roots get a typed error so the
        // caller can route on it (e.g. fall back to a future v1
        // verifier path).
        if key.keytype != "ed25519" || key.scheme != "ed25519" {
            return Err(TufError::UnsupportedKeyType {
                keytype: key.keytype.clone(),
                scheme: key.scheme.clone(),
            });
        }

        let pk_bytes =
            hex::decode(&key.keyval.public).map_err(|e| TufError::BadSignatureFormat {
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

        if verifying_key.verify(signed_bytes, &signature).is_ok() {
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

    /// Negative: ECDSA keys are explicitly rejected in v0 with a
    /// typed error.
    ///
    /// Bug it catches: silently treating an ECDSA key as ed25519
    /// (wrong byte length → BadSignatureFormat) would mask the real
    /// "this is the wrong algorithm" issue. Distinct typed error
    /// lets the caller route on it.
    #[test]
    fn test_verify_role_ecdsa_keytype_rejected_with_unsupported_error() {
        let (mut root, signed, _sks) = build_test_root(1, 1);
        let key = root.keys.get_mut("k0").unwrap();
        key.keytype = "ecdsa-sha2-nistp256".into();
        key.scheme = "ecdsa-sha2-nistp256".into();

        // Provide a syntactically-plausible (but irrelevant) sig so
        // the verifier reaches the keytype check.
        let fake_sig = Signature {
            keyid: "k0".into(),
            sig: hex::encode([0u8; 64]),
        };
        let err = verify_self_signed(&root, &signed, &[fake_sig]).unwrap_err();
        assert!(
            matches!(err, TufError::UnsupportedKeyType { .. }),
            "got {err:?}"
        );
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
}
