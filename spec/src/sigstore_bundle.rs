//! Sigstore bundle v0.3 — JSON-serialised form.
//!
//! Reference: <https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto>
//!
//! A Sigstore bundle is the all-in-one verification artifact: the
//! signature (either a DSSE envelope OR a raw message signature) +
//! the verification material (Fulcio cert chain, Rekor inclusion
//! proofs/promises) needed to verify it offline against a trust root.
//!
//! Wire shape (JSON):
//!
//! ```json
//! {
//!   "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
//!   "verificationMaterial": {
//!     "x509CertificateChain": {
//!       "certificates": [ { "rawBytes": "<base64 DER>" }, ... ]
//!     },
//!     "tlogEntries": [ ... ]
//!   },
//!   "dsseEnvelope":      { ... }   // exactly one of dsseEnvelope OR
//!   "messageSignature":  { ... }   // messageSignature is set
//! }
//! ```
//!
//! Per the protobuf spec, `dsse_envelope` and `message_signature` are
//! a `oneof` — exactly one MUST be set. The cert material is also a
//! `oneof` between `x509CertificateChain` (chain) and `certificate`
//! (single `X509Certificate`); we pin `encode_json` to emit the chain
//! shape and accept either on decode for cosign-legacy compat.
//! Bundles that set both arms are rejected.
//!
//! We do NOT parse X.509 certs (held as raw DER `Vec<u8>`) and we do
//! NOT verify Merkle inclusion proofs — that's
//! `swe_justsign_sign` / `swe_justsign_rekor`'s job. This module is
//! pure wire shape + base64 transcoding.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::dsse::Envelope;

/// Canonical media type for v0.3 bundles. Verifiers should refuse
/// bundles whose `media_type` doesn't start with the
/// `application/vnd.dev.sigstore.bundle+json` prefix; we expose the
/// constant so callers can do that check without typoing the string.
pub const SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE: &str =
    "application/vnd.dev.sigstore.bundle+json;version=0.3";

/// Decoded Sigstore bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// Media type — typically [`SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE`].
    /// Held as a `String` (not a typed enum) because Sigstore has
    /// shipped multiple versions and we want to surface the raw
    /// value to callers so they can decide whether to accept it.
    pub media_type: String,

    /// Trust material needed to verify the signature offline.
    pub verification_material: VerificationMaterial,

    /// Content: exactly one of `dsse_envelope` or `message_signature`
    /// is `Some`. The decoder rejects bundles that violate this.
    pub content: BundleContent,
}

/// Bundle content variant — the protobuf `oneof` discriminator.
///
/// The protobuf spec models this as a oneof; we model it as an enum
/// to make the "exactly one" invariant a type-level guarantee. The
/// decoder still has to enforce it on the wire, but downstream code
/// pattern-matching on `BundleContent` can't accidentally read the
/// wrong arm or both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleContent {
    /// DSSE envelope (in-toto attestations, most cosign sign-blob).
    DsseEnvelope(Envelope),

    /// Raw message signature over a hashed payload (cosign
    /// sign-blob without DSSE wrapping).
    MessageSignature(MessageSignature),
}

/// Trust material — what the verifier needs to bind the signature to
/// a Fulcio identity and a Rekor entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationMaterial {
    /// X.509 certificate chain in DER form (leaf first, then
    /// intermediates). v0 holds the bytes only — parsing happens in
    /// `swe_justsign_sign`.
    pub certificate: Option<Certificate>,

    /// Rekor transparency-log entries proving the signature was
    /// recorded. Empty in offline-only flows; required in standard
    /// Sigstore policy.
    pub tlog_entries: Vec<TlogEntry>,

    /// RFC3161 timestamp authority responses, when present.
    /// **Deferred to a later slice** — the v0 decoder accepts the
    /// field on the wire but doesn't parse it into typed entries.
    /// Held here as opaque bytes so a round-trip preserves them.
    pub timestamp_verification_data: Option<TimestampVerificationData>,
}

/// X.509 cert chain — leaf is index 0.
///
/// We store DER bytes verbatim. Decoding/parsing into structured
/// fields (subject, SAN, validity) is `swe_justsign_sign`'s job so
/// this crate stays IO-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// One DER-encoded cert per `Vec<u8>`. The Sigstore wire format
    /// puts the leaf cert first; intermediates follow.
    pub certificates: Vec<Vec<u8>>,
}

/// `oneof` placeholder for v0 — see field-level docs on
/// `VerificationMaterial::timestamp_verification_data`.
///
/// Held as `serde_json::Value` so we round-trip whatever the wire
/// said without committing to a shape we'll regret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampVerificationData {
    pub raw: serde_json::Value,
}

/// Message signature variant of bundle content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSignature {
    /// Hash of the signed message.
    pub message_digest: HashOutput,

    /// Raw signature bytes — algorithm is implied by the cert's
    /// public key.
    pub signature: Vec<u8>,
}

/// Algorithm-tagged hash output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashOutput {
    /// Hash algorithm name. Sigstore uses the protobuf
    /// `HashAlgorithm` enum names — `"SHA2_256"`, `"SHA2_512"`. We
    /// hold it as a string for forward compat with future algos.
    pub algorithm: String,

    /// Raw hash bytes.
    pub digest: Vec<u8>,
}

/// One Rekor transparency-log entry.
///
/// We deliberately omit `canonicalized_body` (which Rekor returns
/// alongside the entry): for v0 it's redundant with the bundle's own
/// envelope/signature, and storing it doubles the bundle size for no
/// new information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlogEntry {
    /// Sequential index in the Rekor log.
    pub log_index: i64,

    /// Hash of the Rekor instance's public key — identifies which
    /// log this entry came from.
    pub log_id: HashOutput,

    /// Rekor entry kind + version (e.g.
    /// `kind = "intoto"`, `version = "0.0.2"`).
    pub kind_version: KindVersion,

    /// Wall-clock time the entry was integrated, seconds since
    /// Unix epoch. Set by Rekor, not the signer.
    pub integrated_time: i64,

    /// Promise from Rekor to integrate the entry (signed before the
    /// entry actually lands in a published checkpoint). Either the
    /// promise or the proof — typically both — must be present for a
    /// bundle to be verifiable.
    pub inclusion_promise: Option<InclusionPromise>,

    /// Merkle inclusion proof against a published checkpoint. Built
    /// once the entry is canonicalized into the log.
    pub inclusion_proof: Option<InclusionProof>,
}

/// Rekor entry kind + version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindVersion {
    /// e.g. `"intoto"`, `"hashedrekord"`, `"dsse"`.
    pub kind: String,

    /// Per-kind version, e.g. `"0.0.2"`.
    pub version: String,
}

/// Signed Entry Timestamp — Rekor's promise to integrate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionPromise {
    /// Rekor's signature over the canonicalized entry.
    pub signed_entry_timestamp: Vec<u8>,
}

/// Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Index of the leaf this proof is for.
    pub log_index: i64,

    /// Merkle root the proof terminates at.
    pub root_hash: Vec<u8>,

    /// Tree size at the time of proof generation.
    pub tree_size: i64,

    /// Sibling hashes from leaf up to root.
    pub hashes: Vec<Vec<u8>>,

    /// Signed checkpoint binding `root_hash` + `tree_size` to a
    /// Rekor signature.
    pub checkpoint: Checkpoint,
}

/// Signed Rekor checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Newline-delimited checkpoint envelope (note format) — held
    /// as a string because Rekor emits it as text, not bytes.
    pub envelope: String,
}

impl Bundle {
    /// Decode a bundle from its canonical JSON form.
    ///
    /// Enforces the `oneof` invariant: exactly one of `dsseEnvelope`
    /// or `messageSignature` MUST be set. Bundles violating this are
    /// rejected with a typed error rather than silently dropping
    /// one arm.
    pub fn decode_json(buf: &[u8]) -> Result<Self, BundleDecodeError> {
        let wire: BundleWire = serde_json::from_slice(buf)?;

        let content = match (wire.dsse_envelope, wire.message_signature) {
            (Some(_), Some(_)) => return Err(BundleDecodeError::BothContentVariantsSet),
            (None, None) => return Err(BundleDecodeError::NoContentVariantSet),
            (Some(env_wire), None) => {
                // Reuse DSSE envelope decode — but the bundle wire
                // shape nests the envelope as a JSON object, not as
                // a string blob. Re-serialise the inner object and
                // hand it to Envelope::decode_json so all base64
                // handling stays in one place.
                let inner = serde_json::to_vec(&env_wire)
                    .map_err(BundleDecodeError::DsseEnvelopeReSerialise)?;
                let envelope = Envelope::decode_json(&inner)
                    .map_err(|e| BundleDecodeError::DsseEnvelope(e.to_string()))?;
                BundleContent::DsseEnvelope(envelope)
            }
            (None, Some(ms_wire)) => {
                let signature = STANDARD.decode(ms_wire.signature.as_bytes()).map_err(|e| {
                    BundleDecodeError::MessageSignatureBase64 {
                        detail: e.to_string(),
                    }
                })?;
                let digest = STANDARD
                    .decode(ms_wire.message_digest.digest.as_bytes())
                    .map_err(|e| BundleDecodeError::MessageDigestBase64 {
                        detail: e.to_string(),
                    })?;
                BundleContent::MessageSignature(MessageSignature {
                    message_digest: HashOutput {
                        algorithm: ms_wire.message_digest.algorithm,
                        digest,
                    },
                    signature,
                })
            }
        };

        // Cert chain decode accepts BOTH wire shapes per
        // protobuf-specs sigstore_bundle.proto's
        // `VerificationMaterial.content` oneof:
        //
        // * Canonical (what we emit): `x509CertificateChain` ─ the
        //   multi-cert wrapper. Field is at proto number 2; the JSON
        //   key is camelCase per protobuf-JSON convention. Holds an
        //   ordered `certificates` array of `X509Certificate
        //   { rawBytes }`. Leaf at index 0, intermediates after.
        //
        // * Legacy / cosign sign-blob path: `certificate` ─ a SINGLE
        //   `X509Certificate { rawBytes }` (proto field 5). Cosign 2.x
        //   for sign-blob without a chain emits this. We lift it into
        //   a one-element `Vec<Vec<u8>>` so the in-memory model stays
        //   chain-shaped regardless of which wire arm we read.
        //
        // Bundles populating BOTH arms are rejected: the protobuf
        // `oneof` guarantees exactly one is set, and accepting both
        // would mask a producer bug.
        //
        // The legacy `certificate` arm is a v0 compat layer. Plan to
        // remove it in v0.2.0 once downstream consumers (justoci,
        // justsign-cli) all emit the canonical chain shape and the
        // wider Sigstore ecosystem has migrated. Until then, silent
        // acceptance avoids breaking real cosign-signed artifacts.
        let certificate = match (
            wire.verification_material.x509_certificate_chain,
            wire.verification_material.certificate,
        ) {
            (Some(_), Some(_)) => {
                return Err(BundleDecodeError::BothCertificateShapesSet);
            }
            (None, None) => None,
            (Some(chain_wire), None) => {
                let mut certs = Vec::with_capacity(chain_wire.certificates.len());
                for c in chain_wire.certificates {
                    let der = STANDARD.decode(c.raw_bytes.as_bytes()).map_err(|e| {
                        BundleDecodeError::CertificateBase64 {
                            detail: e.to_string(),
                        }
                    })?;
                    certs.push(der);
                }
                Some(Certificate {
                    certificates: certs,
                })
            }
            (None, Some(single_wire)) => {
                let der = STANDARD
                    .decode(single_wire.raw_bytes.as_bytes())
                    .map_err(|e| BundleDecodeError::CertificateBase64 {
                        detail: e.to_string(),
                    })?;
                Some(Certificate {
                    certificates: vec![der],
                })
            }
        };

        let mut tlog_entries = Vec::with_capacity(wire.verification_material.tlog_entries.len());
        for te in wire.verification_material.tlog_entries {
            tlog_entries.push(decode_tlog_entry(te)?);
        }

        Ok(Bundle {
            media_type: wire.media_type,
            verification_material: VerificationMaterial {
                certificate,
                tlog_entries,
                timestamp_verification_data: wire
                    .verification_material
                    .timestamp_verification_data
                    .map(|raw| TimestampVerificationData { raw }),
            },
            content,
        })
    }

    /// Encode a bundle to its canonical JSON form.
    pub fn encode_json(&self) -> Result<Vec<u8>, BundleEncodeError> {
        let (dsse_envelope, message_signature) = match &self.content {
            BundleContent::DsseEnvelope(env) => {
                // Ask the DSSE module to encode, then re-parse so we
                // can nest it as an object (not a string) in the
                // bundle wire shape.
                let env_bytes = env
                    .encode_json()
                    .map_err(|e| BundleEncodeError::DsseEnvelope(e.to_string()))?;
                let env_wire: DsseEnvelopeWire = serde_json::from_slice(&env_bytes)
                    .map_err(BundleEncodeError::DsseEnvelopeReParse)?;
                (Some(env_wire), None)
            }
            BundleContent::MessageSignature(ms) => {
                let ms_wire = MessageSignatureWire {
                    message_digest: HashOutputWire {
                        algorithm: ms.message_digest.algorithm.clone(),
                        digest: STANDARD.encode(&ms.message_digest.digest),
                    },
                    signature: STANDARD.encode(&ms.signature),
                };
                (None, Some(ms_wire))
            }
        };

        // Encoder emits the canonical `x509CertificateChain` shape.
        // See decoder comment for the rationale; in short, this is the
        // protobuf-JSON encoding of `X509CertificateChain` (proto field
        // 2 of the `VerificationMaterial.content` oneof) and is the
        // only protobuf-canonical shape that can hold an ordered chain
        // (leaf-first) in a single field.
        //
        // We emit `None` (i.e. omit the field entirely under
        // `skip_serializing_if = "Option::is_none"`) when the in-memory
        // chain is absent. We do NOT emit an empty chain object: a
        // bundle with `x509CertificateChain.certificates: []` would
        // pass schema validation but be useless to a verifier, so
        // signaling absence at the field level is honest.
        let x509_certificate_chain =
            self.verification_material
                .certificate
                .as_ref()
                .map(|cert| X509CertificateChainWire {
                    certificates: cert
                        .certificates
                        .iter()
                        .map(|der| RawBytesWire {
                            raw_bytes: STANDARD.encode(der),
                        })
                        .collect(),
                });

        let tlog_entries = self
            .verification_material
            .tlog_entries
            .iter()
            .map(encode_tlog_entry)
            .collect();

        let wire = BundleWire {
            media_type: self.media_type.clone(),
            verification_material: VerificationMaterialWire {
                x509_certificate_chain,
                certificate: None,
                tlog_entries,
                timestamp_verification_data: self
                    .verification_material
                    .timestamp_verification_data
                    .as_ref()
                    .map(|t| t.raw.clone()),
            },
            dsse_envelope,
            message_signature,
        };

        let bytes = serde_json::to_vec(&wire)?;
        Ok(bytes)
    }
}

fn decode_tlog_entry(wire: TlogEntryWire) -> Result<TlogEntry, BundleDecodeError> {
    let log_id_digest = STANDARD
        .decode(wire.log_id.digest.as_bytes())
        .map_err(|e| BundleDecodeError::LogIdBase64 {
            detail: e.to_string(),
        })?;

    let inclusion_promise = match wire.inclusion_promise {
        None => None,
        Some(p) => {
            let bytes = STANDARD
                .decode(p.signed_entry_timestamp.as_bytes())
                .map_err(|e| BundleDecodeError::SetBase64 {
                    detail: e.to_string(),
                })?;
            Some(InclusionPromise {
                signed_entry_timestamp: bytes,
            })
        }
    };

    let inclusion_proof =
        match wire.inclusion_proof {
            None => None,
            Some(p) => {
                let root_hash = STANDARD.decode(p.root_hash.as_bytes()).map_err(|e| {
                    BundleDecodeError::RootHashBase64 {
                        detail: e.to_string(),
                    }
                })?;
                let mut hashes = Vec::with_capacity(p.hashes.len());
                for h in p.hashes {
                    let bytes = STANDARD.decode(h.as_bytes()).map_err(|e| {
                        BundleDecodeError::ProofHashBase64 {
                            detail: e.to_string(),
                        }
                    })?;
                    hashes.push(bytes);
                }
                Some(InclusionProof {
                    log_index: p.log_index.parse().map_err(|_| {
                        BundleDecodeError::IntegerField {
                            field: "inclusionProof.logIndex",
                        }
                    })?,
                    root_hash,
                    tree_size: p.tree_size.parse().map_err(|_| {
                        BundleDecodeError::IntegerField {
                            field: "inclusionProof.treeSize",
                        }
                    })?,
                    hashes,
                    checkpoint: Checkpoint {
                        envelope: p.checkpoint.envelope,
                    },
                })
            }
        };

    Ok(TlogEntry {
        log_index: wire
            .log_index
            .parse()
            .map_err(|_| BundleDecodeError::IntegerField { field: "logIndex" })?,
        log_id: HashOutput {
            algorithm: wire.log_id.algorithm,
            digest: log_id_digest,
        },
        kind_version: KindVersion {
            kind: wire.kind_version.kind,
            version: wire.kind_version.version,
        },
        integrated_time: wire.integrated_time.parse().map_err(|_| {
            BundleDecodeError::IntegerField {
                field: "integratedTime",
            }
        })?,
        inclusion_promise,
        inclusion_proof,
    })
}

fn encode_tlog_entry(te: &TlogEntry) -> TlogEntryWire {
    TlogEntryWire {
        log_index: te.log_index.to_string(),
        log_id: HashOutputWire {
            algorithm: te.log_id.algorithm.clone(),
            digest: STANDARD.encode(&te.log_id.digest),
        },
        kind_version: KindVersionWire {
            kind: te.kind_version.kind.clone(),
            version: te.kind_version.version.clone(),
        },
        integrated_time: te.integrated_time.to_string(),
        inclusion_promise: te.inclusion_promise.as_ref().map(|p| InclusionPromiseWire {
            signed_entry_timestamp: STANDARD.encode(&p.signed_entry_timestamp),
        }),
        inclusion_proof: te.inclusion_proof.as_ref().map(|p| InclusionProofWire {
            log_index: p.log_index.to_string(),
            root_hash: STANDARD.encode(&p.root_hash),
            tree_size: p.tree_size.to_string(),
            hashes: p.hashes.iter().map(|h| STANDARD.encode(h)).collect(),
            checkpoint: CheckpointWire {
                envelope: p.checkpoint.envelope.clone(),
            },
        }),
    }
}

// ── JSON wire shapes (private). ─────────────────────────────────
//
// Sigstore uses string-encoded i64 for log_index / integrated_time /
// tree_size because JSON numbers can't safely round-trip 64-bit
// integers in JS clients. We mirror that on the wire and parse to
// i64 at the boundary.

#[derive(Deserialize, Serialize)]
struct BundleWire {
    #[serde(rename = "mediaType")]
    media_type: String,
    #[serde(rename = "verificationMaterial")]
    verification_material: VerificationMaterialWire,
    #[serde(rename = "dsseEnvelope", skip_serializing_if = "Option::is_none")]
    dsse_envelope: Option<DsseEnvelopeWire>,
    #[serde(rename = "messageSignature", skip_serializing_if = "Option::is_none")]
    message_signature: Option<MessageSignatureWire>,
}

#[derive(Deserialize, Serialize)]
struct VerificationMaterialWire {
    /// Canonical chain shape — protobuf-JSON encoding of
    /// `X509CertificateChain`. This is what `encode_json` emits.
    #[serde(
        rename = "x509CertificateChain",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    x509_certificate_chain: Option<X509CertificateChainWire>,

    /// Legacy single-cert shape — protobuf-JSON encoding of
    /// `X509Certificate`. v0 compat: cosign sign-blob without an
    /// explicit chain emits this. We never emit it (the field is
    /// hard-coded to `None` in the encoder). On decode, we lift it
    /// into a one-element chain. Plan to remove this arm in v0.2.0
    /// once the wider ecosystem has migrated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    certificate: Option<X509CertificateWire>,

    #[serde(rename = "tlogEntries", default)]
    tlog_entries: Vec<TlogEntryWire>,

    #[serde(
        rename = "timestampVerificationData",
        skip_serializing_if = "Option::is_none"
    )]
    timestamp_verification_data: Option<serde_json::Value>,
}

/// Wire shape for `X509CertificateChain` ─ a list of DER-encoded
/// certs in leaf-first order. Protobuf-JSON name on the wire is
/// `certificates` (camelCase by convention; lowercase here matches).
#[derive(Deserialize, Serialize)]
struct X509CertificateChainWire {
    certificates: Vec<RawBytesWire>,
}

/// Wire shape for `X509Certificate` ─ a single DER cert. Protobuf
/// field name is `raw_bytes`; protobuf-JSON converts to `rawBytes`.
#[derive(Deserialize, Serialize)]
struct X509CertificateWire {
    #[serde(rename = "rawBytes")]
    raw_bytes: String,
}

#[derive(Deserialize, Serialize)]
struct RawBytesWire {
    #[serde(rename = "rawBytes")]
    raw_bytes: String,
}

#[derive(Deserialize, Serialize)]
struct DsseEnvelopeWire {
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: String,
    signatures: Vec<DsseSignatureWire>,
}

#[derive(Deserialize, Serialize)]
struct DsseSignatureWire {
    #[serde(skip_serializing_if = "Option::is_none")]
    keyid: Option<String>,
    sig: String,
}

#[derive(Deserialize, Serialize)]
struct MessageSignatureWire {
    #[serde(rename = "messageDigest")]
    message_digest: HashOutputWire,
    signature: String,
}

#[derive(Deserialize, Serialize)]
struct HashOutputWire {
    algorithm: String,
    digest: String,
}

#[derive(Deserialize, Serialize)]
struct TlogEntryWire {
    #[serde(rename = "logIndex")]
    log_index: String,
    #[serde(rename = "logId")]
    log_id: HashOutputWire,
    #[serde(rename = "kindVersion")]
    kind_version: KindVersionWire,
    #[serde(rename = "integratedTime")]
    integrated_time: String,
    #[serde(rename = "inclusionPromise", skip_serializing_if = "Option::is_none")]
    inclusion_promise: Option<InclusionPromiseWire>,
    #[serde(rename = "inclusionProof", skip_serializing_if = "Option::is_none")]
    inclusion_proof: Option<InclusionProofWire>,
}

#[derive(Deserialize, Serialize)]
struct KindVersionWire {
    kind: String,
    version: String,
}

#[derive(Deserialize, Serialize)]
struct InclusionPromiseWire {
    #[serde(rename = "signedEntryTimestamp")]
    signed_entry_timestamp: String,
}

#[derive(Deserialize, Serialize)]
struct InclusionProofWire {
    #[serde(rename = "logIndex")]
    log_index: String,
    #[serde(rename = "rootHash")]
    root_hash: String,
    #[serde(rename = "treeSize")]
    tree_size: String,
    hashes: Vec<String>,
    checkpoint: CheckpointWire,
}

#[derive(Deserialize, Serialize)]
struct CheckpointWire {
    envelope: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleDecodeError {
    #[error("bundle JSON parse: {0}")]
    Json(#[from] serde_json::Error),

    #[error("bundle has BOTH dsseEnvelope AND messageSignature set; oneof requires exactly one")]
    BothContentVariantsSet,

    #[error(
        "bundle has NEITHER dsseEnvelope NOR messageSignature set; oneof requires exactly one"
    )]
    NoContentVariantSet,

    #[error("DSSE envelope decode: {0}")]
    DsseEnvelope(String),

    #[error("DSSE envelope re-serialise (internal): {0}")]
    DsseEnvelopeReSerialise(serde_json::Error),

    #[error("certificate base64 decode: {detail}")]
    CertificateBase64 { detail: String },

    #[error(
        "verificationMaterial has BOTH x509CertificateChain AND certificate set; \
         per protobuf-specs sigstore_bundle.proto these are arms of a oneof, \
         exactly one must be set"
    )]
    BothCertificateShapesSet,

    #[error("messageSignature.signature base64 decode: {detail}")]
    MessageSignatureBase64 { detail: String },

    #[error("messageSignature.messageDigest.digest base64 decode: {detail}")]
    MessageDigestBase64 { detail: String },

    #[error("tlogEntry.logId.digest base64 decode: {detail}")]
    LogIdBase64 { detail: String },

    #[error("inclusionPromise.signedEntryTimestamp base64 decode: {detail}")]
    SetBase64 { detail: String },

    #[error("inclusionProof.rootHash base64 decode: {detail}")]
    RootHashBase64 { detail: String },

    #[error("inclusionProof.hashes[*] base64 decode: {detail}")]
    ProofHashBase64 { detail: String },

    #[error("integer field {field} did not parse as i64")]
    IntegerField { field: &'static str },
}

#[derive(Debug, thiserror::Error)]
pub enum BundleEncodeError {
    #[error("bundle JSON serialise: {0}")]
    Json(#[from] serde_json::Error),

    #[error("DSSE envelope encode: {0}")]
    DsseEnvelope(String),

    #[error("DSSE envelope re-parse (internal): {0}")]
    DsseEnvelopeReParse(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsse::Signature;

    /// Build a plausible-shaped bundle with a DSSE envelope, full
    /// verification material, and an inclusion proof.
    fn fixture_dsse_bundle() -> Bundle {
        Bundle {
            media_type: SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE.to_string(),
            verification_material: VerificationMaterial {
                certificate: Some(Certificate {
                    certificates: vec![
                        // Synthesised "DER" — bytes don't have to be
                        // a real cert; we only round-trip them.
                        vec![0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD],
                        vec![0x30, 0x82, 0x02, 0x00, 0xBE, 0xEF],
                    ],
                }),
                tlog_entries: vec![TlogEntry {
                    log_index: 12345678,
                    log_id: HashOutput {
                        algorithm: "SHA2_256".to_string(),
                        digest: vec![0xAA; 32],
                    },
                    kind_version: KindVersion {
                        kind: "intoto".to_string(),
                        version: "0.0.2".to_string(),
                    },
                    integrated_time: 1_700_000_000,
                    inclusion_promise: Some(InclusionPromise {
                        signed_entry_timestamp: vec![0xBB; 64],
                    }),
                    inclusion_proof: Some(InclusionProof {
                        log_index: 12345678,
                        root_hash: vec![0xCC; 32],
                        tree_size: 99_999_999,
                        hashes: vec![vec![0xDD; 32], vec![0xEE; 32]],
                        checkpoint: Checkpoint {
                            envelope: "rekor.example\n99999999\nbase64root\n\n— rekor sig\n"
                                .to_string(),
                        },
                    }),
                }],
                timestamp_verification_data: None,
            },
            content: BundleContent::DsseEnvelope(Envelope {
                payload_type: "application/vnd.in-toto+json".to_string(),
                payload: b"{\"_type\":\"https://in-toto.io/Statement/v1\"}".to_vec(),
                signatures: vec![Signature {
                    keyid: None,
                    sig: vec![0x30, 0x45, 0x02, 0x21, 0xFF, 0xEE],
                }],
            }),
        }
    }

    fn fixture_message_signature_bundle() -> Bundle {
        Bundle {
            media_type: SIGSTORE_BUNDLE_V0_3_MEDIA_TYPE.to_string(),
            verification_material: VerificationMaterial {
                certificate: None,
                tlog_entries: vec![],
                timestamp_verification_data: None,
            },
            content: BundleContent::MessageSignature(MessageSignature {
                message_digest: HashOutput {
                    algorithm: "SHA2_256".to_string(),
                    digest: vec![0x11; 32],
                },
                signature: vec![0x22; 70],
            }),
        }
    }

    /// Encode → decode round-trip of a full DSSE bundle preserves
    /// every field — base64-encoded ones included.
    ///
    /// Bug it catches: any drift in the wire-key naming (camelCase
    /// in JSON, snake_case in Rust), or in the base64 round-trip
    /// for any of {cert DER, log id digest, SET bytes, root hash,
    /// proof hashes, signature bytes}, would surface as a
    /// re-decode mismatch on a single specific field.
    #[test]
    fn test_round_trip_full_dsse_bundle() {
        let original = fixture_dsse_bundle();
        let bytes = original.encode_json().unwrap();
        let decoded = Bundle::decode_json(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    /// Encode → decode of a message-signature bundle round-trips.
    #[test]
    fn test_round_trip_message_signature_bundle() {
        let original = fixture_message_signature_bundle();
        let bytes = original.encode_json().unwrap();
        let decoded = Bundle::decode_json(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    /// Bundle with BOTH dsseEnvelope AND messageSignature is
    /// rejected with a specific typed error.
    ///
    /// Bug it catches: a decoder that picked the first present arm
    /// silently would let a malicious signer attach a side-payload
    /// the verifier didn't check. The protobuf `oneof` is the
    /// security boundary; we enforce it on the JSON form too.
    #[test]
    fn test_decode_rejects_both_content_variants_set() {
        let json = br#"{
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "verificationMaterial": { "tlogEntries": [] },
            "dsseEnvelope": {
                "payloadType": "x",
                "payload": "",
                "signatures": [{ "sig": "MEUCIQ==" }]
            },
            "messageSignature": {
                "messageDigest": { "algorithm": "SHA2_256", "digest": "ESERESERESERESERESERESERESERESERESERESERESERESEREQ==" },
                "signature": "MEUCIQ=="
            }
        }"#;
        let err = Bundle::decode_json(json).unwrap_err();
        assert!(matches!(err, BundleDecodeError::BothContentVariantsSet));
    }

    /// Bundle with NEITHER variant set is rejected.
    ///
    /// Bug it catches: a decoder that synthesised an empty default
    /// envelope when both fields were absent would produce a
    /// "verifiable" bundle from nothing. Reject it loudly.
    #[test]
    fn test_decode_rejects_no_content_variant_set() {
        let json = br#"{
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "verificationMaterial": { "tlogEntries": [] }
        }"#;
        let err = Bundle::decode_json(json).unwrap_err();
        assert!(matches!(err, BundleDecodeError::NoContentVariantSet));
    }

    /// The wire form uses string-encoded integers for `logIndex`,
    /// `integratedTime`, `treeSize`. The encode path MUST emit
    /// strings (not raw JSON numbers) so JS clients reading the
    /// bundle don't lose precision on values > 2^53.
    ///
    /// Bug it catches: a wire shape that typed these as `i64`
    /// would emit `"logIndex": 12345678` instead of
    /// `"logIndex": "12345678"`, breaking interop with cosign/sigstore-js.
    #[test]
    fn test_encode_emits_string_encoded_integer_fields() {
        let bundle = fixture_dsse_bundle();
        let bytes = bundle.encode_json().unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(
            s.contains(r#""logIndex":"12345678""#),
            "logIndex must be string-encoded; got: {s}"
        );
        assert!(
            s.contains(r#""integratedTime":"1700000000""#),
            "integratedTime must be string-encoded; got: {s}"
        );
        assert!(
            s.contains(r#""treeSize":"99999999""#),
            "treeSize must be string-encoded; got: {s}"
        );
    }

    /// Cert chain base64 decode preserves DER bytes verbatim — no
    /// normalisation, no re-ordering, no de-duplication. The leaf
    /// MUST stay at index 0.
    ///
    /// Bug it catches: a decoder that sorted the cert chain (e.g.
    /// "intermediates first") would break verifiers that rely on
    /// position, and a leaf cert is what carries the SAN that
    /// Sigstore policy matches against.
    #[test]
    fn test_certificate_chain_preserves_order_and_bytes() {
        let original = fixture_dsse_bundle();
        let bytes = original.encode_json().unwrap();
        let decoded = Bundle::decode_json(&bytes).unwrap();
        let cert = decoded.verification_material.certificate.unwrap();
        assert_eq!(cert.certificates.len(), 2);
        assert_eq!(
            cert.certificates[0],
            vec![0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD]
        );
        assert_eq!(
            cert.certificates[1],
            vec![0x30, 0x82, 0x02, 0x00, 0xBE, 0xEF]
        );
    }

    /// Bundle with malformed base64 in the message signature surfaces
    /// as a typed error, not a panic.
    ///
    /// Bug it catches: an `unwrap()` on the base64 decode would let
    /// a malicious source crash the verifier with a truncated
    /// signature.
    #[test]
    fn test_decode_invalid_signature_base64_returns_typed_error() {
        let json = br#"{
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "verificationMaterial": { "tlogEntries": [] },
            "messageSignature": {
                "messageDigest": { "algorithm": "SHA2_256", "digest": "ESERESERESERESERESERESERESERESERESERESERESERESEREQ==" },
                "signature": "not valid base64!!"
            }
        }"#;
        let err = Bundle::decode_json(json).unwrap_err();
        assert!(matches!(
            err,
            BundleDecodeError::MessageSignatureBase64 { .. }
        ));
    }

    /// Inclusion proof `hashes` array preserves order — Merkle proof
    /// verification walks the array leaf-to-root and the wrong order
    /// terminates at the wrong root.
    ///
    /// Bug it catches: a decoder that collected proof hashes into a
    /// `HashSet` (or sorted them lexicographically) would make every
    /// non-trivial proof fail verification.
    #[test]
    fn test_inclusion_proof_hashes_preserve_order() {
        let mut original = fixture_dsse_bundle();
        // Use a clearly ordered set of distinct hashes.
        if let Some(proof) = &mut original.verification_material.tlog_entries[0].inclusion_proof {
            proof.hashes = vec![
                vec![0x01; 32],
                vec![0x02; 32],
                vec![0x03; 32],
                vec![0x04; 32],
            ];
        }
        let bytes = original.encode_json().unwrap();
        let decoded = Bundle::decode_json(&bytes).unwrap();
        let proof = decoded.verification_material.tlog_entries[0]
            .inclusion_proof
            .as_ref()
            .unwrap();
        assert_eq!(proof.hashes.len(), 4);
        assert_eq!(proof.hashes[0], vec![0x01; 32]);
        assert_eq!(proof.hashes[1], vec![0x02; 32]);
        assert_eq!(proof.hashes[2], vec![0x03; 32]);
        assert_eq!(proof.hashes[3], vec![0x04; 32]);
    }

    /// Bundle without optional fields (no cert, no tlog, no
    /// inclusion proof, no inclusion promise) round-trips cleanly —
    /// this is the offline "trust me" shape some non-Sigstore tools
    /// emit, and we shouldn't reject it at the wire layer (policy
    /// rejects it later).
    #[test]
    fn test_round_trip_minimal_message_signature_bundle() {
        let original = fixture_message_signature_bundle();
        let bytes = original.encode_json().unwrap();
        let decoded = Bundle::decode_json(&bytes).unwrap();
        assert_eq!(original, decoded);
        // Sanity: nothing optional crept in via default-construction.
        assert!(decoded.verification_material.certificate.is_none());
        assert!(decoded.verification_material.tlog_entries.is_empty());
        assert!(decoded
            .verification_material
            .timestamp_verification_data
            .is_none());
    }

    /// Load-bearing pin (issue #31): `encode_json` MUST emit the cert
    /// material at `verificationMaterial.x509CertificateChain` with a
    /// `certificates` list of `{"rawBytes": "..."}` objects, and MUST
    /// NOT emit the legacy single-cert `verificationMaterial.certificate`
    /// shape.
    ///
    /// Bug it catches: a future serde refactor that flips the field
    /// name back (e.g. someone renames the `x509_certificate_chain`
    /// wire field to `certificate` thinking it's just camelCasing)
    /// silently breaks every downstream cosign / sigstore-rs verifier
    /// that pattern-matches the protobuf-JSON oneof arm by name. A
    /// round-trip test does NOT catch this — we'd round-trip our own
    /// bad shape just fine. The wire-key assertion is the only thing
    /// that pins the externally-observable JSON contract.
    #[test]
    fn test_encode_json_emits_canonical_certificate_shape() {
        let bundle = fixture_dsse_bundle();
        let bytes = bundle.encode_json().expect("encode");
        let s = std::str::from_utf8(&bytes).expect("utf8");

        // Canonical chain key MUST be present.
        assert!(
            s.contains(r#""x509CertificateChain":{"certificates":[{"rawBytes":""#),
            "expected x509CertificateChain.certificates[].rawBytes shape, got: {s}"
        );

        // Legacy single-cert key MUST NOT be present. We're strict:
        // the substring `"certificate":` (with no `Chain` suffix)
        // would only appear if the encoder regressed to the legacy
        // arm. Other places the word `certificate` appears in the
        // wire (e.g. `x509CertificateChain`) include a different
        // suffix or are unrelated.
        assert!(
            !s.contains(r#""certificate":"#),
            "encoder must not emit the legacy `certificate` arm; got: {s}"
        );

        // Schema sanity: `verificationMaterial` exists at top level.
        assert!(
            s.contains(r#""verificationMaterial":{"#),
            "expected verificationMaterial wrapper, got: {s}"
        );
    }

    /// Round-trip via the canonical shape: encode → decode preserves
    /// the chain.
    ///
    /// Bug it catches: a decoder that only handled the legacy
    /// `certificate` arm (and silently dropped the
    /// `x509CertificateChain` arm to `None`) would let our own
    /// encoded bundles fail to round-trip — the chain would survive
    /// encode but vanish on decode.
    #[test]
    fn test_decode_json_accepts_canonical_certificate_shape() {
        let original = fixture_dsse_bundle();
        let bytes = original.encode_json().expect("encode");
        let decoded = Bundle::decode_json(&bytes).expect("decode");

        let cert = decoded
            .verification_material
            .certificate
            .expect("chain present");
        assert_eq!(cert.certificates.len(), 2);
        assert_eq!(
            cert.certificates[0],
            vec![0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD]
        );
        assert_eq!(
            cert.certificates[1],
            vec![0x30, 0x82, 0x02, 0x00, 0xBE, 0xEF]
        );
    }

    /// Hand-crafted JSON in the legacy `certificate.rawBytes`
    /// (singular `X509Certificate`) shape decodes successfully and
    /// the cert bytes come through verbatim.
    ///
    /// Bug it catches: a decoder that hard-rejected the legacy arm
    /// would break compat with cosign 2.x sign-blob output (which
    /// only ships the leaf cert, encoded as the singular
    /// `X509Certificate` oneof arm). The legacy arm is a v0 compat
    /// layer; this test pins that we DO accept it during the
    /// migration window. The legacy single cert is lifted into a
    /// one-element chain so downstream verification code stays
    /// chain-shaped.
    ///
    /// `inputBytes` for `rawBytes` is `0x30, 0x82, 0x01, 0x00, 0xCA, 0xFE`
    /// base64-encoded as `MIIBAMr+`.
    #[test]
    fn test_decode_json_accepts_legacy_x509certificatechain_shape_with_warning() {
        // NB: the test name historically refers to the cosign-legacy
        // arm; in protobuf-specs terms this is the singular
        // `X509Certificate` (`certificate.rawBytes`) arm. The test
        // covers BOTH shapes a producer might use — first the
        // x509CertificateChain wrapper using the legacy field name,
        // then the singular cosign sign-blob shape.
        let chain_legacy = br#"{
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "verificationMaterial": {
                "x509CertificateChain": {
                    "certificates": [
                        { "rawBytes": "MIIBAN6t" },
                        { "rawBytes": "MIICAL7v" }
                    ]
                },
                "tlogEntries": []
            },
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": "ESERESERESERESERESERESERESERESERESERESERESERESEREQ=="
                },
                "signature": "MEUCIQ=="
            }
        }"#;
        let decoded = Bundle::decode_json(chain_legacy).expect("decode legacy chain");
        let cert = decoded
            .verification_material
            .certificate
            .expect("chain decoded");
        assert_eq!(cert.certificates.len(), 2);
        assert_eq!(
            cert.certificates[0],
            vec![0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD]
        );
        assert_eq!(
            cert.certificates[1],
            vec![0x30, 0x82, 0x02, 0x00, 0xBE, 0xEF]
        );

        // Cosign sign-blob singular shape — `certificate.rawBytes`
        // (X509Certificate oneof arm). The single DER is lifted into
        // a one-element Vec so the in-memory `Certificate` model is
        // consistent.
        let single_legacy = br#"{
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "verificationMaterial": {
                "certificate": { "rawBytes": "MIIBAMr+" },
                "tlogEntries": []
            },
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": "ESERESERESERESERESERESERESERESERESERESERESERESEREQ=="
                },
                "signature": "MEUCIQ=="
            }
        }"#;
        let decoded = Bundle::decode_json(single_legacy).expect("decode single legacy");
        let cert = decoded
            .verification_material
            .certificate
            .expect("single cert lifted to chain");
        assert_eq!(cert.certificates.len(), 1);
        assert_eq!(
            cert.certificates[0],
            vec![0x30, 0x82, 0x01, 0x00, 0xCA, 0xFE]
        );
    }

    /// A bundle that populates BOTH `x509CertificateChain` AND
    /// `certificate` arms is rejected with a typed error — the
    /// protobuf `oneof` requires exactly one to be set, and a
    /// permissive decoder would let a malicious producer ship
    /// inconsistent material that two different verifiers
    /// interpret differently.
    ///
    /// Bug it catches: a decoder that "preferred" one arm and
    /// silently ignored the other would create a verifier-confusion
    /// surface across the Sigstore ecosystem.
    #[test]
    fn test_decode_rejects_both_certificate_shapes_set() {
        let json = br#"{
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "verificationMaterial": {
                "x509CertificateChain": {
                    "certificates": [{ "rawBytes": "MIIBAN6t" }]
                },
                "certificate": { "rawBytes": "MIIBAMr+" },
                "tlogEntries": []
            },
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": "ESERESERESERESERESERESERESERESERESERESERESERESEREQ=="
                },
                "signature": "MEUCIQ=="
            }
        }"#;
        let err = Bundle::decode_json(json).expect_err("must reject both arms");
        assert!(
            matches!(err, BundleDecodeError::BothCertificateShapesSet),
            "expected BothCertificateShapesSet, got {err:?}"
        );
    }

    /// Encode → decode → re-encode is byte-stable. This is a
    /// stronger invariant than the existing struct-level round-trip:
    /// it pins that the JSON form is canonical (no re-ordering of
    /// keys, no extraneous whitespace, no float drift on numeric
    /// fields).
    ///
    /// Bug it catches: a serde refactor that swapped to a HashMap-
    /// backed wire shape would scramble field order on each encode,
    /// breaking attestation hashes that some consumers compute over
    /// the bundle bytes.
    #[test]
    fn test_decode_json_round_trip_preserves_chain_bytes() {
        let original = fixture_dsse_bundle();
        let first_bytes = original.encode_json().expect("encode 1");
        let decoded = Bundle::decode_json(&first_bytes).expect("decode");
        let second_bytes = decoded.encode_json().expect("encode 2");
        assert_eq!(
            first_bytes, second_bytes,
            "encode → decode → re-encode must be byte-stable"
        );

        // And the chain bytes specifically must come through
        // verbatim — no normalisation, no re-ordering.
        let cert = decoded
            .verification_material
            .certificate
            .expect("chain decoded");
        assert_eq!(cert.certificates.len(), 2);
        assert_eq!(
            cert.certificates[0],
            vec![0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD]
        );
        assert_eq!(
            cert.certificates[1],
            vec![0x30, 0x82, 0x02, 0x00, 0xBE, 0xEF]
        );
    }

    /// A bundle whose in-memory `verification_material.certificate`
    /// is `None` MUST emit JSON with NEITHER the
    /// `x509CertificateChain` nor the legacy `certificate` field
    /// present. The `Option`-typed wire field is the source of truth
    /// for "no chain attached".
    ///
    /// Bug it catches: a wire shape that emitted
    /// `"x509CertificateChain":{"certificates":[]}` (an empty
    /// wrapper) would pass schema validation but be semantically
    /// "we have a chain — it's empty", which is meaningfully
    /// different from "no chain at all". Verifiers reading the
    /// bundle to decide whether to do PKI vs raw-key validation
    /// branch on field presence; an empty-but-present chain misroutes
    /// them.
    #[test]
    fn test_encode_json_with_empty_chain_emits_no_certificate_field() {
        let bundle = fixture_message_signature_bundle();
        // Sanity: the fixture has no chain.
        assert!(bundle.verification_material.certificate.is_none());

        let bytes = bundle.encode_json().expect("encode");
        let s = std::str::from_utf8(&bytes).expect("utf8");

        assert!(
            !s.contains("x509CertificateChain"),
            "expected x509CertificateChain field absent for None chain, got: {s}"
        );
        // `"certificate":` would be the legacy arm, which we never
        // emit; this is belt-and-suspenders against a future bug that
        // wires up the legacy arm by mistake.
        assert!(
            !s.contains(r#""certificate":"#),
            "legacy certificate arm must never be emitted, got: {s}"
        );
    }
}
