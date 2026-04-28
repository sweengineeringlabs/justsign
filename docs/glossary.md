# Glossary

**Audience**: Anyone reading the rest of the docs and hitting an unfamiliar Sigstore-specific or justsign-specific term.

Alphabetised list of terms used in justsign. Acronyms include their expansion. Cross-references use the term's exact heading.

---

## A

**ADR** - Architecture Decision Record. A short, dated document recording a significant architectural decision, the alternatives considered, and the rationale for the path picked. Lives at [`docs/3-design/adr/`](3-design/adr/).

**Attestation** - A signed [DSSE](#d) envelope whose payload is an [in-toto Statement](#i). Distinct from a raw blob signature: an attestation makes a claim ABOUT some software (e.g. "this artifact was built by GitHub Actions on commit X"), not merely "this artifact was signed by key Y". Justsign's `attest` / `verify_attestation` API is the primary attestation surface.

---

## B

**Bundle** - The all-in-one Sigstore verification artifact: signature (DSSE envelope OR raw MessageSignature) plus all verification material (Fulcio cert chain, Rekor inclusion proof / promise, signed checkpoint) needed to verify it offline against a trust root. Justsign emits Sigstore Bundle v0.3 per [`spec/src/sigstore_bundle.rs`](../spec/src/sigstore_bundle.rs).

---

## C

**Canonical body** - The exact bytes Rekor stored for a transparency-log entry, base64-encoded into [`tlogEntries[*].canonicalizedBody`](#t). Required by sigstore-go's bundle validation for v0.3; absence triggers cosign's silent fallback to the legacy bundle parser.

**Checkpoint** - A signed Rekor tree-state record (note format) binding a `tree_size` + `root_hash` to a Rekor signature. Lives at `tlogEntries[*].inclusionProof.checkpoint.envelope`. Verifiers cross-check the inclusion proof's root against this checkpoint to confirm the proof is against a Rekor-attested tree state, not an attacker-fabricated one.

**Cosign** - The reference Sigstore CLI for signing and verifying artifacts. Maintained by the Sigstore project at <https://github.com/sigstore/cosign>. Justsign's interop target is cosign 3.x with `--new-bundle-format`; cosign 2.x is supported only on the bundle-decode side for back-compat.

**CSR** - Certificate Signing Request. The PKCS#10 envelope justsign sends to Fulcio carrying the operator's ephemeral public key plus a proof-of-possession signature. Fulcio binds the OIDC subject claim into the resulting cert's SAN.

---

## D

**Dex** - Sigstore's federated OpenID Connect broker, hosted at `oauth2.sigstore.dev`. Fronts the upstream identity providers (GitHub, Google, Microsoft) so Sigstore-trusted OIDC tokens can be minted from any of them through one redirect flow.

**DSSE** - Dead Simple Signing Envelope. An envelope format that wraps a typed payload (`payload_type` MIME) plus one or more signatures over the [PAE](#p) of the payload. Spec at <https://github.com/secure-systems-lab/dsse>. Justsign's `sign_blob` and `attest` produce DSSE-content bundles.

---

## F

**Fulcio** - Sigstore's keyless Certificate Authority. Accepts a [CSR](#c) plus an [OIDC](#o) ID token; returns a 10-minute-validity X.509 cert chain whose leaf SAN is the OIDC subject. Production: `fulcio.sigstore.dev`; staging: `fulcio.sigstage.dev`.

---

## H

**HashedRekord** - Rekor's schema for MessageSignature-content bundles. The signature is verified against the raw payload digest (`SHA-256(payload)`) — distinct from the [`dsse`](#d) schema, which signs the [PAE](#p). Schema kind value: `"hashedrekord"`.

---

## I

**Inclusion promise** - A Rekor [SET](#s) (signed entry timestamp) — a signature over the entry's canonical fields, returned synchronously on submit. Proves Rekor accepted the entry; weaker than an inclusion proof, which proves the entry is committed to a published tree state.

**Inclusion proof** - A Merkle audit path from a leaf hash up to a tree root, plus the `tree_size` at proof time. Lets a verifier reconstruct the root and check it against a [signed checkpoint](#c) without trusting Rekor's word.

**In-toto Statement** - The typed payload format for [attestations](#a). Carries `_type`, `subject` (one or more digest-bound artifacts), `predicateType` (e.g. SLSA Provenance v1, CycloneDX 1.5), and `predicate` (the typed claim). Spec at <https://github.com/in-toto/attestation>.

---

## K

**Keyless signing** - Sigstore's signing model where the signer uses an ephemeral keypair bound to an OIDC identity via a [Fulcio](#f)-issued short-lived cert, instead of a long-lived static key. Justsign's `sign_blob_keyless` is the primary keyless surface.

---

## L

**LogId** - Identifier for a transparency-log instance — `SHA-256(public_key)` of the log's signing key. Held in `tlogEntries[*].logId.keyId`. NOT a `HashOutput` — protobuf-specs defines `LogId` as a separate message with only a `key_id: bytes` field.

---

## M

**MessageSignature** - The non-DSSE bundle content type: a raw signature over the payload's SHA-256 digest, plus the digest itself. The interop shape for `cosign verify-blob`. Justsign's `sign_blob_message` and `verify_blob_message` are the MessageSignature surface; default for the `sign-blob` CLI.

**MSRV** - Minimum Supported Rust Version. The oldest `rustc` toolchain justsign commits to building on. Justsign's MSRV policy lives at [`docs/4-development/guide/msrv_policy.md`](4-development/guide/msrv_policy.md).

---

## O

**OCI** - Open Container Initiative. The ecosystem and image / artifact format spec used for container distribution. Justsign's `sign_oci` / `verify_oci` produce + verify the OCI 1.1 referrer manifest cosign uses for image signing.

**OIDC** - OpenID Connect. The identity layer on top of OAuth 2.0 used by Sigstore for keyless signing. The OIDC ID token's subject claim is what Fulcio embeds in the leaf cert's SAN.

---

## P

**PAE** - Pre-Authentication Encoding. A length-prefixed serialisation of a [DSSE](#d) envelope's `payload_type` and `payload`, used as the actual signed bytes. Spec at <https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>. Justsign's `spec::pae` is the canonical implementation.

**PKCE** - Proof Key for Code Exchange (RFC 7636). An OAuth 2.0 extension that protects the authorization-code flow against code-interception attacks. Sigstore's Dex broker requires PKCE with the S256 method; justsign's interactive-browser provider implements it in `sign/src/oidc/interactive_browser.rs`.

---

## R

**Rekor** - Sigstore's public, append-only transparency log for software signatures. Production: `rekor.sigstore.dev`; staging: `rekor.sigstage.dev`. Spec at <https://github.com/sigstore/rekor>. Justsign's `rekor` crate is the SPI + HTTP client.

**Round-trip** - The cosign-against-production-Sigstore regression check described in [`docs/6-deployment/production_round_trip_runbook.md`](6-deployment/production_round_trip_runbook.md). Sign with justsign, verify with cosign, against production endpoints.

---

## S

**SAF** - Stratified Encapsulation Architecture (formerly known as the SEA framework). A layered-architecture pattern where each crate exposes a public façade trait and consumers depend on the trait, not the implementation. Used in some Sigstore-adjacent projects but NOT a justsign concept; mentioned only because the template-engine framework references it.

**SAN** - Subject Alternative Name. The X.509 cert extension Fulcio uses to bind the OIDC subject claim (email, workflow ID) into the keyless leaf cert. `cosign verify-blob --certificate-identity` matches against this field.

**SET** - Signed Entry Timestamp. Rekor's signature over a transparency-log entry's canonical fields, returned synchronously on submit as the [inclusion promise](#i). Held in `tlogEntries[*].inclusionPromise.signedEntryTimestamp`.

**Sigstore** - The public-good keyless-signing infrastructure run by the Linux Foundation. Comprises [Fulcio](#f) (CA), [Rekor](#r) (transparency log), and a [TUF](#t) trust-root distribution. <https://www.sigstore.dev>.

**SLSA** - Supply-chain Levels for Software Artifacts (pronounced "salsa"). A framework for software-supply-chain integrity. SLSA Provenance v1 is one of the in-toto predicates justsign emits via `sign_slsa_provenance`. <https://slsa.dev>.

**SPDX** - Software Package Data Exchange. An open SBOM format. Justsign's `sign_spdx` emits SPDX 2.3 documents wrapped in an in-toto Statement.

**SPI** - Service Provider Interface. The trait surface a consumer implements to plug a custom backend into a justsign crate. Examples: `RekorClient`, `FulcioClient`, the `Signer` trait.

**SUMMARY.md** - mdBook's table-of-contents file. Drives the rendered docs site at GitHub Pages. Lives at [`docs/SUMMARY.md`](SUMMARY.md). Distinct from [`docs/README.md`](README.md), which is the source-tree navigation hub.

---

## T

**TLDR** - "Too long; didn't read" — a short summary at the top of long docs (template convention: 200+ lines must carry a `> **TLDR**:` blockquote). Distinct from the document's first paragraph: TLDR is for the reader who never scrolls, the first paragraph is for the reader who does.

**TLog entry** - One transparency-log record. In a justsign bundle: `tlogEntries[*]`. Carries `logIndex` (global, across shards), `logId.keyId`, `kindVersion`, `integratedTime`, `inclusionPromise.signedEntryTimestamp`, `inclusionProof` (with shard-local `logIndex`, `treeSize`, `rootHash`, `hashes[]`, `checkpoint`), and `canonicalizedBody`.

**TUF** - The Update Framework. A spec for secure software-update delivery, used by Sigstore to distribute its trust root (Fulcio CA cert + Rekor public key) to clients. Spec at <https://theupdateframework.io>. Justsign's `tuf` crate is a span-preserving TUF client; trust-root bootstrap policy is recorded in [ADR-001](3-design/adr/001_sigstore_tuf_bootstrap.md).

---

## V

**VerifyingKey** - Justsign's algorithm-tagged enum wrapping a public key (P-256 / Ed25519 / P-384 / secp256k1). The `verify_blob` `trusted_keys` parameter takes `&[VerifyingKey]`, not the algorithm-specific type.
