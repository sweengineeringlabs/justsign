# Architecture

## Diagrams

Four diagrams covering the four shapes of the system: which crates depend on which (inclusion), how the pieces wire up at runtime (block), how a sign call flows data end-to-end (data flow), and how a keyless sign-then-verify call sequences (sequence).

### Inclusion: workspace dep graph

```mermaid
flowchart TD
  cli["cli<br/>(justsign binary)"]
  sign["sign<br/>(sign_blob, verify_blob, attest, sign_oci, ...)"]
  fulcio["fulcio<br/>(HTTP CSR client)"]
  rekor["rekor<br/>(HTTP transparency log client)"]
  tuf["tuf<br/>(root walker, span parser, embedded Sigstore root)"]
  spec["spec<br/>(DSSE / Bundle / in-toto / SLSA / SBOM wire formats + Clock SPI)"]

  cli --> sign
  sign --> fulcio
  sign --> rekor
  sign --> tuf
  sign --> spec
  fulcio --> spec
  rekor --> spec
  tuf --> spec

  subgraph rustcrypto [RustCrypto stack]
    p256["p256 (ECDSA P-256)"]
    ed25519["ed25519-dalek"]
    p384["p384"]
    k256["k256 (secp256k1)"]
    sha2["sha2"]
    der["der / x509-cert / spki"]
  end

  subgraph http [HTTP / async]
    reqwest
    tokio["tokio (--features async only)"]
  end

  sign --> rustcrypto
  fulcio --> reqwest
  rekor --> reqwest
  tuf --> reqwest
  fulcio -.opt.-> tokio
  rekor -.opt.-> tokio
```

### Block: runtime layout of a sign + verify session

```mermaid
flowchart LR
  Caller --> SignAPI["sign::sign_blob / sign_blob_keyless / attest / sign_oci"]
  SignAPI --> DSSE[DSSE envelope + PAE]
  SignAPI --> Signer["Signer trait<br/>(EcdsaP256 / Ed25519 / Pkcs11 / KMS-stub)"]
  Signer --> Sig[signature bytes]

  SignAPI -.optional.-> Fulcio["HttpFulcioClient<br/>(keyless cert via OIDC)"]
  Fulcio --> Cert["X.509 leaf + chain"]

  SignAPI -.optional.-> Rekor["HttpRekorClient<br/>(transparency log)"]
  Rekor --> TLog["LogEntry + inclusion proof"]

  DSSE --> Bundle["Sigstore Bundle v0.3"]
  Sig --> Bundle
  Cert --> Bundle
  TLog --> Bundle

  Bundle --> Wire[wire bytes]

  Wire --> VerifyAPI["sign::verify_blob / verify_blob_keyless"]
  VerifyAPI --> ChainVerify["cert_chain::verify_chain<br/>(against trusted anchors or TUF root)"]
  VerifyAPI --> SigVerify["VerifyingKey::verify (P-256/Ed25519/...)"]
  VerifyAPI --> RekorReverify["rekor::verify_inclusion_proof"]
  VerifyAPI --> ClockGate["spec::Clock check on cert validity window"]

  TUF["tuf::TufClient<br/>(embedded Sigstore v14 root)"] -.feeds anchors.-> ChainVerify
```

### Data flow: blob → DSSE → Bundle

```mermaid
flowchart TD
  Payload[blob payload + payload_type] --> PAE["PAE: 'DSSEv1' SP &lt;type-len&gt; SP &lt;type&gt; SP &lt;payload-len&gt; SP &lt;payload&gt;"]
  PAE --> Sign[Signer::sign &rarr; raw signature bytes]
  Sign --> DSSE[DSSE Envelope JSON]
  Payload --> DSSE
  DSSE --> Bundle["Bundle v0.3:<br/>verificationMaterial + DsseEnvelope content"]
  CertChain[Fulcio cert chain] -.keyless only.-> Bundle
  Tlog[Rekor inclusion proof + log_index] -.optional.-> Bundle
  Bundle --> JSON[bundle.encode_json &rarr; canonical wire bytes]
```

### Sequence: keyless sign, then verify

```mermaid
sequenceDiagram
  participant App as caller
  participant OIDC as OidcProvider
  participant Fulcio as HttpFulcioClient
  participant Signer as EcdsaP256Signer
  participant Sign as sign::sign_blob_keyless
  participant Rekor as HttpRekorClient

  App->>OIDC: fetch_token
  OIDC-->>App: id_token
  App->>Signer: new(generated SigningKey)
  App->>Fulcio: sign_csr(csr, id_token)
  Fulcio-->>App: cert chain (leaf + intermediates)
  App->>Sign: sign_blob_keyless(payload, payload_type, signer, chain, Some(rekor))
  Sign->>Signer: sign(PAE)
  Signer-->>Sign: signature
  Sign->>Rekor: submit(hashed_rekord)
  Rekor-->>Sign: LogEntry + inclusion_proof
  Sign-->>App: Bundle (with chain, sig, tlog)

  Note over App: bytes travel over the wire to a verifier

  participant V as verifier
  participant Vfy as sign::verify_blob_keyless
  V->>Vfy: verify_blob_keyless(bundle, trust_anchors, expected_san, Some(rekor))
  Vfy->>Vfy: parse cert chain
  Vfy->>Vfy: chain walk (leaf<-intermediate<-root in trust_anchors)
  Vfy->>Vfy: clock check (notBefore <= now < notAfter)
  Vfy->>Vfy: SAN policy check
  Vfy->>Vfy: DSSE PAE re-derive + signature verify
  Vfy->>Rekor: verify_inclusion_proof
  Rekor-->>Vfy: ok / proof failure
  Vfy-->>V: Ok / VerifyError
```

## Six crates

| Crate | Role | Public surface |
|---|---|---|
| `spec` | Wire formats (DSSE, in-toto Statement, Sigstore Bundle, SLSA, SBOM) + Clock SPI | `Envelope`, `Bundle`, `Statement`, `Subject`, `Clock`, `SystemClock`, `FixedClock`, `pae`, predicate-type constants |
| `fulcio` | OIDC token + CSR → short-lived cert chain | `FulcioClient`, `HttpFulcioClient`, `MockFulcioClient`, `CertChain`, `build_csr` |
| `rekor` | Transparency log: submit + fetch + Merkle proof verify | `RekorClient`, `HttpRekorClient`, `MockRekorClient`, `LogEntry`, `verify_inclusion`, granular `RekorError` variants |
| `tuf` | TUF root walker, span-preserving JSON, embedded Sigstore production root | `TufClient::sigstore`, `TufClient::with_initial_root_bytes`, `verify_role` (Ed25519 + ECDSA P-256), `parse_with_signed_span`, `canonicalize` |
| `sign` | High-level API + per-algorithm signers + OIDC providers + KMS stubs + PKCS#11 + OCI signing + attestations | `sign_blob`, `verify_blob`, `sign_blob_keyless`, `verify_blob_keyless`, `attest`, `verify_attestation`, `sign_oci`, `verify_oci`, `Signer`, `VerifyingKey`, `OidcProvider`, `EcdsaP256Signer`, `Ed25519Signer`, `Pkcs11Signer` |
| `cli` | `justsign` operator binary | `generate-key-pair`, `public-key`, `sign-blob`, `verify-blob`, `oidc-token` subcommands |

## Key design decisions

**Pure Rust, std-only at the core.** No subprocess, no `cosign` binary, no FFI. RustCrypto for all primitives. `reqwest` (sync `blocking` by default; `tokio` only behind `--features async`).

**Bytes over Values for verification.** TUF role signatures verify against the *exact wire bytes* of the `signed` field (via `tuf::span::parse_with_signed_span`), not against a re-canonicalised emit. Closes the bytes-drift surface a re-canonicaliser bug class would otherwise leave open. See ADR `docs/3-design/adr/001_sigstore_tuf_bootstrap.md`.

**Algorithm-tagged VerifyingKey.** `verify_blob`'s `trusted_keys: &[VerifyingKey]` parameter dispatches across P-256 / Ed25519 / P-384 / secp256k1 at runtime. Each variant gates on its feature flag — default builds carry only P-256.

**Stub-then-promote for KMS.** AWS / GCP / Azure / Vault Transit signers ship as typed stubs (`SignerError::Stubbed` per call) so callers can declare the surface today. Real SDK integrations land per-provider as separate slices to keep the dep-tree balloon scoped. Tracked in #17–#20.

**Embedded Sigstore TUF root.** `TufClient::sigstore()` uses an `include_bytes!`-bundled v14 production root, validated by chained-root walking. Override available via `with_initial_root_bytes`. Build-time check fails the build if the bundled asset corrupts or expires; runtime guard returns `TufError::EmbeddedRootExpired` on stale bundle. ADR 001 documents the policy.

**Skip-pass for live integrations.** Every test that talks to a real network endpoint (Fulcio staging, Rekor staging, SoftHSM2, Sigstore TUF mirror) is *always-on* and prints `SKIP: ...` when its env var isn't set. CI reports test counts unchanged whether the live hosts are reachable or not.

## Pipeline (ASCII)

```
                       ┌───────────────────┐
                       │  Caller           │
                       │  (CLI / library)  │
                       └─────────┬─────────┘
                                 │
                                 ▼
                       ┌───────────────────┐
                       │  sign API         │
                       │  sign_blob /      │
                       │  verify_blob /    │
                       │  attest / sign_oci│
                       └─┬───┬───┬─────┬───┘
                         │   │   │     │
                         ▼   │   │     │
                       DSSE  │   │     │
                       PAE   │   │     │
                         │   │   │     │
                         ▼   ▼   ▼     ▼
                     Signer Fulcio Rekor TUF
                       │   │   │     │
                       └─┬─┴─┬─┴───┬─┘
                         │   │     │
                         ▼   ▼     ▼
                       ┌───────────────────┐
                       │  Sigstore Bundle  │
                       │  v0.3 wire bytes  │
                       └───────────────────┘
```

## Wire format authority

The Sigstore protobuf-specs v0.3 final is the wire-format source of truth. `Bundle::encode_json` emits the singular leaf shape `verificationMaterial.certificate.rawBytes` (protobuf `X509Certificate` oneof arm) — required by cosign 3.0+ — and accepts both that shape and the deprecated `verificationMaterial.x509CertificateChain.certificates[].rawBytes` chain wrapper on decode for cosign 2.x compat. Pinned by `test_encode_json_emits_canonical_certificate_shape` in `spec/src/sigstore_bundle.rs` (inverted in #38 from #31's pin). Verifiers reconstruct intermediates and the root from their TUF-validated trust anchors, not from the bundle.

For the threat model and what the verifier guarantees / does NOT guarantee, see [`docs/3-design/threat_model.md`](threat_model.md). For ADRs, see [`docs/3-design/adr/`](adr/).
