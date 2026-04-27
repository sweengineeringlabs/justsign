# justsign

**Pure-Rust cosign equivalent. Sign, verify, attest — no Go binary.**

A cosign-shaped operator + library: produces and verifies Sigstore
bundles, talks to Fulcio (keyless certs) and Rekor (transparency
log), establishes trust via TUF.

## Status

Pre-v0. First vertical slice: DSSE envelope decode / encode / PAE
in `spec`. The crates below are scaffolded; their content lands in
subsequent slices.

## Crates

| Crate                  | Role                                                                              |
|------------------------|-----------------------------------------------------------------------------------|
| `swe_justsign_spec`    | Wire formats: DSSE envelope, in-toto attestation, Sigstore bundle JSON, Rekor entries. Pure structs + serde, no IO. |
| `swe_justsign_fulcio`  | Fulcio client: OIDC token → CSR → short-lived cert chain.                       |
| `swe_justsign_tuf`     | TUF metadata fetch + verify; establishes Sigstore root of trust.                 |
| `swe_justsign_rekor`   | Rekor client: submit + Merkle inclusion-proof verification. Independent — works with static keys too. |
| `swe_justsign_sign`    | High-level API: sign / verify blob, OCI artifact, attestation. Composes the above + RustCrypto primitives. |
| `swe_justsign_cli`     | `justsign` operator binary.                                                      |

## Sibling repos

- [`vmisolate`](../vmisolate)
- [`justoci`](../justoci) — uses `sigstore-rs` today; justsign is a
  candidate replacement once parity is reached.
- [`justcas`](../justcas)
- [`justext4`](../justext4)

## Documentation

- [Threat model](docs/3-design/threat-model.md) — what the v0 verifier
  guarantees, what it doesn't, and the caller-side checklist.

## Build

```
cargo build --workspace
cargo test  --workspace
```

Minimum supported Rust version: **1.75**.

## License

[Apache-2.0](LICENSE). Matches `justoci`, `justcas`, `justext4`,
OCI specs, every CNCF project.
