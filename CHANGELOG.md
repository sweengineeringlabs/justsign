# Changelog

**Audience**: Library consumers tracking justsign releases.

All notable changes to this project are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Cross-verification of the bundled Sigstore root against cosign and sigstore-go (#34)** — `tuf/tests/cross_verify_external_roots.rs` bootstraps the real TUF client from the older roots those projects ship (pinned by SHA-256 at release tags), walks Sigstore's signed chain, and requires it to land on exactly the bytes in `tuf/assets`. Runs in CI (`tuf-cross-verify`) and in the root watcher before a refresh PR is opened.
- **`sign tuf-root show` / `sign tuf-root verify [--root <path>]` (#35)** — shows the bundled Sigstore root (version, sha256, source, fetched-at, expires) and checks it, or a file you supply, for parse, shape, expiry and self-signature to threshold. Distinct exit codes: `3` malformed, `4` expired, `5` signature below threshold, `1` usage/IO. `tuf::verify_root_self_signature` is now public.
- **Sigstore TUF root watcher and operator runbook (#33, #36)** — `.github/workflows/sigstore_root_watch.yml` (monthly, plus manual dispatch) cross-checks the newest Sigstore root against GitHub, verifies the signature chain with the real client, and opens a refresh PR; it fails the run when the embedded root nears expiry un-rotated. The logic is `scripts/sigstore_root_refresh.py` (stdlib only, unit-tested in CI). `docs/7-operations/sigstore_bootstrap.md` documents confirming, refreshing, overriding and recovering the bundled root.
- **Documentation framework compliance** — full audit pass against the swelabs template-engine standard. Added `docs/README.md` (W³H navigation hub), `docs/glossary.md` (alphabetised term list), `docs/3-design/compliance/compliance_checklist.md` (per-PR architectural review gate). Added repo-root governance set: `CONTRIBUTING.md`, `CHANGELOG.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, plus `.github/ISSUE_TEMPLATE/` and `.github/PULL_REQUEST_TEMPLATE.md`. Every existing `docs/` file gained an `**Audience**:` declaration; the 200+-line round-trip runbook gained a TLDR blockquote.
- **Production Sigstore round-trip verified end-to-end (#23)** — cosign 3.0.6 `verify-blob --new-bundle-format` accepts a justsign-keyless bundle against production Fulcio + Rekor. Permanent evidence at <https://search.sigstore.dev/?logIndex=1396196448>.
- **Rekor `LogEntry` carries the full v0.3 verification surface**: `integrated_time`, `log_id`, `signed_entry_timestamp` (SET), `checkpoint_envelope`, plus separate `log_index` (global) and `proof_log_index` (shard-local) for sharded-Rekor support.
- **Spec `TlogEntry.canonicalized_body`** populated from the Rekor response — required by sigstore-go's bundle validation for v0.3.
- **Spec `LogId { key_id: bytes }`** message — distinct from `HashOutput`. Fixes `proto: unknown field "algorithm"` rejection from sigstore-go.
- **MessageSignature content path** (#40) — `sign_blob_message`, `sign_blob_message_keyless`, `verify_blob_message`, `verify_blob_message_keyless` produce / verify cosign-blob-interop bundles. CLI default `--shape message`.
- **DSSE Rekor schema** (#39) — `submit_dsse` on `RekorClient` for DSSE-content bundles; schema dispatched by bundle content type.
- **Singular leaf certificate** (#38) — `verificationMaterial.certificate.rawBytes` (protobuf-specs v0.3 final), required by cosign 3.x. Decoder still accepts the deprecated `x509CertificateChain` form for back-compat.
- **Canonical bundle mediaType** — `application/vnd.dev.sigstore.bundle.v0.3+json` (the `.v0.3+json` suffix-tree form, not `;version=0.3`).
- **Interactive-browser OIDC provider** — full OAuth code+PKCE (S256) flow against Sigstore's Dex broker, fronting GitHub / Google / Microsoft. Behind `--features oidc-browser`. Listener timeout 15 minutes (was 5).
- **CLI `--keyless` flag** for `sign-blob` — wires Fulcio + `sign_blob_keyless` end-to-end. Defaults to staging Fulcio for safety.
- **MSRV stability policy** at [`docs/4-development/msrv_policy.md`](docs/4-development/msrv_policy.md).
- **Migration guide** at [`docs/4-development/migration_guide.md`](docs/4-development/migration_guide.md).
- **mdBook docs site** published to GitHub Pages on push to `main`.
- **Bundled Sigstore production trust root** (#27) plus `with_initial_root_bytes` override.
- **Clock SPI + cert expiry enforcement** (#26) — `VerifyError::CertExpired` is now produced.
- **Granular `RekorError` variants** (#32) — transport vs HTTP status vs decode vs already-exists separated.
- **TUF ECDSA P-256 dispatch** (#37) in `verify_role`.

### Changed

- `try_verify` (in `verify_blob_message`) now hands `payload` (not `pinned_digest`) to RustCrypto's verify, symmetric with the signer's `Signer::sign(payload)` convention. Off-by-one-hash regression caught and fixed in #23.

### Fixed

- **`Pkcs11Signer` could crash the process under concurrent signing.** Each `sign` loads the PKCS#11 module, `C_Initialize`s it and `C_Finalize`s it on drop; the library's state is process-global, so two threads signing at once let one finalize it under the other (SoftHSM2 died with SIGSEGV). `Signer` is `Send + Sync`, so this was a supported use. A process-wide lock now covers the whole load/sign/finalize span. The SoftHSM e2e tests also now verify signatures against the token's public key instead of only checking DER shape, and `sign_prehash` has its own e2e test.
- **Feature-gated signers no longer compile-fail.** Adding `Signer::sign_prehash` (013b0f1) left the AWS/GCP/Azure/Vault KMS stubs and `Pkcs11Signer` without an implementation, so `--features pkcs11` (and every KMS feature) failed to build. The KMS stubs return the same typed `Stubbed` error as `sign`; `Pkcs11Signer` shares one session path between `sign` and `sign_prehash`. CI gains a `cargo check --workspace --all-features --all-targets` job so this class of break is caught on push.
- **TUF client could not verify the live Sigstore mirror.** `TufClient` verified signatures over the raw wire bytes of `signed`, but TUF signatures cover the canonical JSON form and Sigstore serves pretty-printed JSON, so every real root/timestamp failed with `BelowThreshold { valid: 0 }`. It now verifies over the canonical form. It also now requests `<N>.snapshot.json` / `<N>.targets.json` when `consistent_snapshot` is set (the plain names 404 on Sigstore), accepts version-only pins (hashes are optional in TUF) while enforcing `signed.version == pinned version` (new `TufError::VersionMismatch`), and hash-checks when hashes are present. The unit tests used compact, key-sorted fixtures that happen to equal the canonical form, which is why this was never caught; the `live_sigstore` test now passes against the real mirror.
- `cert_chain::verify_chain` now returns `ChainError::UnsupportedAlgorithm` (naming the OID and chain index) instead of `RootNotTrusted` when the topmost certificate is signed with a non-ECDSA-P256-SHA256 algorithm (e.g. Ed25519) and is not itself a trust anchor. Previously the correct trust anchor was reported as untrusted (#42).

## [0.1.0] — TBD (pre-release)

This is the initial release. v0.1.0 is the cut at which the public API stabilises and crates.io publication begins; until then the workspace is on `0.1.0-pre`. See [issue #15](https://github.com/sweengineeringlabs/justsign/issues/15) for the publication plan.

[Unreleased]: https://github.com/sweengineeringlabs/justsign/compare/main...dev
[0.1.0]: https://github.com/sweengineeringlabs/justsign/releases/tag/v0.1.0
