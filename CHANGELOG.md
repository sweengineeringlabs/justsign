# Changelog

**Audience**: Library consumers tracking justsign releases.

All notable changes to this project are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

## [0.1.0] — TBD (pre-release)

This is the initial release. v0.1.0 is the cut at which the public API stabilises and crates.io publication begins; until then the workspace is on `0.1.0-pre`. See [issue #15](https://github.com/sweengineeringlabs/justsign/issues/15) for the publication plan.

[Unreleased]: https://github.com/sweengineeringlabs/justsign/compare/main...dev
[0.1.0]: https://github.com/sweengineeringlabs/justsign/releases/tag/v0.1.0
