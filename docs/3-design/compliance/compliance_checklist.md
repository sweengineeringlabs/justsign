# Architecture compliance checklist

**Audience**: Code reviewers, contributors writing PRs that touch justsign's architectural boundaries.

Use this checklist during code review for any PR that touches the project's architectural boundaries. Every item must pass before merge. This checklist is **project-specific** — it enforces the architecture defined in [`../architecture.md`](../architecture.md), not general documentation standards.

> For documentation-format compliance (Audience lines, TLDR rule, ADR naming, glossary format, etc.) see the framework-level [`template-engine/templates/compliance-checklist.md`](https://github.com/swelabs/template-engine/blob/main/templates/compliance-checklist.md).

---

## How to use

1. Open this checklist alongside the PR diff.
2. Run the `cargo` / `grep` commands inline; mark each item.
3. Address failures before requesting review. Items that don't apply to the PR (e.g. no proto changes) can be marked N/A.

---

## 1. Crate-graph compliance

Reference: [`../architecture.md`](../architecture.md) — "Crate layout".

### 1.1 Dependency direction

- [ ] No upward dependencies. `spec` depends on nothing in this workspace; `rekor` and `fulcio` depend only on `spec`; `tuf` depends only on `spec`; `sign` depends on `spec` + `rekor` + `fulcio` + `tuf`; `cli` depends on `sign`.
- [ ] No back-edges. PR does not add a `sign → cli` or `spec → sign` edge.
- [ ] New external deps justified. Heavyweight additions (anything pulling >50 transitive crates, anything `unsafe`-dense, anything network-stack-shaped) flagged in the PR description.

**Verify**:
```sh
cargo tree -p swe_justsign_spec | grep -E '^├|^└' | wc -l   # surface area shouldn't grow without intent
cargo build --workspace                                      # rust catches dep-direction violations at link time
```

### 1.2 Feature gating

- [ ] New optional deps live behind a Cargo feature, not in `[dependencies]` unconditionally.
- [ ] Algorithm features (`ed25519`, `ecdsa-p384`, `secp256k1`) compile in isolation (no cross-feature leak).
- [ ] OIDC features split correctly: `oidc` (token-only, no browser) vs `oidc-browser` (full interactive flow with `open` crate). The browser dep does NOT bleed into the `oidc` feature.

**Verify**:
```sh
cargo build -p swe_justsign_sign --no-default-features --features oidc            # no `open` dep pulled in
cargo build -p swe_justsign_sign --no-default-features --features oidc-browser    # `open` dep present
cargo build --workspace --no-default-features                                     # baseline still builds
```

---

## 2. Wire-format compliance

Reference: [`../architecture.md`](../architecture.md) — "Bundle wire shape" + [`../../6-deployment/production_round_trip_runbook.md`](../../6-deployment/production_round_trip_runbook.md).

### 2.1 Bundle producer

- [ ] `mediaType` is `application/vnd.dev.sigstore.bundle.v0.3+json` (the `.v0.3+json` form, not the deprecated `;version=0.3` parameter form).
- [ ] `verificationMaterial.certificate.rawBytes` carries the leaf cert (singular leaf form, protobuf-specs v0.3 final), NOT `x509CertificateChain.certificates[]`.
- [ ] `verificationMaterial.tlogEntries[*]` carries every required field for v0.3: `logIndex`, `logId.keyId`, `kindVersion`, `integratedTime` (non-zero), `inclusionPromise.signedEntryTimestamp`, `inclusionProof` (with shard-local `logIndex` < `treeSize`, `rootHash`, `hashes[]`, `checkpoint.envelope`), and `canonicalizedBody`.
- [ ] `tlogEntries[*].logIndex` is the GLOBAL Rekor index. `tlogEntries[*].inclusionProof.logIndex` is the SHARD-LOCAL index. They are distinct fields, never collapsed.
- [ ] MessageSignature-content bundles use the `hashedrekord` Rekor schema. DSSE-content bundles use the `dsse` schema. Schema choice is dispatched on bundle content type, not hardcoded.

**Verify**: re-run the production round-trip per the runbook. Last-known-good bundle: logIndex 1396196448. Any wire-shape PR MUST trigger a fresh round-trip before merging.

### 2.2 Signing convention

- [ ] `Signer::sign` for ECDSA hashes the message internally (RustCrypto's standard convention). Producer code passes the raw `payload`, NOT a pre-computed digest.
- [ ] `verify_blob_message` passes the raw `payload` (NOT `pinned_digest`) to `try_verify`, symmetric with the signer.
- [ ] Rekor's `hashedrekord` verifier expects `sig` over `SHA-256(payload)`. Any signing path that breaks this convention re-runs the round-trip before merging.

---

## 3. Trait SPI stability

Reference: [`../architecture.md`](../architecture.md) — "Trait SPI everywhere".

### 3.1 Public trait surface

- [ ] `RekorClient`, `FulcioClient`, `Signer`, and the `*Verifier` trait surfaces in `sign` are not changed without a corresponding entry in [`../../4-development/migration_guide.md`](../../4-development/migration_guide.md).
- [ ] Trait additions are NON-default-method-only OR have a default impl that won't break external implementors. Required-method additions are a SemVer break and tracked as such.
- [ ] `LogEntry`, `Bundle`, `TlogEntry`, `MessageSignature`, `DsseEnvelope`, `Certificate`, `LogId` field additions are non-breaking only when they have `#[serde(default)]` for deserialise + a sensible default for in-memory construction.

**Verify**:
```sh
cargo public-api --diff-with-published   # if installed; otherwise eyeball the public re-exports in lib.rs
```

---

## 4. Test-pyramid compliance

Reference: [`../../5-testing/testing_strategy.md`](../../5-testing/testing_strategy.md).

### 4.1 Test density

- [ ] PR adds tests for every new public function / trait method / wire field. NO production code without a test.
- [ ] Each test name matches `test_<action>_<condition>_<expectation>`. Bare `test_foo()` names rejected on review.
- [ ] Each test asserts the RIGHT thing — not `unwrap().is_some()`, but the actual value or error variant.
- [ ] Negative tests for safety-critical surfaces (verification, OIDC parsing, base64 decoding) are mandatory; "happy path only" coverage rejected.

**Verify**:
```sh
cargo test --workspace 2>&1 | grep -E 'test result' | tail -20  # all suites pass
cargo test --workspace --doc                                    # doctests pass
```

### 4.2 No fake tests

- [ ] No "test that exists to bump count" — every test must catch a specific bug if the implementation breaks. Re-read each test name against its body before merging.
- [ ] No tautological tests (`assert_eq!(x, x)` in disguise).
- [ ] No silent-swallow `.ok()` or `.unwrap_or_default()` in tests that were supposed to assert against a specific error variant.

---

## 5. Cross-cutting

### 5.1 Commit + branch hygiene

- [ ] Commit message follows `type(scope): description` and includes a `Closes #N` line for the issue it resolves.
- [ ] No AI-attribution lines in commit body (no `Co-Authored-By: Claude…`, etc.) unless the maintainer explicitly OK'd it.
- [ ] PR cascades through `dev → test → int → uat → prd → main` ff-only — no `--force`, no off-line rebases.

### 5.2 Doc updates

- [ ] Every architectural change (anything in this checklist) has a corresponding ADR or update to `architecture.md`.
- [ ] Wire-shape changes update the production round-trip runbook's "Failure modes" table if a new fail mode is introduced or an old one closed.
- [ ] Migration guide gains an entry for any caller-visible API change.

---

## See also

- [`../architecture.md`](../architecture.md) — the architectural rules this checklist enforces.
- [`../adr/README.md`](../adr/README.md) — durable decisions that justify the rules.
- [`../../5-testing/testing_strategy.md`](../../5-testing/testing_strategy.md) — the test-pyramid conventions referenced in §4.
- [`../../6-deployment/production_round_trip_runbook.md`](../../6-deployment/production_round_trip_runbook.md) — the wire-format regression check referenced in §2.
