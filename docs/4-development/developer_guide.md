# Developer guide

## Local setup

```sh
git clone https://github.com/sweengineeringlabs/justsign
cd justsign
cargo build --workspace
cargo test  --workspace
```

**MSRV**: 1.88. Pinned in workspace `Cargo.toml` because the active dep graph requires it (`base64ct` 1.7+ wants edition2024, `icu_collections` 2.x declared 1.86, `time` 0.3.47 via `rcgen` declared 1.88). Pinning back is whack-a-mole; we track the ecosystem instead.

**No sibling-repo path-deps required.** justsign is fully self-contained — no path-deps to other workspace members. Drop into any directory and `cargo build` works.

## Six-branch flow

Branches: `dev → test → int → uat → prd → main`, fast-forward only.

- Land work on `dev` (PR + review).
- Cascade ff-only through `test → int → uat → prd → main` once CI is green.
- `main` is what triggers the mdBook + Pages workflow at `.github/workflows/pages.yml`.
- The five non-main branches mostly mirror `dev`; they exist for staged release gating per the workspace SDLC posture.

For day-to-day contribution, work on `dev` and let cascade roll through automatically when CI passes.

## Testing

```sh
# Default features
cargo test --workspace

# All features (including KMS stubs + pkcs11 + ed25519/p384/k256 + oidc + async)
cargo test -p swe_justsign_sign --all-features
cargo test -p swe_justsign_fulcio --features async
cargo test -p swe_justsign_rekor --features async

# Per-feature smoke (the CI matrix runs each of these)
cargo test -p swe_justsign_sign --features pkcs11
cargo test -p swe_justsign_sign --features oidc
cargo test -p swe_justsign_sign --features oidc,oidc-browser
```

Test counts shift release-to-release. Read the actual numbers via:

```sh
cargo test --workspace 2>&1 | grep "test result:"
```

### Skip-pass live integration tests

Live tests are *always-on* (no `#[ignore]`) and SKIP at runtime when their env vars aren't set. They print `SKIP: <reason>` to stderr and return success.

| Test | Env vars |
|---|---|
| Fulcio staging integration | `JUSTSIGN_FULCIO_STAGING=1` + `JUSTSIGN_OIDC_TOKEN=<JWT>` |
| Rekor staging integration | `JUSTSIGN_REKOR_STAGING=1` |
| TUF live walk against Sigstore mirror | `JUSTSIGN_TUF_LIVE=1` + `JUSTSIGN_TUF_BOOTSTRAP=<path/to/root.json>` |
| PKCS#11 SoftHSM2 e2e | `JUSTSIGN_SOFTHSM_LIB=` + `JUSTSIGN_SOFTHSM_PIN=` + `JUSTSIGN_SOFTHSM_KEY_LABEL=` |

CI runs these on a manual-dispatch workflow (`.github/workflows/staging.yml`). Set the env vars in the workflow's repo secrets to enable.

## Conventions

### Test naming

Every test follows `test_<action>_<condition>_<expectation>`. Examples:

- `test_sign_blob_with_mock_signer_round_trips_through_verify`
- `test_verify_blob_keyless_rejects_signature_from_wrong_key`
- `test_pkcs11_signer_sign_with_missing_module_returns_module_load_error`

### Bug-class doc comments

Every test names the bug class it catches, in a `///` doc comment above `#[test]`:

```rust
/// Bug it catches: a verifier that ignored expected_predicate_type
/// (or compared the wrong field, e.g. payload_type instead of
/// predicateType) would happily accept an SPDX SBOM where a SLSA
/// Provenance was required.
#[test]
fn test_verify_attestation_rejects_wrong_predicate_type() { /* ... */ }
```

A test that can't articulate a concrete regression is rejected at review.

### Doc filenames

Every `.md` file in `docs/` uses **snake_case**, no kebab-case. ADRs live at `docs/3-design/adr/NNN_snake_case_slug.md`.

### No emojis

In code, in commit messages, in docs. Never.

### No blanket warning suppressions

`#![allow(dead_code, unused_imports)]` at module/lib root is forbidden. Warnings are signal — clear them, or carve a narrow `#[allow(...)]` on the specific construct with a comment explaining why.

## Adding a new signer

Walkthrough using `Pkcs11Signer` as the template:

1. Create `sign/src/<name>.rs` — gate the module on a feature flag if the impl pulls a new dep:
   ```rust
   #[cfg(feature = "pkcs11")]
   pub mod pkcs11;
   ```
2. Define your struct + `impl Signer for YourSigner` — the `Signer` trait is in `sign/src/signer.rs`. You implement `sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError>` and `key_id(&self) -> Option<String>`.
3. Add error variants to `sign::SignerError` if your signer has unique failure modes (e.g. `ModuleLoad { path, cause }` for PKCS#11 path-not-found).
4. Add the feature flag to `sign/Cargo.toml`'s `[features]` block, with a comment explaining what it pulls.
5. Re-export your signer from `sign/src/lib.rs`, gated on the feature flag.
6. Write tests in your new module — minimum 3, each with a `Bug it catches:` doc comment:
   - Constructor smoke (struct holds the right fields).
   - `key_id` returns the expected identifier.
   - `sign` returns a typed error on a known bad input (e.g. wrong module path).
7. Add a skip-pass live integration test if your signer talks to a real backend (mirror the SoftHSM2 pattern).
8. Update `docs/3-design/integration_guide.md`'s feature-flag table with your new flag's status.

## Adding a new attestation predicate type

Walkthrough using `SLSA Provenance v1` (#8) as the template:

1. Add the predicate-type URI constant + typed structs in `spec/src/<name>.rs` (e.g. `spec/src/slsa.rs`). All structs derive `Serialize + Deserialize + Debug + Clone + PartialEq + Eq` with `serde(rename_all = "camelCase")` for the wire shape and `serde(skip_serializing_if = "Option::is_none")` for optional fields.
2. Re-export the constant + types from `spec/src/lib.rs`.
3. Add convenience wrappers in `sign/src/<name>.rs`: `sign_<predicate>(...)` and `verify_<predicate>(...)` that call `attest` / `verify_attestation` with the predicate-type URI pinned. Returning a `Verified<Predicate>` struct lets callers consume the typed predicate without re-decoding.
4. Tests: round-trip, predicate-type mismatch rejection, subject-digest mismatch rejection, `expected_subject_digest = None` skips, rekor witnessed flow.

The SBOM (CycloneDX + SPDX) wrappers in `sign/src/sbom.rs` are the simpler "opaque body" template — just constants + four wrapper functions, no struct types.

## Fuzzing

`fuzz/` at the workspace root carries `cargo-fuzz` targets for the wire-decode parsers (DSSE, Bundle, Statement, TUF canonicalize, TUF span parser, Fulcio chain, Rekor decode, OCI manifest).

```sh
cargo install cargo-fuzz --locked
cd fuzz
cargo +nightly fuzz run envelope_decode_json -- -max_total_time=300
```

The CI workflow `.github/workflows/fuzz.yml` runs each target for 5 minutes on `workflow_dispatch`. Fuzzing requires `nightly` Rust + libFuzzer runtime — Linux runners have this out of the box.

## CI workflows

| Workflow | Triggers | Purpose |
|---|---|---|
| `ci.yml` | push to all 6 branches | `cargo build` + `cargo test --workspace` + `cargo clippy -D warnings` + `cargo fmt --check` + MSRV gate (`1.88`) |
| `pages.yml` | push to `main` | mdBook build + Pages deploy |
| `staging.yml` | manual dispatch | live Fulcio / Rekor / TUF / SoftHSM2 integration tests with secrets-gated env vars |
| `fuzz.yml` | manual dispatch | `cargo-fuzz` targets, 5 min each |

## Common gotchas

- **`cargo fmt`** runs as a CI gate. Run it locally (`cargo fmt --all`) before pushing.
- **`cargo clippy -- -D warnings`** is the lint gate. Even pedantic clippy lints become errors — fix them or add a narrow `#[allow(...)]` with rationale.
- **Workspace MSRV** is enforced by a separate CI job. If you add a dep that requires a higher MSRV, bump the workspace `rust-version` and document it in the commit message + `docs/4-development/developer_guide.md`.
- **No `#[ignore]`** for live integration tests — use the skip-pass pattern instead.
