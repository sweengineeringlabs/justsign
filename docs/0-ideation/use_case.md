# Use cases

**Audience**: Product leads, architects, integrators

Concrete actor + action + outcome descriptions for justsign. Each use case names who is doing what, under what constraints, and what a successful outcome looks like.

---

## UC-01: Rust build tool signs release artifacts without a Go binary on PATH

**Actor**: Platform engineer maintaining a Rust-based release pipeline.

**Context**: The pipeline produces OCI artifacts and needs to attach cosign signatures and SLSA provenance. The CI runner is a minimal Linux container or a Windows Server host — `cosign` is not installed and adding a Go binary to the runner image is blocked by the security team.

**Flow**:
1. Build produces the artifact bytes.
2. Pipeline calls `justsign::sign_blob_keyless()` with the artifact bytes and a GitHub Actions OIDC token provider.
3. justsign contacts Fulcio (HTTPS), obtains a short-lived certificate, signs, submits to Rekor, and returns a `Bundle`.
4. `Bundle::encode_json()` writes the `.sigstore.json` bundle alongside the artifact.

**Outcome**: Cosign-wire-compatible signature produced in-process. Verifiable by `cosign verify-blob` or any Sigstore-compatible verifier. No Go binary, no subprocess, no PATH dependency.

**Constraints satisfied**: Pure Rust — single static binary. Works on Windows CI runners. Blocking (sync) API compatible with non-async build tooling.

---

## UC-02: Hardware-backed signing via PKCS#11 HSM

**Actor**: Security engineer at a regulated institution (financial services, medical devices) where private signing keys must never leave an HSM or YubiKey.

**Context**: `cosign` supports PKCS#11 via an external plugin with subprocess invocation. `sigstore-rs` has no PKCS#11 surface. The team needs a library-level PKCS#11 integration with no fork/exec in the signing path.

**Flow**:
1. Build pipeline loads the PKCS#11 provider at runtime via `Pkcs11Signer::new("/usr/lib/libykcs11.so", slot, pin)`.
2. `justsign::sign_blob()` uses the `Pkcs11Signer` — key material never leaves the HSM.
3. Signature + Rekor entry produced. Bundle written alongside artifact.

**Outcome**: Signing key stays in hardware for the full signing call. No intermediate key material in process memory beyond the duration of the HSM operation.

**Constraints satisfied**: No subprocess. Provider library path is caller-supplied — supports YubiKey, SoftHSM2, and any vendor HSM that exposes a PKCS#11 interface.

---

## UC-03: Air-gapped pipeline signs against a self-hosted Sigstore instance

**Actor**: Infrastructure team in a classified or air-gapped environment with no outbound internet access.

**Context**: The public Sigstore endpoints (`fulcio.sigstore.dev`, `rekor.sigstore.dev`, `tuf.sigstore.dev`) are unreachable. The team runs a self-hosted Fulcio + Rekor + Trillian stack internally. They need a signing client that accepts custom endpoints and a caller-supplied TUF trust root.

**Flow**:
1. `FulcioClient::new("https://fulcio.internal")` and `RekorClient::new("https://rekor.internal")` point at the internal stack.
2. `TufTrustRoot::from_bytes(BUNDLED_ROOT_JSON)` loads an operator-approved snapshot of the TUF root — no network fetch required.
3. `sign_blob_keyless()` runs entirely against internal infrastructure.

**Outcome**: Keyless signing works in a fully air-gapped environment. The trust root is refreshed on a controlled cadence by the operator, not pulled from the internet at sign time.

**Constraints satisfied**: All endpoints are caller-configurable. TUF root is injectable — no implicit fetch from `tuf.sigstore.dev`.

---

## UC-04: Multi-algorithm verifier accepts signatures from heterogeneous signers

**Actor**: Platform team running a policy enforcement point that verifies artifacts signed by multiple teams, some using P-256 (legacy) and some using Ed25519 (new policy).

**Context**: Different teams adopted different algorithms at different times. The verifier must accept both without separate code paths or separate policy files per algorithm.

**Flow**:
1. Policy file lists a set of accepted `VerifyingKey` values — mix of `VerifyingKey::P256(...)` and `VerifyingKey::Ed25519(...)`.
2. `justsign::verify_blob()` accepts `&[VerifyingKey]` — tries each key against the bundle.
3. Verification passes if any key in the set validates the signature.

**Outcome**: Single verifier call handles all algorithm variants. Adding a new algorithm (P-384, secp256k1) requires adding a key to the policy list, not changing the verifier code.

**Constraints satisfied**: Algorithm selection is a runtime policy decision, not a compile-time choice. All four algorithms (P-256, Ed25519, P-384, secp256k1) are behind feature flags that compose cleanly.

---

## UC-05: CI staging environment tests the full sign-verify round trip

**Actor**: Library developer adding a new signing feature who needs to run an end-to-end test against the Sigstore staging environment.

**Context**: `sigstore-rs` blocks staging automation — `SigningContext::staging()` is not public (upstream issue #562). Without a staging e2e test, signing changes can only be validated against production, which is unacceptable for a library under development.

**Flow**:
1. Test calls `sign_blob_keyless()` against `fulcio.sigstore-test.dev` + `rekor.sigstore-test.dev`.
2. Until upstream issue #562 is resolved, the test is annotated with `#[skip_pass]` — it runs, reports its result, but does not fail CI.
3. When the staging gap closes, the annotation is removed and the test becomes a hard gate.

**Outcome**: The staging harness runs on every CI push today. When the upstream fix lands it activates automatically — no manual intervention required.

**Constraints satisfied**: Skip-pass pattern prevents staging flakiness from blocking unrelated PRs while keeping the test visible in CI output.
