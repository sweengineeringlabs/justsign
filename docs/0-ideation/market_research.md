# Market research

**Audience**: Product leads, architects, contributors

Ecosystem facts and producer niche analysis behind justsign's positioning. Two questions answered here: (1) what does the Rust Sigstore tooling landscape look like, and (2) who actually needs a pure-Rust, embeddable Sigstore client?

---

## Rust Sigstore ecosystem survey

Survey of existing Sigstore client implementations — Rust crates, Go tooling, and language bindings — and why none covers the pure-Rust, embeddable, audit-clean case that justsign targets.

### The reference implementation: cosign (Go)

`cosign` is the Sigstore project's primary CLI and reference implementation, written in Go.

| Property | Value |
|----------|-------|
| Capabilities | Sign blobs, containers, and attestations; verify; TUF root management |
| Language | Go — not embeddable in Rust |
| Rust integration | Subprocess only (`std::process::Command`) |
| Determinism | Non-deterministic process invocations; no stable library API surface |
| Dep graph | ~300 Go modules; pulls in AWS/GCP/Azure SDKs transitively |
| Air-gapped use | Requires Go binary on PATH; binary size ~50 MB |

Subprocess invocation of `cosign` is the pattern used by most Rust projects that need Sigstore today. It works until it doesn't: hard dependencies on the host environment, hermetic build failures, and expensive test isolation.

### The existing Rust crate: `sigstore-rs`

`sigstore-rs` is the Sigstore project's official Rust client library, maintained by the Sigstore community.

| Property | Value |
|----------|-------|
| Capabilities | Sign + verify blobs and containers; Fulcio + Rekor clients; TUF root handling |
| Pure Rust | Partial — historically spawned `cosign` subprocess for some signing paths; pure-Rust migration ongoing |
| Dep graph | Heavy: pulls in `tokio`, `hyper`, `rustls`, `x509-cert`, `ecdsa`, `p256`, plus optional AWS/GCP/Azure credential crates |
| API stability | Alpha; breaking changes between minor versions |
| Key gap | No public `SigningContext::staging()` as of survey date (upstream [sigstore/sigstore-rs#562](https://github.com/sigstore/sigstore-rs/issues/562)) — blocks staging e2e signing from being automated |
| PKCS#11 | Not supported |
| Multi-algo | P-256 only in stable API |
| Async | Required — no blocking client |
| MSRV | Tracks latest stable; no MSRV stability commitment |

`sigstore-rs` is the correct starting point for most Rust projects. The gaps that drove justsign are:

1. **Subprocess residue.** The pure-Rust migration is incomplete; some code paths still invoke `cosign` or rely on cosign being on `$PATH` for the staging environment.
2. **API gaps.** `SigningContext::staging()` is not public. No PKCS#11 surface. No multi-algorithm `VerifyingKey` enum.
3. **Dep graph size.** The async-only design forces `tokio` into every consumer. For synchronous build tools this is unnecessary weight.
4. **No blocking clients.** `reqwest::blocking` works for build tooling; `sigstore-rs` provides only async clients.
5. **MSRV instability.** A library that breaks on the previous Rust stable is a problem for projects with conservative MSRV policies.

### Other language clients

| Client | Language | Rust embeddable? | Notes |
|--------|----------|-----------------|-------|
| `python-sigstore` | Python | No | Reference Python client; subprocess or IPC only from Rust |
| `sigstore-java` | Java | No | JVM; not embeddable |
| `sigstore-go` | Go | No | Newer Go client; same subprocess problem as cosign |
| `sigstore-js` | TypeScript/Node | No | Browser/Node only |

No language client other than `sigstore-rs` is embeddable in Rust. For teams that want Sigstore without Go on the PATH, the choice is `sigstore-rs` or DIY.

### The DIY approach

Some teams assemble a Sigstore-compatible signing pipeline from raw cryptographic primitives:

- `p256` / `ed25519` crates for key material
- `reqwest` for HTTP calls to Fulcio and Rekor
- `serde_json` for bundle serialisation
- Manual DSSE envelope construction

This works for simple sign-a-blob use cases but quickly becomes unmaintainable:

- DSSE envelope format is subtle (PAE encoding, base64url vs base64)
- Rekor submission requires Merkle inclusion proof verification
- TUF root handling requires span-preserving JSON verification to prevent signature drift
- Bundle v0.3 wire format changed the `verificationMaterial.certificate` shape between cosign 2.x and 3.x — DIY code has to track these changes manually

justsign packages all of this into one crate with a stable API, tested against the production Sigstore endpoints.

### The gap

| Requirement | `cosign` subprocess | `sigstore-rs` | DIY | **justsign** |
|-------------|:------------------:|:-------------:|:---:|:------------:|
| Pure Rust (no subprocess) | ✗ | Partial | ✓ | ✓ |
| Embeddable as library | ✗ | ✓ | ✓ | ✓ |
| Blocking (sync) clients | ✗ | ✗ | ✓ | ✓ |
| PKCS#11 hardware keys | ✗ | ✗ | Manual | ✓ |
| Multi-algorithm verifier | ✓ | Partial | Manual | ✓ |
| Audit-clean dep graph | N/A | ✗ | ✓ | ✓ |
| Stable MSRV | N/A | ✗ | ✓ | ✓ |
| Staging e2e automation | ✓ | Blocked (#562) | Manual | ✓ (skip-pass) |
| cosign-wire compatible | ✓ | ✓ | Manual | ✓ |

justsign occupies the "embeddable, sync, multi-algo, pure-Rust" slot that `sigstore-rs` doesn't fully cover today.

### Risk and counter-arguments

**"Just use `sigstore-rs` — it's the official client."**
Correct for most projects. The gaps that drove justsign are specific: sync build tooling, PKCS#11, multi-algo verifier, and the staging API gap. For async-only services that only need P-256, `sigstore-rs` is the right choice.

**"The staging API gap in `sigstore-rs` will be fixed eventually."**
Yes, and justsign will track it (issue #21). In the meantime, justsign's skip-pass test pattern lets CI run the staging harness today — it SKIP-passes until the upstream fix lands, then activates automatically.

**"Maintaining a second Rust Sigstore client increases ecosystem fragmentation."**
Acknowledged. The mitigation is wire compatibility: justsign's bundles are byte-for-byte identical to what `cosign` and `sigstore-rs` produce. A consumer that already trusts cosign-produced signatures doesn't need to adopt justsign to verify them.

**"PKCS#11 is niche."**
True for SaaS. Less true for HSM-gated signing in regulated industries (financial services, medical devices, government) where key material must not leave hardware. No existing Rust Sigstore client covers this path.

---

## The pure-Rust Sigstore client niche

Who needs an embeddable pure-Rust Sigstore client — and why the existing toolchain fails them.

### The subprocess problem

The current state of Rust + Sigstore is: shell out to `cosign`. This works until it doesn't:

| Constraint | Impact |
|------------|--------|
| `cosign` must be on `$PATH` | Breaks hermetic builds, CI agents, Windows pipelines |
| Process spawning is non-deterministic | Different exit codes / stdout across OS versions; can't unit-test without mocking the subprocess |
| Binary size ~50 MB | Unacceptable for minimal base images, embedded targets, WASM sandboxes |
| No structured error surface | Parsing `stderr` for error classification is fragile |
| `cosign` API changes between versions | The `--certificate-chain` → `--certificate` rename in cosign 3.x broke many pipelines |

A pure-Rust library eliminates all five. Error types are Rust enums, not stderr strings. The dependency is in `Cargo.toml`, not in the CI runner's PATH.

### Concrete producer categories

#### Rust build tooling that needs Sigstore

The canonical case. A Rust tool that produces OCI artifacts or VM images needs to attach SLSA provenance + cosign signatures. Shelling out to `cosign` is the path of least resistance — until the build is hermetic, or runs on Windows, or the CI agent image doesn't include Go.

`sigstore-rs`'s async-only API and the staging API gap (`SigningContext::staging()` not public) block CI automation for synchronous build tools. justsign resolves both: a blocking client by default, and a skip-pass staging harness that activates automatically when the upstream gap closes.

#### CI pipelines with hermetic build requirements

Bazel, Buck2, and Nix enforce that build actions declare all inputs. A `cosign` binary call is an undeclared host dependency — it violates hermeticity. A Rust crate dependency is declared in `Cargo.toml` and tracked by the lockfile.

For these pipelines, an embeddable library is not optional; it's the only compliant path.

#### Windows-native build pipelines

`cosign` ships no native Windows build from the Sigstore project. Teams running Windows-native CI (not WSL2, not Docker) that need to sign OCI artifacts or blobs have no supported cosign path. A pure-Rust library that builds on Windows with `cargo build` is the only option.

#### PKCS#11 hardware-backed signing

Regulated industries (financial services, medical devices, government contracting) require that private signing keys never leave a hardware security module (HSM) or smartcard (YubiKey). cosign supports PKCS#11 via an external plugin; `sigstore-rs` does not.

justsign's `--features pkcs11` exposes a `Pkcs11Signer` that loads the PKCS#11 provider from a caller-supplied path at runtime — no fork, no subprocess, no key material in process memory longer than the signing call.

#### Air-gapped environments

Classified networks, industrial control systems, and some financial environments prohibit outbound internet access. cosign's binary update mechanism assumes internet access; its TUF bootstrap assumes access to `tuf.sigstore.dev`.

justsign's TUF crate accepts a caller-supplied trust root, enabling an operator to bundle an approved snapshot of the Sigstore trust root and refresh it on a controlled cadence — without requiring the build agent to reach the public-good Sigstore infrastructure.

#### Multi-algorithm signing requirements

NIST SP 800-208 recommends algorithm agility. Some organisations require Ed25519 for new signing keys (smaller signatures, faster verification) while maintaining P-256 for legacy interoperability. cosign's primary surface is P-256 ECDSA; multi-algo support is fragmented.

justsign's `VerifyingKey` enum unifies P-256, Ed25519, P-384, and secp256k1 behind a single type. A verifier that accepts `&[VerifyingKey]` handles all four algorithms with no code changes when a new algorithm is added.

### What "production-ready" means for this niche

All of the above categories share the same bar:

1. **cosign-wire compatible.** Bundles produced by justsign must be verifiable by `cosign verify-blob`. This is the interoperability baseline — existing consumers of cosign-signed artifacts don't need to adopt justsign to verify them.
2. **Production Sigstore round-trip.** Sign with justsign, verify with cosign, against production Fulcio + Rekor. The round-trip runbook documents the manual check; CI automation is the next step.
3. **No subprocess calls.** The library must not spawn `cosign`, `openssl`, or any other external binary in the production code path.
4. **Typed errors.** Every failure path returns a typed variant, not a string. Callers must be able to distinguish `RekorSubmitFailed` from `CertExpired` from `BundleDecodeFailed`.
5. **Sync and async.** Build tools are synchronous; long-running services are async. A library that forces `tokio` on build tools, or blocks threads in services, isn't production-ready for both.
