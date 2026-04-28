# justsign benchmarks

**Audience**: Contributors, adopters evaluating signing pipeline latency.

> **TLDR**: `sign_blob` takes **312 µs** for a 1 KB payload in-process. `cosign sign-blob` costs **3,750 ms** per call — a **~12,000× gap** driven by scrypt key decryption on every invocation plus Go subprocess overhead. Run `cargo bench -p swe_justsign_bench --bench sign_verify --features cosign` on Linux/WSL2 to reproduce.

## Bench architecture

The benchmark lives in `bench/benches/sign_verify.rs`. It exercises `sign_blob` and `verify_blob` as pure in-process cryptographic operations — no Fulcio, no Rekor, no network. The `cosign` feature adds a `CosignRunner` that invokes `cosign sign-blob` as a subprocess for direct comparison.

### Signer SPI

`sign_blob` dispatches through a `Signer` trait:

```rust
pub trait Signer: Send + Sync {
    fn key_id(&self) -> Option<String>;
    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignerError>;
}
```

`&self` (not `&mut self`) allows `Arc<dyn Signer>` sharing across threads. The bench uses `EcdsaP256Signer` — the default signer. Ed25519, P-384, and secp256k1 are feature-gated; the harness wires in any `impl Signer`.

### What `sign_blob()` measures

The timing window covers:

1. **PAE encoding** — `spec::pae(payload_type.as_bytes(), payload)` per the DSSE spec
2. **ECDSA-P256 sign** — `signer.sign(&pae_bytes)` → SHA-256 hash + scalar multiplication → DER signature
3. **Bundle construction** — DSSE envelope + Sigstore Bundle v0.3 JSON serialization

No Fulcio HTTPS round-trip. No Rekor submission. No network. The keyless path (`sign_blob_keyless`) adds ~100–300 ms (Fulcio) + ~100–200 ms (Rekor) — identical costs whether you use justsign or cosign.

### What `verify_blob()` measures

The timing window covers:

1. **PAE re-derivation** — `envelope.pae()` re-encodes the canonical authenticated bytes
2. **ECDSA-P256 verify** — SHA-256 hash + two scalar multiplications → accept/reject
3. **Policy check** — "at least one signature validates" against trusted key set

### Allocation isolation

- Payloads are pre-generated as `Vec<u8>` (same bytes every iteration — no allocation in the loop)
- SigningKey created once per payload size via seeded RNG (`ChaCha20Rng::from_seed([0x42u8; 32])`) — deterministic, reproducible keypair across runs
- `verify_blob` signs once outside the timing window, then measures verify iterations against the same bundle

## Environment

| Field | Value |
|---|---|
| Date | 2026-04-28 |
| Host | Ubuntu 24.04 (WSL2), x86-64 |
| Toolchain | stable (release profile) |
| Bench harness | Criterion 0.5 |
| Samples | 100 per case |
| Warmup | 3 s |
| cosign version | v3.0.6 |

## Results — `sign_blob` (P-256, static key, no Rekor)

Measures: DSSE PAE encoding + P-256 ECDSA sign + bundle JSON serialization.

| Payload | Mean time | Throughput |
|---|---|---|
| 1 KB | **312 µs** | 3.12 MiB/s |
| 64 KB | **415 µs** | 150.8 MiB/s |
| 1 MB | **2.61 ms** | 383 MiB/s |

## Results — `verify_blob` (P-256, static key, no Rekor)

Measures: DSSE PAE re-derivation + P-256 ECDSA verify + bundle JSON access.

| Payload | Mean time | Throughput |
|---|---|---|
| 1 KB | **466 µs** | 2.09 MiB/s |
| 64 KB | **487 µs** | 128.3 MiB/s |
| 1 MB | **1.46 ms** | 683 MiB/s |

## Comparison — sign: justsign vs cosign

cosign has no offline verify bench — `cosign verify-blob` for a static key requires the bundle written by a prior `sign-blob` call, coupling the two runs. Only sign is compared here.

| Payload | justsign (in-process) | cosign (subprocess) | advantage |
|---|---|---|---|
| 1 KB | **312 µs** | 3,750 ms | **~12,000×** |
| 64 KB | **415 µs** | 4,181 ms | **~10,000×** |
| 1 MB | **2.61 ms** | 3,800 ms | **~1,455×** |

## What the numbers mean

### The ~12,000× gap

cosign's ~3.5–4 s floor breaks down into two structural costs:

| Category | cosign pays per call | justsign pays? |
|---|---|---|
| Go runtime startup + stdlib init | ~50–100 ms | No (in-process) |
| **scrypt key decryption** (`N=65536`) | **~3,400 ms** | **No (key held in memory)** |
| Key file read + parse | ~5 ms | No |
| Flag parsing + CLI dispatch | ~5 ms | No |
| **Actual P-256 sign + DSSE + serialization** | **~0.3 ms** | **Yes — 312 µs** |

The dominant cost is **scrypt key decryption on every invocation**. cosign v3 generates keys in `ENCRYPTED SIGSTORE PRIVATE KEY` format using `scrypt(N=65536, r=8, p=1)` — deliberately expensive for key storage security. The problem is it runs the full KDF on every `sign-blob` call, even with an empty password. justsign parses and holds the key in memory once at process startup; in a batch pipeline that cost is paid once not per-artifact.

For a release pipeline signing 1,000 artifacts: **312 ms** (justsign) vs **~3,750 s / 62 minutes** (cosign subprocess) for the signing loop alone.

### Why verify is slower than sign for small payloads

At 1 KB, `sign_blob` takes 312 µs but `verify_blob` takes 466 µs — verify is **1.49× slower** for the same payload.

P-256 ECDSA verification requires **two** scalar multiplications (one for the public key, one for the signature point). Signing requires **one**. For small payloads the SHA-256 hash is negligible and the scalar multiplications dominate. This is a property of ECDSA arithmetic, not a justsign implementation choice.

At 1 MB the order reverses: verify reaches 683 MiB/s vs sign's 383 MiB/s. SHA-256 hashing of the PAE bytes dominates, and the verify path has a cheaper post-hash dispatch.

### Throughput at large payloads

At 1 MB, sign reaches 383 MiB/s and verify 683 MiB/s. The bottleneck is SHA-256 throughput — the PAE encoding hashes the full payload. This is an x86 SHA-NI ceiling, not a justsign implementation ceiling.

## Reproducing

### Prerequisites

| Requirement | Notes |
|---|---|
| Rust stable toolchain | required |
| cosign 2.x+ (comparison only) | Linux/WSL2 — `~/.local/bin/cosign` or `brew install cosign` |

### Steps

**1. Clone and enter the workspace**

```sh
git clone git@github.com:sweengineeringlabs/justsign.git
cd justsign
```

**2. Run the benchmark (justsign only)**

```sh
cargo bench -p swe_justsign_bench --bench sign_verify
```

**3. Run with cosign comparison (Linux/WSL2)**

```sh
cargo bench -p swe_justsign_bench --bench sign_verify --features cosign
```

**4. Run a single case**

```sh
cargo bench -p swe_justsign_bench --bench sign_verify -- "sign_blob/justsign/1kb"
cargo bench -p swe_justsign_bench --bench sign_verify -- "verify_blob/justsign/1mb"
```

### Output

Criterion prints results to stdout. HTML reports are written to:

```
target/criterion/sign_blob/report/index.html
target/criterion/verify_blob/report/index.html
```

These files are ephemeral — `cargo clean` removes them. Re-run the bench to regenerate.
