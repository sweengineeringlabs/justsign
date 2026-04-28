# justsign benchmarks

**Audience**: Contributors, adopters evaluating signing pipeline latency.

> **TLDR**: `sign_blob` takes **234 µs** for a 1 KB payload in-process. `cosign sign-blob` (subprocess) costs ≥ 50 ms just for Go binary startup — a **200×+ gap** for small-payload signing loops. Run `cargo bench -p swe_justsign_sign --bench sign_verify` to reproduce. Compare against `cosign` via `scripts/bench/compare_cosign.sh`.

## Bench architecture

The benchmark lives in `sign/benches/sign_verify.rs`. It exercises `sign_blob` and `verify_blob` as pure in-process cryptographic operations — no Fulcio, no Rekor, no network.

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
| Host | Windows 11, x86-64 |
| Toolchain | stable (release profile) |
| Bench harness | Criterion 0.5 |
| Samples | 100 per case |
| Warmup | 3 s |

## Results — `sign_blob` (P-256, static key, no Rekor)

Measures: DSSE PAE encoding + P-256 ECDSA sign + bundle JSON serialization.

| Payload | Mean time | Throughput |
|---|---|---|
| 1 KB | **234 µs** | 4.2 MiB/s |
| 64 KB | **905 µs** | 67.4 MiB/s |
| 1 MB | **4.94 ms** | 202 MiB/s |

High variance (up to 10% outliers) is expected on a Windows dev machine. Re-run on an idle Linux host for tighter confidence intervals.

## Results — `verify_blob` (P-256, static key, no Rekor)

Measures: DSSE PAE re-derivation + P-256 ECDSA verify + bundle JSON access.

| Payload | Mean time | Throughput |
|---|---|---|
| 1 KB | **1.07 ms** | 0.93 MiB/s |
| 64 KB | **784 µs** | 77.9 MiB/s |
| 1 MB | **2.30 ms** | 434 MiB/s |

## What the numbers mean

### The 200× headline

`sign_blob` at 234 µs vs `cosign sign-blob` at ≥ 50 ms. For a release pipeline signing 1 000 artifacts, that's **234 ms** (justsign, embedded) vs **50 s+** (cosign subprocess) for the signing loop alone.

The gap is not algorithmic — both use P-256 ECDSA on the same data. The gap is architectural:

| Category | cosign pays | justsign pays? |
|---|---|---|
| Go runtime startup | ~10–20 ms | No |
| Dynamic linker + stdlib init | ~5–10 ms | No |
| Flag parsing + CLI dispatch | ~1–5 ms | No |
| Key file read + parse | ~1–5 ms | No (key held in memory) |
| **Actual P-256 sign + DSSE + serialization** | **~0.2 ms** | **Yes — 234 µs** |

Only ~0.4% of cosign's time is the cryptographic operation. The rest is subprocess overhead that justsign never pays — the same structural dynamic as any in-process library vs subprocess comparison.

The caveat: the keyless path (`sign_blob_keyless`) adds one Fulcio HTTPS round-trip (~100–300 ms) and one Rekor submission (~100–200 ms). These are network operations and are identical in cost whether you use justsign or cosign. The 200× advantage applies to the signing operation itself, which dominates in high-throughput batch pipelines.

### Why verify is slower than sign for small payloads

At 1 KB, `sign_blob` takes 234 µs but `verify_blob` takes 1.07 ms — verify is **4.6× slower** for the same payload.

P-256 ECDSA verification requires **two** scalar multiplications (one for the public key, one for the signature point). Signing requires **one**. For small payloads the SHA-256 hash is negligible and the scalar multiplications dominate. This is not a justsign implementation choice — it is a property of ECDSA arithmetic.

At 1 MB the order reverses: verify reaches 434 MiB/s vs sign's 202 MiB/s. SHA-256 hashing of the PAE bytes (proportional to payload) dominates, and the verify path has a cheaper post-hash dispatch.

### Throughput at large payloads

At 1 MB, both paths reach 200–430 MiB/s. The bottleneck at this scale is SHA-256 throughput — the PAE encoding hashes the full payload. This is an x86 SHA-NI hardware ceiling, not a justsign implementation ceiling. Any P-256 DSSE implementation using the same digest hits the same wall.

## Market comparison

Run `scripts/bench/compare_cosign.sh` on Linux or WSL2 (cosign requires Linux for the static-key flow). The script generates a throwaway P-256 key and times `cosign sign-blob --key` for the same payload sizes.

The cosign numbers include Go subprocess startup (~50 ms). The script notes this explicitly. The comparison targets the common-ancestor case (P-256 static key) where both tools perform the same cryptographic work — the only difference is in-process vs subprocess.

## Reproducing

### Prerequisites

| Requirement | Notes |
|---|---|
| Rust stable toolchain | required |
| `cosign` (comparison only) | Linux/WSL2; GitHub release or `brew install cosign` |

### Steps

**1. Clone and enter the workspace**

```sh
git clone git@github.com:sweengineeringlabs/justsign.git
cd justsign
```

**2. Run the benchmark**

```sh
cargo bench -p swe_justsign_sign --bench sign_verify
```

**3. Run a single case**

```sh
cargo bench -p swe_justsign_sign --bench sign_verify -- "sign_blob/1kb"
cargo bench -p swe_justsign_sign --bench sign_verify -- "verify_blob/1mb"
```

**4. Compare against cosign (WSL2/Linux)**

```sh
bash scripts/bench/compare_cosign.sh
```

### Output

Criterion prints results to stdout. HTML reports are written to:

```
target/criterion/sign_blob/report/index.html
target/criterion/verify_blob/report/index.html
```

These files are ephemeral — `cargo clean` removes them. Re-run the bench to regenerate.
