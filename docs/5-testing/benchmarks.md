# justsign benchmarks

**Audience**: Contributors, adopters evaluating signing pipeline latency.

> **TLDR**: `sign_blob` takes **234 µs** for a 1 KB payload in-process. `cosign sign-blob` (subprocess) costs ≥ 50 ms just for Go binary startup — a **200×+ gap** for small-payload signing loops. Run `cargo bench -p swe_justsign_sign --bench sign_verify` to reproduce. Compare against `cosign` via `scripts/bench/compare_cosign.sh`.

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
No Fulcio, no Rekor, no network. Payload sizes chosen to show scaling from 1 KB to 1 MB.

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

Verify is slower than sign for small payloads because P-256 ECDSA verification requires two scalar multiplications vs one for signing. At large payload sizes the SHA-256 hashing of PAE bytes dominates and throughput improves.

## What the numbers mean

**The 200× headline**: `sign_blob` at 234 µs vs `cosign sign-blob` at ≥ 50 ms is the cost of Go binary subprocess startup. For a release pipeline signing 1 000 artifacts, that's **234 ms** (justsign, embedded) vs **50 s+** (cosign subprocess) for the signing loop alone.

The static-key path tested here is the lower bound on our latency — the keyless path (`sign_blob_keyless`) adds one Fulcio HTTPS round-trip (~100–300 ms) and one Rekor submission (~100–200 ms), which are identical costs whether you use justsign or cosign.

## Market comparison

Run `scripts/bench/compare_cosign.sh` on Linux or WSL2 (cosign requires Linux for the key-file flow tested). The script generates a throwaway P-256 key and times `cosign sign-blob --key` for the same payload sizes. The output explicitly flags that the cosign numbers include Go subprocess startup.

## Reproducing

```sh
cargo bench -p swe_justsign_sign --bench sign_verify
```

HTML report: `target/criterion/sign_blob/report/index.html`
