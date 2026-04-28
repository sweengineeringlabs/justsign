//! Criterion benchmarks for `sign_blob` and `verify_blob`.
//!
//! Measures: pure in-process sign + verify latency with a static P-256
//! keypair — no Fulcio, no Rekor, no network. This isolates the
//! RustCrypto ECDSA + DSSE PAE + JSON serialization cost.
//!
//! Run:
//!   cargo bench -p swe_justsign_sign --bench sign_verify
//!
//! Market comparison (subprocess startup included):
//!   scripts/bench/compare_cosign.sh   (requires cosign 3.x on PATH)

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use p256::ecdsa::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sign::{EcdsaP256Signer, VerifyingKey, sign_blob, verify_blob};

/// Seeded RNG — deterministic across runs so the keypair is stable.
fn seeded_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0x42u8; 32])
}

fn bench_sign_blob(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_blob");

    let payloads: &[(usize, &str)] = &[
        (1_024,        "1KB"),
        (64_000,       "64KB"),
        (1_048_576,    "1MB"),
    ];

    for &(size, label) in payloads {
        let payload: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let sk = SigningKey::random(&mut seeded_rng());
        let signer = EcdsaP256Signer::new(sk, None);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("justsign", label),
            &payload,
            |b, p| {
                b.iter(|| {
                    sign_blob(p, "application/octet-stream", &signer, None)
                        .expect("sign_blob must succeed")
                });
            },
        );
    }
    group.finish();
}

fn bench_verify_blob(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_blob");

    let payloads: &[(usize, &str)] = &[
        (1_024,        "1KB"),
        (64_000,       "64KB"),
        (1_048_576,    "1MB"),
    ];

    for &(size, label) in payloads {
        let payload: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let sk = SigningKey::random(&mut seeded_rng());
        let trusted = vec![VerifyingKey::P256(*sk.verifying_key())];
        let signer = EcdsaP256Signer::new(sk, None);
        let bundle = sign_blob(&payload, "application/octet-stream", &signer, None)
            .expect("setup: sign_blob must succeed");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new("justsign", label), |b| {
            b.iter(|| verify_blob(&bundle, &trusted, None).expect("verify_blob must succeed"));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_sign_blob, bench_verify_blob);
criterion_main!(benches);
