//! Runner-agnostic Criterion sign/verify benchmark.
//!
//! Cases are driven by `bench/bench.toml`. Add entries there to bench
//! new runners or payload sizes without touching this file.
//!
//! Run:
//!   cargo bench -p swe_justsign_bench --bench sign_verify
//!   cargo bench -p swe_justsign_bench --bench sign_verify --features cosign   (Linux/WSL2)
//!
//! Single case:
//!   cargo bench -p swe_justsign_bench --bench sign_verify -- "sign_blob/justsign/1kb"
//!   cargo bench -p swe_justsign_bench --bench sign_verify -- "verify_blob/justsign/1mb"

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use swe_justsign_bench::load_runners;

fn bench_sign(c: &mut Criterion) {
    let runners = load_runners();
    let mut group = c.benchmark_group("sign_blob");
    for runner in &runners {
        group.throughput(Throughput::Bytes(runner.payload_bytes()));
        group.bench_function(
            BenchmarkId::from_parameter(runner.label()),
            |b| b.iter(|| runner.sign()),
        );
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let runners = load_runners();
    let mut group = c.benchmark_group("verify_blob");
    for runner in runners.iter().filter(|r| r.has_verify()) {
        group.throughput(Throughput::Bytes(runner.payload_bytes()));
        group.bench_function(
            BenchmarkId::from_parameter(runner.label()),
            |b| b.iter(|| runner.verify()),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_sign, bench_verify);
criterion_main!(benches);
