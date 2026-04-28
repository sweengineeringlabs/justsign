use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct BenchConfig {
    pub case: Vec<CaseConfig>,
}

#[derive(Debug, Deserialize)]
pub struct CaseConfig {
    pub runner: String,
    pub label: String,
    #[serde(flatten)]
    pub params: HashMap<String, toml::Value>,
}

/// SPI implemented by every sign/verify runner.
///
/// Each runner owns its reusable state (keypair, payload, pre-computed
/// bundle, etc.). The harness calls `sign()` and `verify()` in tight
/// loops — runners must not perform setup inside those methods.
///
/// `has_verify` allows runners that cannot produce a verifiable offline
/// signature (e.g. cosign, which needs a Rekor bundle for full
/// verification) to opt out of the verify benchmark group.
pub trait SignRunner {
    fn label(&self) -> &str;
    fn payload_bytes(&self) -> u64;
    fn sign(&self);
    fn has_verify(&self) -> bool {
        true
    }
    fn verify(&self);
}

pub fn load_runners() -> Vec<Box<dyn SignRunner>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/bench.toml");
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let config: BenchConfig = toml::from_str(&src)
        .unwrap_or_else(|e| panic!("invalid bench.toml: {e}"));
    config.case.into_iter().filter_map(build_runner).collect()
}

fn build_runner(case: CaseConfig) -> Option<Box<dyn SignRunner>> {
    match case.runner.as_str() {
        #[cfg(feature = "justsign")]
        "justsign" => Some(Box::new(justsign_runner::JustsignRunner::new(case))),
        #[cfg(feature = "cosign")]
        "cosign" => Some(Box::new(cosign_runner::CosignRunner::new(case))),
        other => {
            eprintln!("bench: skipping '{other}' — feature not enabled");
            None
        }
    }
}

#[cfg(feature = "justsign")]
mod justsign_runner;
#[cfg(feature = "cosign")]
mod cosign_runner;
