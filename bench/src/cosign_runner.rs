use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tempfile::TempDir;

use crate::{CaseConfig, SignRunner};

pub struct CosignRunner {
    label: String,
    payload_bytes: u64,
    key_path: PathBuf,
    payload_path: PathBuf,
    _tmp: TempDir,
}

impl CosignRunner {
    pub fn new(case: CaseConfig) -> Self {
        which_cosign();

        let payload_bytes = case
            .params
            .get("payload_bytes")
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| panic!("cosign case '{}': missing param 'payload_bytes'", case.label))
            as u64;

        let tmp = TempDir::new().expect("cosign bench: failed to create work dir");

        // Generate a deterministic P-256 key and write as PKCS#8 PEM.
        // cosign sign-blob --key accepts PKCS#8 PEM private keys.
        let sk = SigningKey::random(&mut ChaCha20Rng::from_seed([0x43u8; 32]));
        let key_pem = sk
            .to_pkcs8_pem(LineEnding::LF)
            .expect("cosign bench: failed to encode private key as PEM");
        let key_path = tmp.path().join("key.pem");
        fs::write(&key_path, key_pem.as_bytes())
            .expect("cosign bench: failed to write key.pem");

        // Write payload once; re-used across all iterations.
        let payload: Vec<u8> = (0..payload_bytes as usize).map(|i| i as u8).collect();
        let payload_path = tmp.path().join("payload.bin");
        fs::write(&payload_path, &payload)
            .expect("cosign bench: failed to write payload");

        Self { label: case.label, payload_bytes, key_path, payload_path, _tmp: tmp }
    }
}

impl SignRunner for CosignRunner {
    fn label(&self) -> &str {
        &self.label
    }

    fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    fn sign(&self) {
        let status = Command::new("cosign")
            .args([
                "sign-blob",
                "--key",
                self.key_path.to_str().expect("key path is valid utf-8"),
                "--output-signature",
                "/dev/null",
                "--yes",
                self.payload_path.to_str().expect("payload path is valid utf-8"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("cosign bench: failed to spawn cosign sign-blob");
        assert!(status.success(), "cosign sign-blob exited with {status}");
    }

    fn has_verify(&self) -> bool {
        // cosign verify-blob for a static key requires the signature from a
        // prior sign-blob call. The sign bench discards the signature
        // (--output-signature /dev/null) to avoid including file I/O in the
        // signing timing window. A separate verify benchmark would need to
        // pre-compute and store the signature, coupling sign and verify runs.
        // Omitted from this bench; see scripts/bench/compare_cosign.sh for a
        // full sign+verify comparison.
        false
    }

    fn verify(&self) {
        unimplemented!("CosignRunner::verify — see has_verify()")
    }
}

fn which_cosign() {
    Command::new("cosign")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|_| panic!(
            "cosign not found on PATH — the cosign bench requires Linux or WSL2 with cosign 2.x installed"
        ));
}
