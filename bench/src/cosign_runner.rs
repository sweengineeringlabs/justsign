use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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

        // Generate a cosign key pair with empty password (COSIGN_PASSWORD suppresses prompt).
        // cosign v3 uses its own ENCRYPTED SIGSTORE PRIVATE KEY format — PKCS#8 PEM is rejected.
        let key_prefix = tmp.path().join("key");
        let key_prefix_str = key_prefix.to_str().expect("key prefix is valid utf-8");
        let status = Command::new("cosign")
            .args(["generate-key-pair", "--output-key-prefix", key_prefix_str])
            .env("COSIGN_PASSWORD", "")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("cosign bench: failed to spawn cosign generate-key-pair");
        assert!(status.success(), "cosign generate-key-pair exited with {status}");

        let key_path = tmp.path().join("key.key");

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
                "--bundle",
                "/dev/null",
                "--yes",
                self.payload_path.to_str().expect("payload path is valid utf-8"),
            ])
            .env("COSIGN_PASSWORD", "")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("cosign bench: failed to spawn cosign sign-blob");
        assert!(status.success(), "cosign sign-blob exited with {status}");
    }

    fn has_verify(&self) -> bool {
        // cosign verify-blob for a static key requires the bundle from a prior
        // sign-blob call. The sign bench discards the bundle (--bundle /dev/null)
        // to avoid including file I/O in the signing timing window. A separate
        // verify benchmark would need to pre-compute and store the bundle,
        // coupling sign and verify runs. Omitted from this bench.
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
            "cosign not found on PATH — the cosign bench requires Linux or WSL2 with cosign 2.x+ installed"
        ));
}
