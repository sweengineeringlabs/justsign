use p256::ecdsa::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sign::spec::sigstore_bundle::Bundle;
use sign::{EcdsaP256Signer, VerifyingKey, sign_blob, verify_blob};

use crate::{CaseConfig, SignRunner};

pub struct JustsignRunner {
    label: String,
    payload: Vec<u8>,
    signer: EcdsaP256Signer,
    /// Pre-computed bundle for verify iterations — avoids signing overhead
    /// inside the verify timing window.
    bundle: Bundle,
    trusted: Vec<VerifyingKey>,
}

impl JustsignRunner {
    pub fn new(case: CaseConfig) -> Self {
        let payload_bytes = case
            .params
            .get("payload_bytes")
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| panic!("justsign case '{}': missing param 'payload_bytes'", case.label))
            as usize;

        let payload: Vec<u8> = (0..payload_bytes).map(|i| i as u8).collect();

        // Deterministic keypair — same across every run for reproducibility.
        let sk = SigningKey::random(&mut ChaCha20Rng::from_seed([0x42u8; 32]));
        let trusted = vec![VerifyingKey::P256(*sk.verifying_key())];
        let signer = EcdsaP256Signer::new(sk, None);

        // Pre-sign once outside any timing window.
        let bundle = sign_blob(&payload, "application/octet-stream", &signer, None)
            .expect("justsign bench: setup sign_blob must succeed");

        Self { label: case.label, payload, signer, bundle, trusted }
    }
}

impl SignRunner for JustsignRunner {
    fn label(&self) -> &str {
        &self.label
    }

    fn payload_bytes(&self) -> u64 {
        self.payload.len() as u64
    }

    fn sign(&self) {
        sign_blob(&self.payload, "application/octet-stream", &self.signer, None)
            .expect("justsign bench: sign_blob must succeed");
    }

    fn verify(&self) {
        verify_blob(&self.bundle, &self.trusted, None)
            .expect("justsign bench: verify_blob must succeed");
    }
}
