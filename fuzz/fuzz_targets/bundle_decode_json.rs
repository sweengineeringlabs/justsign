#![no_main]
//! Fuzz target: `spec::Bundle::decode_json` (Sigstore Bundle v0.3)
//! must surface a typed error or a successful decode for any byte
//! slice — never panic. Bundles arrive over a registry pull or a
//! signed-attestation download; the parser is squarely on the
//! attack surface.

use libfuzzer_sys::fuzz_target;
use spec::Bundle;

fuzz_target!(|data: &[u8]| {
    let _ = Bundle::decode_json(data);
});
