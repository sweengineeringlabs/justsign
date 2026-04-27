#![no_main]
//! Fuzz target: `spec::Envelope::decode_json` must surface a typed
//! error or a successful decode for any byte slice — never panic.
//!
//! Wire-decode parsers consume bytes from untrusted sources (a
//! Sigstore bundle pulled from a registry, a DSSE envelope handed
//! over a network). A panic on any of them is a denial-of-service
//! against verifiers; this harness asserts no panic regardless of
//! input shape.

use libfuzzer_sys::fuzz_target;
use spec::Envelope;

fuzz_target!(|data: &[u8]| {
    let _ = Envelope::decode_json(data);
});
