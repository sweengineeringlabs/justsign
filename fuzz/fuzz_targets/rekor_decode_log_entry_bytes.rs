#![no_main]
//! Fuzz target: `rekor::client::decode_log_entry_bytes` must
//! surface a typed error or a successful decode for any byte slice
//! — never panic.
//!
//! This is the shared decoder that the blocking and async Rekor
//! clients both route through after they've taken bytes off the
//! wire. The function is pure (no I/O); the fuzzer drives it
//! directly with arbitrary bytes.

use libfuzzer_sys::fuzz_target;
use rekor::decode_log_entry_bytes;

fuzz_target!(|data: &[u8]| {
    let _ = decode_log_entry_bytes(data);
});
