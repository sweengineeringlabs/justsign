#![no_main]
//! Fuzz target: `tuf::canonical::canonicalize` must surface a typed
//! error or successful output for any `serde_json::Value` — never
//! panic.
//!
//! `canonicalize` takes an already-parsed `Value`, so we first feed
//! the fuzz input to `serde_json::from_slice`. If that fails we
//! return early — it's not the canonicaliser's job to handle non-
//! JSON. If it succeeds, we hand the parsed `Value` to
//! `canonicalize` and drop whatever it returns. The contract under
//! test is "any well-formed JSON is canonicalisable without panic".

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use tuf::canonicalize;

fuzz_target!(|data: &[u8]| {
    let value: Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return,
    };
    let _ = canonicalize(&value);
});
