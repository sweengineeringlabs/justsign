#![no_main]
//! Fuzz target: `fulcio::chain::parse_chain` (the public PEM-chain
//! parser) must surface a typed error or a successful parse for any
//! byte slice — never panic.
//!
//! Inputs flow PEM-decode → DER-parse → X.509 extension walk;
//! every layer is a place a hostile certificate chain can try to
//! trip the parser. The target asserts that no such input panics.

use libfuzzer_sys::fuzz_target;
use fulcio::parse_chain;

fuzz_target!(|data: &[u8]| {
    let _ = parse_chain(data);
});
