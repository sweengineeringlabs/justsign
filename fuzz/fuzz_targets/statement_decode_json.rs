#![no_main]
//! Fuzz target: `spec::Statement::decode_json` (in-toto Statement
//! v1) must surface a typed error or a successful decode for any
//! byte slice — never panic. Statements are the JSON payload
//! wrapped inside a DSSE envelope; a malformed Statement should
//! produce `StatementDecodeError`, not unwind.

use libfuzzer_sys::fuzz_target;
use spec::Statement;

fuzz_target!(|data: &[u8]| {
    let _ = Statement::decode_json(data);
});
