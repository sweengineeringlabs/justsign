#![no_main]
//! Fuzz target: `tuf::span::parse_with_signed_span::<Root>` must
//! surface a typed error or a successful parse for any byte slice
//! — never panic.
//!
//! `parse_with_signed_span` is the span-preserving TUF envelope
//! parser. It hand-rolls a JSON scanner to find the byte range of
//! the `signed` value (so the verifier can hash exactly the bytes
//! the producer signed). Hand-rolled scanners are panic risks; the
//! target's job is to flush them out.

use libfuzzer_sys::fuzz_target;
use tuf::{parse_with_signed_span, Root};

fuzz_target!(|data: &[u8]| {
    let _ = parse_with_signed_span::<Root>(data);
});
