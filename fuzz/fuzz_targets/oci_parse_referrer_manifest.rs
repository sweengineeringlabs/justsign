#![no_main]
//! Fuzz target: `sign::oci::parse_referrer_manifest` must surface a
//! typed error or a successful parse for any byte slice — never
//! panic.
//!
//! Referrer manifests come from an OCI registry's referrers API,
//! pointing the verifier at the bundle blob to fetch. A panic here
//! is a denial-of-service against the verifier; the target asserts
//! no such panic exists for any byte input.

use libfuzzer_sys::fuzz_target;
use sign::oci::parse_referrer_manifest;

fuzz_target!(|data: &[u8]| {
    let _ = parse_referrer_manifest(data);
});
