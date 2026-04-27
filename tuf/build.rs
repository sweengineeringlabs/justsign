//! Build-time integrity check for the bundled Sigstore production
//! TUF root metadata asset (`assets/sigstore_prod.root.json`).
//!
//! This script is component 2 of issue #27: catch a corrupted or
//! expired embedded asset at `cargo build` time rather than at
//! runtime. The runtime expiry guard (component 3) lives in
//! `swe_justsign_tuf::client::TufClient::with_initial_root_bytes`.
//!
//! # What this script verifies
//!
//! 1. The asset file exists and is valid JSON.
//! 2. The asset has the expected TUF envelope shape: a top-level
//!    `signed` object with `_type == "root"`, an integer `version`,
//!    and an RFC 3339 UTC-Z `expires` timestamp.
//! 3. The asset is not already expired relative to the build clock.
//!    An expired asset fails the build with a typed message.
//! 4. The asset is not within `WARN_DAYS` of expiry. A near-expiry
//!    asset emits `cargo:warning` so a release manager notices the
//!    refresh is overdue while there is still time to land it.
//!
//! # Design notes
//!
//! The script avoids `chrono` and `time`. The embedded asset's
//! `expires` is always RFC 3339 UTC-Z (TUF spec §4.2.2 + Sigstore
//! convention), so a small inline parser is sufficient. Mirrors the
//! decision in `tuf/src/expiry.rs`, which makes the same trade-off
//! at runtime: we already maintain ~50 LOC of std-only date code, no
//! reason to grow the build-dep graph for a duplicate.
//!
//! # Failure modes
//!
//! - Missing asset file -> panic with a `cargo:warning` directing
//!   the operator to fetch + commit the asset.
//! - Asset is not JSON -> panic with the underlying parse error.
//! - Asset shape is wrong -> panic naming the missing field.
//! - Asset expired -> panic naming the expiry timestamp + a hint to
//!   refresh and bump the version.
//! - Near-expiry warning -> `cargo:warning` only; build succeeds.

use std::time::{SystemTime, UNIX_EPOCH};

const ASSET_PATH: &str = "assets/sigstore_prod.root.json";

/// Emit a `cargo:warning` when the embedded root expires within this
/// many days of the build clock.
const WARN_DAYS: i64 = 30;

fn main() {
    println!("cargo:rerun-if-changed={ASSET_PATH}");
    println!("cargo:rerun-if-changed=build.rs");

    let bytes = std::fs::read(ASSET_PATH).unwrap_or_else(|e| {
        panic!(
            "missing or unreadable embedded TUF asset {ASSET_PATH}: {e}. \
             Fetch the current Sigstore production root from \
             https://tuf-repo-cdn.sigstore.dev/<N>.root.json and commit it \
             to {ASSET_PATH}; see docs/2-architecture/adr_001_sigstore_tuf_bootstrap.md."
        )
    });

    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("embedded TUF asset {ASSET_PATH} is not valid JSON: {e}"));

    let signed = v
        .get("signed")
        .and_then(|s| s.as_object())
        .unwrap_or_else(|| {
            panic!("embedded TUF asset {ASSET_PATH} is missing top-level `signed` object")
        });

    let role_type = signed
        .get("_type")
        .and_then(|t| t.as_str())
        .unwrap_or_else(|| panic!("embedded TUF asset {ASSET_PATH} is missing `signed._type`"));
    if role_type != "root" {
        panic!("embedded TUF asset {ASSET_PATH} has _type = \"{role_type}\", expected \"root\"");
    }

    let version = signed
        .get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| {
            panic!("embedded TUF asset {ASSET_PATH} is missing or malformed `signed.version`")
        });

    let expires = signed
        .get("expires")
        .and_then(|e| e.as_str())
        .unwrap_or_else(|| panic!("embedded TUF asset {ASSET_PATH} is missing `signed.expires`"));

    // Parse `expires` (RFC 3339 UTC-Z) into Unix seconds.
    let expires_unix = parse_rfc3339_utc_z(expires).unwrap_or_else(|e| {
        panic!("embedded TUF asset {ASSET_PATH} `expires` field is not RFC 3339 UTC-Z: {e}")
    });

    // Compute "now" as Unix seconds. If the build clock is before
    // 1970 (vanishingly rare), treat it as 0 -- the expiry comparison
    // will then likely fail, surfacing the misconfigured clock.
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    if now_unix >= expires_unix {
        panic!(
            "embedded TUF asset {ASSET_PATH} has expired: `signed.expires` = {expires} \
             is in the past relative to the build clock. Refresh the asset to a current \
             Sigstore production root (https://tuf-repo-cdn.sigstore.dev/<N>.root.json), \
             update src/embedded.rs constants (SHA-256, source URL, fetched-at, version), \
             and re-run cargo build."
        );
    }

    let seconds_to_expiry = expires_unix - now_unix;
    let days_to_expiry = seconds_to_expiry / 86_400;
    if days_to_expiry < WARN_DAYS {
        println!(
            "cargo:warning=embedded Sigstore TUF root expires in {days_to_expiry} days \
             (at {expires}). Refresh tuf/{ASSET_PATH} before the deadline; see \
             docs/2-architecture/adr_001_sigstore_tuf_bootstrap.md."
        );
    }

    // Surface the embedded root version to the compiled crate as an
    // env var so log lines can reference it without re-parsing the
    // asset.
    println!("cargo:rustc-env=JUSTSIGN_TUF_BAKED_ROOT_VERSION={version}");
}

/// Parse an `YYYY-MM-DDTHH:MM:SSZ` RFC 3339 UTC-Z timestamp into
/// Unix seconds. Sub-second fractions are tolerated (any `.<frac>`
/// between `SS` and `Z` is ignored, which is safe because we only
/// compare at second granularity).
///
/// We do NOT handle timezone offsets -- the asset is required to be
/// UTC-Z, and rejecting other offsets prevents a silent expiry
/// bypass on a misencoded asset.
fn parse_rfc3339_utc_z(s: &str) -> Result<i64, String> {
    if !s.ends_with('Z') {
        return Err(format!("timestamp must end in 'Z' (UTC): {s}"));
    }
    if s.len() < 20 {
        return Err(format!("timestamp too short to be RFC 3339: {s}"));
    }
    // Fixed-width grammar lets us slice without a tokenizer.
    let bytes = s.as_bytes();
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(format!("timestamp does not match YYYY-MM-DDTHH:MM:SS: {s}"));
    }

    fn parse_uint(slice: &[u8]) -> Result<i64, String> {
        let s = std::str::from_utf8(slice).map_err(|e| format!("non-utf8: {e}"))?;
        s.parse::<i64>().map_err(|e| format!("not int: {e}"))
    }

    let year = parse_uint(&bytes[0..4])?;
    let month = parse_uint(&bytes[5..7])?;
    let day = parse_uint(&bytes[8..10])?;
    let hour = parse_uint(&bytes[11..13])?;
    let minute = parse_uint(&bytes[14..16])?;
    let second = parse_uint(&bytes[17..19])?;

    if !(1..=12).contains(&month) {
        return Err(format!("month out of range: {month}"));
    }
    if !(1..=31).contains(&day) {
        return Err(format!("day out of range: {day}"));
    }
    if !(0..=23).contains(&hour) {
        return Err(format!("hour out of range: {hour}"));
    }
    if !(0..=59).contains(&minute) {
        return Err(format!("minute out of range: {minute}"));
    }
    if !(0..=60).contains(&second) {
        return Err(format!("second out of range: {second}"));
    }

    let days = days_from_civil(year, month as u32, day as u32);
    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    Ok(secs)
}

/// Howard Hinnant's `days_from_civil` algorithm. Computes the number
/// of days between 1970-01-01 (Unix epoch) and the given proleptic
/// Gregorian date. Same algorithm as the inverse `unix_to_utc` in
/// `tuf/src/expiry.rs`, just running the other direction.
///
/// Source: <http://howardhinnant.github.io/date_algorithms.html>.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe: i64 = y - era * 400; // [0, 399]
    let m = m as i64;
    let d = d as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}
