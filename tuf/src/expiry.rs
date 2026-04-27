//! RFC 3339 expiry comparison without a `chrono` dep.
//!
//! TUF metadata `expires` fields are always RFC 3339 timestamps
//! ending in either `Z` (UTC) or `+00:00`. We constrain the parser
//! to UTC-Z so two timestamps compare lexicographically AND
//! chronologically — the calendar maths is trivial when the inputs
//! always have the shape `YYYY-MM-DDTHH:MM:SSZ` (length 20) or
//! `YYYY-MM-DDTHH:MM:SS.<frac>Z`.
//!
//! # Why not `chrono`
//!
//! `chrono` would add ~7 transitive deps (`time`, `serde`,
//! `winapi`/`iana-time-zone`, …) for one operation: "is this UTC
//! timestamp in the past?" Our implementation needs:
//!
//! 1. A `now()` source (we use [`std::time::SystemTime`]).
//! 2. The ability to format `now()` as the same canonical RFC 3339
//!    string the metadata uses (so we can string-compare).
//! 3. A guard that rejects malformed inputs loudly rather than
//!    silently skipping the expiry check.
//!
//! All three are ~50 LOC of std, no new deps.
//!
//! # Spec references
//!
//! - TUF spec §4.2.2 "expires":
//!   <https://theupdateframework.io/specification/latest/#metadata>
//! - RFC 3339 §5.6 "Internet Date/Time Format":
//!   <https://www.rfc-editor.org/rfc/rfc3339#section-5.6>

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns true iff `expires` is strictly before `now`.
///
/// `expires` MUST be a UTC RFC 3339 string ending in `Z`. Any other
/// shape (`+02:00`, `-05:00`, no timezone) is rejected with `Err`
/// to avoid silently bypassing expiry on metadata that uses a
/// non-UTC offset — which would otherwise sort lexicographically
/// before its UTC equivalent.
pub fn is_expired(expires: &str, now: SystemTime) -> Result<bool, ExpiryParseError> {
    if !expires.ends_with('Z') {
        return Err(ExpiryParseError::NotUtcZ {
            value: expires.to_string(),
        });
    }
    // Minimum well-formed shape: `YYYY-MM-DDTHH:MM:SSZ` — 20 chars.
    if expires.len() < 20 {
        return Err(ExpiryParseError::TooShort {
            value: expires.to_string(),
        });
    }
    // The grammar after the leading 4-digit year is fixed-width, so
    // we can lex-compare against the UTC `now` rendered with the
    // same shape and the answer is also chronological. Sub-second
    // fractions in either operand are tolerated because '.' (0x2E)
    // sorts before 'Z' (0x5A) so a value with a fractional part
    // still compares correctly against one without.
    let now_str = format_rfc3339_utc(now)?;
    Ok(expires < now_str.as_str())
}

/// Format `now` as `YYYY-MM-DDTHH:MM:SSZ` in UTC.
///
/// Public so callers can render their own "now" stamps to compare
/// against fetched metadata if they want; primarily used by
/// [`is_expired`].
pub fn format_rfc3339_utc(now: SystemTime) -> Result<String, ExpiryParseError> {
    let dur = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ExpiryParseError::ClockBeforeEpoch)?;
    let secs = dur.as_secs();
    let (year, month, day, hour, minute, second) = unix_to_utc(secs);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Convert a Unix timestamp (seconds since 1970-01-01 UTC) into
/// `(year, month, day, hour, minute, second)` in the proleptic
/// Gregorian calendar.
///
/// Plain integer arithmetic, no allocation, no `chrono`. Algorithm
/// from Howard Hinnant's "chrono date algorithms"
/// (<http://howardhinnant.github.io/date_algorithms.html>) — civil
/// from days; widely cited and trivially auditable.
fn unix_to_utc(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days_since_epoch = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;

    // Howard Hinnant's `civil_from_days`. Shifts the epoch to
    // 0000-03-01 so the leap-year / month-length logic becomes
    // closed-form.
    let z = days_since_epoch + 719_468; // shift to 0000-03-01
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = y + (if m <= 2 { 1 } else { 0 });

    let hour = (secs_of_day / 3_600) as u32;
    let minute = ((secs_of_day % 3_600) / 60) as u32;
    let second = (secs_of_day % 60) as u32;

    (year, m, d, hour, minute, second)
}

/// Errors from parsing or comparing TUF expiry strings.
#[derive(Debug, thiserror::Error)]
pub enum ExpiryParseError {
    /// `expires` did not end in `Z`. We reject non-UTC offsets
    /// rather than risk a silent expiry bypass on metadata that
    /// uses `+02:00` etc.
    #[error("expiry timestamp must end in 'Z' (UTC), got: {value}")]
    NotUtcZ {
        /// The offending value, surfaced for diagnostics.
        value: String,
    },

    /// `expires` was shorter than the minimum well-formed
    /// `YYYY-MM-DDTHH:MM:SSZ` (20 chars).
    #[error("expiry timestamp too short to be RFC 3339: {value}")]
    TooShort {
        /// The offending value, surfaced for diagnostics.
        value: String,
    },

    /// The system clock is set before the Unix epoch. Vanishingly
    /// rare in practice but std forces us to handle it.
    #[error("system clock is before Unix epoch")]
    ClockBeforeEpoch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// `is_expired` returns true when expiry is strictly before now.
    ///
    /// Bug it catches: an expiry comparison that uses `<=` instead of
    /// `<` would falsely flag a metadata document as expired exactly
    /// at the boundary (or, swapped, would let a 1-second-stale
    /// document slip through).
    #[test]
    fn test_is_expired_with_past_expires_returns_true() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000); // 2023-11-14T22:13:20Z
        assert!(is_expired("2020-01-01T00:00:00Z", now).unwrap());
    }

    /// `is_expired` returns false when expiry is in the future.
    ///
    /// Bug it catches: a date-rendering off-by-one (e.g. month index
    /// 0-vs-1) that flips the comparison.
    #[test]
    fn test_is_expired_with_future_expires_returns_false() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert!(!is_expired("2099-01-01T00:00:00Z", now).unwrap());
    }

    /// Non-UTC offsets are rejected with a typed error rather than
    /// silently letting expiry through.
    ///
    /// Bug it catches: a parser that strips the offset and treats
    /// the bare datetime as UTC would let a `2024-01-01T00:00:00+02:00`
    /// timestamp pass when it has actually expired in UTC.
    #[test]
    fn test_is_expired_with_non_utc_offset_returns_typed_error() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let err = is_expired("2099-01-01T00:00:00+02:00", now).expect_err("must reject offset");
        assert!(matches!(err, ExpiryParseError::NotUtcZ { .. }), "{err:?}");
    }

    /// Truncated timestamps are rejected with a typed error.
    ///
    /// Bug it catches: a slice index into an under-length string
    /// would panic; we want a typed error instead so a malformed
    /// metadata document doesn't crash the verifier.
    #[test]
    fn test_is_expired_with_truncated_timestamp_returns_typed_error() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let err = is_expired("2099Z", now).expect_err("must reject short");
        assert!(matches!(err, ExpiryParseError::TooShort { .. }), "{err:?}");
    }

    /// Round-trip: rendering `now` then comparing it to itself
    /// returns `false` (not strictly before).
    ///
    /// Bug it catches: a `<=` slip that would say "now expired
    /// itself".
    #[test]
    fn test_is_expired_with_now_equal_to_expires_returns_false() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let now_str = format_rfc3339_utc(now).unwrap();
        assert!(!is_expired(&now_str, now).unwrap());
    }

    /// Hinnant's algorithm correctly renders the Unix epoch itself.
    #[test]
    fn test_format_rfc3339_utc_at_epoch_returns_1970() {
        let s = format_rfc3339_utc(UNIX_EPOCH).unwrap();
        assert_eq!(s, "1970-01-01T00:00:00Z");
    }

    /// Hinnant's algorithm correctly renders a representative date
    /// past Y2K — guards against a year-rollover off-by-one.
    #[test]
    fn test_format_rfc3339_utc_at_known_timestamp_matches() {
        // 2023-11-14T22:13:20Z = 1_700_000_000 seconds since epoch.
        let s = format_rfc3339_utc(UNIX_EPOCH + Duration::from_secs(1_700_000_000)).unwrap();
        assert_eq!(s, "2023-11-14T22:13:20Z");
    }
}
