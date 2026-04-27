//! Clock SPI for time-aware verifiers.
//!
//! Lives in `spec` because both `swe_justsign_sign` (cert validity
//! window in `verify_blob_keyless`) and `swe_justsign_tuf` (role
//! `expires` in `TufClient`) need a time source, and `tuf` does not
//! depend on `sign`. The shared `spec` dependency is the only common
//! ground.
//!
//! # Why a trait, not just `SystemTime::now()`?
//!
//! Three reasons:
//!
//! 1. **Deterministic tests.** A verifier that consults
//!    `SystemTime::now()` cannot be exercised against a cert whose
//!    `notAfter` is fixed in the past or future without the test
//!    being implicitly time-bombed. Injecting a [`FixedClock`] makes
//!    expiry tests deterministic across the host's wall-clock state.
//!
//! 2. **Air-gapped / replay deploys.** Some operators verify bundles
//!    on systems whose clock is intentionally pinned to a release
//!    timestamp (e.g. reproducing a build). A real `Clock` lets them
//!    pass their own time source through.
//!
//! 3. **Testing clock-skew failure modes.** A producer with a
//!    fast-skewed clock can mint a cert whose `notBefore` is in
//!    every verifier's future; that must reject loudly, not silently
//!    pass through. Without an injectable clock this failure mode is
//!    untestable from the outside.
//!
//! # Production default
//!
//! [`SystemClock`] resolves "now" through [`std::time::SystemTime`].
//! It is the default for every public constructor that doesn't take
//! an explicit `Clock`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Source of the current time, in Unix epoch seconds.
///
/// Implementations MUST be `Send + Sync` so a `Box<dyn Clock>` is
/// safe to share across threads (e.g. inside a `TufClient` that may
/// be wrapped in an `Arc` and called from multiple workers).
///
/// The single method returns `i64` to express "seconds since Unix
/// epoch, possibly before". A `Clock` whose host system is set
/// before 1970 returns a negative value rather than panicking;
/// downstream comparisons against cert `notBefore` / `notAfter`
/// (which are also `i64` in this codebase's wire shape) compare
/// correctly under signed arithmetic.
pub trait Clock: Send + Sync {
    /// Current time as Unix epoch seconds.
    ///
    /// Implementations MUST NOT panic. A clock that cannot read its
    /// time source should return `0` (Unix epoch) and let the
    /// downstream comparison reject every `notAfter` set after 1970,
    /// which is the safer default than crashing the verifier.
    fn now_unix_secs(&self) -> i64;
}

/// Production clock — reads [`SystemTime::now()`].
///
/// Cross-platform on Windows, Linux, and macOS. No platform-specific
/// syscall: `SystemTime` is std's portable abstraction.
#[derive(Debug, Default, Copy, Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => {
                // u64 -> i64: clamp at i64::MAX. SystemTime values
                // past year 2^63 / 86400 / 365.25 ≈ year 292 277 026
                // 596 are not a real concern; the clamp is a safe
                // ceiling for the type conversion regardless.
                let s = d.as_secs();
                if s > i64::MAX as u64 {
                    i64::MAX
                } else {
                    s as i64
                }
            }
            Err(e) => {
                // Clock is set before 1970. Recover the negative
                // delta as i64 seconds — duration_since returns the
                // absolute distance via the Err's `duration()`.
                let neg = e.duration().as_secs();
                if neg > i64::MAX as u64 {
                    i64::MIN
                } else {
                    -(neg as i64)
                }
            }
        }
    }
}

/// Test-only clock that always returns the configured Unix epoch
/// seconds.
///
/// Held in a `pub` field so callers can construct it in one
/// expression: `FixedClock(1_700_000_000)`. Used by
/// `verify_blob_keyless_with_clock` tests to pin "now" without
/// touching `SystemTime::now()`.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct FixedClock(pub i64);

impl Clock for FixedClock {
    fn now_unix_secs(&self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bug it catches: a `SystemClock` impl that returns `0` (or any
    /// hard-coded constant) instead of consulting the real system
    /// clock — every `notAfter` check would silently pass for a cert
    /// with `notAfter > 0`.
    ///
    /// We pin a wide window (2024-01-01 to 2100-01-01) so the test
    /// is robust against reasonable host clock drift but still
    /// detects a stub returning 0 or `i64::MAX`.
    #[test]
    fn test_system_clock_now_returns_current_time_within_sane_bounds() {
        let now = SystemClock.now_unix_secs();
        // 2024-01-01T00:00:00Z = 1 704 067 200.
        assert!(
            now >= 1_704_067_200,
            "SystemClock returned {now}, which is before 2024-01-01; \
             likely a stub returning 0 or a time source that's not \
             reading the real wall clock"
        );
        // 2100-01-01T00:00:00Z = 4 102 444 800.
        assert!(
            now < 4_102_444_800,
            "SystemClock returned {now}, which is after 2100-01-01; \
             likely a stub returning i64::MAX or arithmetic overflow"
        );
    }

    /// Bug it catches: a `FixedClock` impl that delegates to
    /// `SystemTime::now()` — would defeat the entire purpose of the
    /// test-injection seam. The configured value MUST round-trip
    /// exactly.
    #[test]
    fn test_fixed_clock_now_returns_configured_value_exactly() {
        let pinned = 1_700_000_000_i64; // 2023-11-14T22:13:20Z
        let clock = FixedClock(pinned);
        assert_eq!(clock.now_unix_secs(), pinned);
    }

    /// Bug it catches: a `FixedClock` that masks negative values to
    /// 0 — would hide pre-1970 clock states from the verifier. The
    /// trait contract says negatives are legal; pin it.
    #[test]
    fn test_fixed_clock_now_with_negative_value_returns_negative_value() {
        let clock = FixedClock(-12345);
        assert_eq!(clock.now_unix_secs(), -12345);
    }

    /// Bug it catches: a Clock impl that isn't `Send + Sync` — the
    /// `Box<dyn Clock>` shared inside `TufClient` would fail to
    /// compile. Pin the trait bound at the type level.
    #[test]
    fn test_clock_trait_bounds_send_sync_for_box_dyn_clock() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn Clock>>();
    }
}
