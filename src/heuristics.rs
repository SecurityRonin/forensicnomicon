//! Forensic heuristics — detection thresholds and pure predicates.
//!
//! Encodes forensic "rules of thumb" as compile-time constants and zero-dependency
//! pure-math predicate functions. These represent investigator experience about
//! *what patterns are suspicious*, distinct from:
//!
//! - [`rootkit`](crate::rootkit) — known-bad identifiers for specific malware families
//! - Format modules ([`journald`](crate::journald), etc.) — wire-format constants
//!
//! # Design constraint
//!
//! Every item in this module must have zero runtime dependencies. Functions operate
//! only on primitive types (`i64`, `u32`, `u8`). Anything requiring `chrono`,
//! `serde`, or I/O belongs in a higher layer (e.g., `rt-correlation`).

// ── Temporal: born-before-OS-install ──────────────────────────────────────────

/// Default threshold for born-before-OS-install timestomp detection: 24 hours
/// in nanoseconds.
///
/// A file with a `$STANDARD_INFORMATION` birth time more than this interval
/// before the OS install date warrants investigation for timestomping
/// (MITRE T1070.006).
pub const BORN_BEFORE_INSTALL_THRESHOLD_NS: i64 = 86_400_000_000_000; // 24 h

/// Windows FILETIME epoch offset in 100-nanosecond intervals.
///
/// FILETIME counts 100-ns ticks since 1601-01-01 UTC.
/// Unix epoch is 1970-01-01 UTC.
/// Difference: 11 644 473 600 seconds = 116 444 736 000 000 000 × 100 ns ticks.
///
/// Use `i128` arithmetic when converting to nanoseconds to avoid overflow.
pub const FILETIME_EPOCH_DIFF_100NS: i128 = 116_444_736_000_000_000;

// ── Temporal: working-hours anomaly ───────────────────────────────────────────

/// Start of the standard corporate working-hours window (inclusive), UTC.
///
/// Events before this hour are classified as outside working hours.
pub const WORKING_HOURS_START: u32 = 9;

/// End of the standard corporate working-hours window (exclusive), UTC.
///
/// Events at or after this hour are classified as outside working hours.
pub const WORKING_HOURS_END: u32 = 17;

// ── Predicates ────────────────────────────────────────────────────────────────

/// Returns `true` if a file's birth time predates OS installation by more than
/// [`BORN_BEFORE_INSTALL_THRESHOLD_NS`].
///
/// This is the standard variant of the born-before-install check using the
/// compiled-in 24-hour threshold. Use the three-argument version in
/// `rt-correlation::temporal_checks` when a custom threshold is required.
///
/// All timestamps must be nanoseconds since the Unix epoch.
#[must_use]
pub fn is_born_before_install(file_born_ns: i64, os_install_ns: i64) -> bool {
    file_born_ns < os_install_ns - BORN_BEFORE_INSTALL_THRESHOLD_NS
}

/// Returns `true` if the given UTC hour (0–23) falls outside working hours.
///
/// Outside working hours means: before [`WORKING_HOURS_START`] or at/after
/// [`WORKING_HOURS_END`]. Weekend detection requires a separate call to check
/// the weekday; this function only considers the hour.
///
/// Use this with `chrono`-derived hour values from higher layers.
#[must_use]
pub fn is_hour_outside_working_hours(hour: u8) -> bool {
    let h = u32::from(hour);
    !(WORKING_HOURS_START..WORKING_HOURS_END).contains(&h)
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn born_before_install_threshold_is_24h() {
        assert_eq!(BORN_BEFORE_INSTALL_THRESHOLD_NS, 24 * 3_600_000_000_000i64);
    }

    #[test]
    fn filetime_epoch_diff_is_correct() {
        // 11 644 473 600 seconds × 10_000_000 (ticks per second)
        assert_eq!(FILETIME_EPOCH_DIFF_100NS, 11_644_473_600i128 * 10_000_000);
    }

    #[test]
    fn working_hours_start_is_nine() {
        assert_eq!(WORKING_HOURS_START, 9);
    }

    #[test]
    fn working_hours_end_is_seventeen() {
        assert_eq!(WORKING_HOURS_END, 17);
    }

    // ── is_born_before_install ─────────────────────────────────────────────────

    #[test]
    fn born_two_days_before_install_returns_true() {
        let install_ns = 1_700_000_000_000_000_000i64; // arbitrary
        let file_born_ns = install_ns - 2 * BORN_BEFORE_INSTALL_THRESHOLD_NS;
        assert!(is_born_before_install(file_born_ns, install_ns));
    }

    #[test]
    fn born_after_install_returns_false() {
        let install_ns = 1_700_000_000_000_000_000i64;
        let file_born_ns = install_ns + BORN_BEFORE_INSTALL_THRESHOLD_NS;
        assert!(!is_born_before_install(file_born_ns, install_ns));
    }

    #[test]
    fn born_twelve_hours_before_install_returns_false() {
        // 12 h < 24 h threshold → not suspicious
        let install_ns = 1_700_000_000_000_000_000i64;
        let file_born_ns = install_ns - BORN_BEFORE_INSTALL_THRESHOLD_NS / 2;
        assert!(!is_born_before_install(file_born_ns, install_ns));
    }

    #[test]
    fn born_exactly_at_threshold_returns_false() {
        // equal means NOT before (strict less-than)
        let install_ns = 1_700_000_000_000_000_000i64;
        let file_born_ns = install_ns - BORN_BEFORE_INSTALL_THRESHOLD_NS;
        assert!(!is_born_before_install(file_born_ns, install_ns));
    }

    // ── is_hour_outside_working_hours ─────────────────────────────────────────

    #[test]
    fn hour_8_is_outside_working_hours() {
        assert!(is_hour_outside_working_hours(8));
    }

    #[test]
    fn hour_9_is_inside_working_hours() {
        assert!(!is_hour_outside_working_hours(9));
    }

    #[test]
    fn hour_16_is_inside_working_hours() {
        assert!(!is_hour_outside_working_hours(16));
    }

    #[test]
    fn hour_17_is_outside_working_hours() {
        assert!(is_hour_outside_working_hours(17));
    }

    #[test]
    fn hour_0_midnight_is_outside_working_hours() {
        assert!(is_hour_outside_working_hours(0));
    }

    #[test]
    fn hour_23_is_outside_working_hours() {
        assert!(is_hour_outside_working_hours(23));
    }
}
