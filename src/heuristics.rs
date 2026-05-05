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

    // ── SI/FN timestomp (group 1) ─────────────────────────────────────────────

    #[test]
    fn si_before_fn_threshold_is_one_second() {
        assert_eq!(SI_PRECEDES_FN_THRESHOLD_NS, 1_000_000_000i64);
    }

    #[test]
    fn si_two_seconds_before_fn_is_timestomp() {
        let fn_born = 1_700_000_000_000_000_000i64;
        let si_born = fn_born - 2 * SI_PRECEDES_FN_THRESHOLD_NS;
        assert!(is_si_before_fn(si_born, fn_born));
    }

    #[test]
    fn si_after_fn_is_not_timestomp() {
        let fn_born = 1_700_000_000_000_000_000i64;
        let si_born = fn_born + SI_PRECEDES_FN_THRESHOLD_NS;
        assert!(!is_si_before_fn(si_born, fn_born));
    }

    #[test]
    fn si_equal_fn_is_not_timestomp() {
        let ts = 1_700_000_000_000_000_000i64;
        assert!(!is_si_before_fn(ts, ts));
    }

    #[test]
    fn si_exactly_at_threshold_is_not_timestomp() {
        let fn_born = 1_700_000_000_000_000_000i64;
        let si_born = fn_born - SI_PRECEDES_FN_THRESHOLD_NS;
        assert!(!is_si_before_fn(si_born, fn_born));
    }

    // ── Null/wiped timestamp (group 2) ───────────────────────────────────────

    #[test]
    fn null_timestamp_window_is_one_day() {
        assert_eq!(NULL_TIMESTAMP_WINDOW_NS, 86_400_000_000_000i64);
    }

    #[test]
    fn zero_timestamp_is_null() {
        assert!(is_null_timestamp(0));
    }

    #[test]
    fn negative_timestamp_is_null() {
        assert!(is_null_timestamp(-1));
    }

    #[test]
    fn timestamp_within_one_day_of_epoch_is_null() {
        assert!(is_null_timestamp(NULL_TIMESTAMP_WINDOW_NS - 1));
    }

    #[test]
    fn timestamp_exactly_at_one_day_is_not_null() {
        assert!(!is_null_timestamp(NULL_TIMESTAMP_WINDOW_NS));
    }

    #[test]
    fn modern_timestamp_is_not_null() {
        // 2024-01-01 in ns
        assert!(!is_null_timestamp(1_704_067_200_000_000_000i64));
    }

    // ── Rapid-access / burst (group 3) ───────────────────────────────────────

    #[test]
    fn rapid_access_threshold_is_one_second() {
        assert_eq!(RAPID_ACCESS_THRESHOLD_NS, 1_000_000_000i64);
    }

    #[test]
    fn two_events_half_second_apart_are_rapid() {
        assert!(is_rapid_sequence(0, 500_000_000));
    }

    #[test]
    fn two_events_two_seconds_apart_are_not_rapid() {
        assert!(!is_rapid_sequence(0, 2_000_000_000));
    }

    #[test]
    fn rapid_sequence_with_reversed_order() {
        assert!(is_rapid_sequence(500_000_000, 0));
    }

    #[test]
    fn burst_access_all_rapid_returns_true() {
        let ts = [0i64, 100_000_000, 200_000_000, 300_000_000];
        assert!(is_burst_access(&ts));
    }

    #[test]
    fn burst_access_one_slow_gap_returns_false() {
        let ts = [0i64, 100_000_000, 2_000_000_000, 2_100_000_000];
        assert!(!is_burst_access(&ts));
    }

    #[test]
    fn burst_access_empty_returns_false() {
        assert!(!is_burst_access(&[]));
    }

    #[test]
    fn burst_access_single_element_returns_false() {
        assert!(!is_burst_access(&[42]));
    }

    // ── Network port heuristics (group 4) ────────────────────────────────────

    #[test]
    fn ephemeral_port_boundary_correct() {
        assert_eq!(MIN_EPHEMERAL_PORT, 49152u16);
    }

    #[test]
    fn port_49152_is_ephemeral() {
        assert!(is_ephemeral_port(49152));
    }

    #[test]
    fn port_49151_is_not_ephemeral() {
        assert!(!is_ephemeral_port(49151));
    }

    #[test]
    fn port_65535_is_ephemeral() {
        assert!(is_ephemeral_port(65535));
    }

    #[test]
    fn known_miner_port_3333_detected() {
        assert!(is_miner_port(3333));
    }

    #[test]
    fn known_miner_port_14444_detected() {
        assert!(is_miner_port(14444));
    }

    #[test]
    fn non_miner_port_80_not_detected() {
        assert!(!is_miner_port(80));
    }

    #[test]
    fn tunnel_port_9050_tor_detected() {
        assert!(is_common_tunnel_port(9050));
    }

    #[test]
    fn tunnel_port_1080_socks_detected() {
        assert!(is_common_tunnel_port(1080));
    }

    #[test]
    fn non_tunnel_port_443_not_detected() {
        assert!(!is_common_tunnel_port(443));
    }

    // ── UID/GID boundaries (group 5) ─────────────────────────────────────────

    #[test]
    fn max_system_uid_is_999() {
        assert_eq!(MAX_SYSTEM_UID, 999u32);
    }

    #[test]
    fn root_uid_0_is_system() {
        assert!(is_system_uid(0));
    }

    #[test]
    fn uid_999_is_system() {
        assert!(is_system_uid(999));
    }

    #[test]
    fn uid_1000_is_user() {
        assert!(is_user_uid(1000));
        assert!(!is_system_uid(1000));
    }

    #[test]
    fn uid_999_is_not_user() {
        assert!(!is_user_uid(999));
    }

    // ── C2 beacon regularity (group 6) ───────────────────────────────────────

    #[test]
    fn beacon_jitter_ppt_is_25() {
        assert_eq!(BEACON_JITTER_PPT, 25u64);
    }

    #[test]
    fn perfectly_regular_intervals_detected() {
        // 60s intervals, no jitter
        let iv = [60_000_000_000i64; 5];
        assert!(is_regular_interval(&iv));
    }

    #[test]
    fn intervals_within_jitter_detected_as_regular() {
        // median = 60s; 2% jitter well within 2.5%
        let base = 60_000_000_000i64;
        let jitter = base / 50; // 2%
        let iv = [base - jitter, base, base + jitter, base, base - jitter / 2];
        assert!(is_regular_interval(&iv));
    }

    #[test]
    fn irregular_intervals_not_detected_as_beacon() {
        let iv = [60_000_000_000i64, 120_000_000_000, 30_000_000_000, 90_000_000_000, 60_000_000_000];
        assert!(!is_regular_interval(&iv));
    }

    #[test]
    fn fewer_than_three_intervals_returns_false() {
        assert!(!is_regular_interval(&[60_000_000_000i64, 60_000_000_000]));
    }

    #[test]
    fn empty_intervals_returns_false() {
        assert!(!is_regular_interval(&[]));
    }

    #[test]
    fn negative_interval_returns_false() {
        assert!(!is_regular_interval(&[60_000_000_000i64, -1, 60_000_000_000]));
    }

    // ── File size heuristics (group 7) ───────────────────────────────────────

    #[test]
    fn min_meaningful_file_bytes_is_4() {
        assert_eq!(MIN_MEANINGFUL_FILE_BYTES, 4u64);
    }

    #[test]
    fn large_file_threshold_is_1_gib() {
        assert_eq!(LARGE_FILE_THRESHOLD_BYTES, 1_073_741_824u64);
    }

    #[test]
    fn zero_byte_file_is_hollow() {
        assert!(is_hollow_file(0));
    }

    #[test]
    fn three_byte_file_is_hollow() {
        assert!(is_hollow_file(3));
    }

    #[test]
    fn four_byte_file_is_not_hollow() {
        assert!(!is_hollow_file(4));
    }

    #[test]
    fn one_gib_file_is_potential_container() {
        assert!(is_potential_container(1_073_741_824));
    }

    #[test]
    fn two_gib_file_is_potential_container() {
        assert!(is_potential_container(2_147_483_648));
    }

    #[test]
    fn small_file_is_not_potential_container() {
        assert!(!is_potential_container(1_000_000));
    }
}
