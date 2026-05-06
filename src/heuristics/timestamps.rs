//! NTFS timestamp precision and MACB consistency heuristics.

// NTFS stores 100-nanosecond intervals. A timestamp divisible by 10_000_000
// (= 1 second in 100-ns ticks) was written with only second-level precision —
// a common timestomping artifact.

/// Returns `true` if the FILETIME has sub-second precision.
/// Legitimate NTFS timestamps almost always have non-zero sub-second components.
#[must_use]
pub fn has_subsecond_precision(filetime: u64) -> bool {
    filetime % 10_000_000 != 0
}

/// Returns `true` if the FILETIME was written with only second-level precision
/// (sub-second component is exactly zero). Common timestomping indicator.
#[must_use]
pub fn is_low_precision_timestamp(filetime: u64) -> bool {
    filetime != 0 && !has_subsecond_precision(filetime)
}

/// Returns `true` if all four MACB timestamps are identical.
/// Timestomping tools commonly set all four to the same value.
#[must_use]
pub fn is_all_macb_identical(m: i64, a: i64, c: i64, b: i64) -> bool {
    m == a && a == c && c == b
}

/// Returns `true` if the timestamp (Unix nanoseconds) falls on an exact UTC hour boundary.
/// Manually-set timestamps are often rounded to whole hours — a human-set indicator.
#[must_use]
pub fn is_round_hour_timestamp(ts_ns: i64) -> bool {
    ts_ns > 0 && ts_ns % 3_600_000_000_000 == 0
}

/// Minimum plausible Windows install date (Unix seconds).
/// 2001-09-09 01:46:40 UTC = 1_000_000_000 — no legitimate install predates Windows XP.
pub const MIN_PLAUSIBLE_INSTALL_DATE_SECS: u32 = 1_000_000_000;

/// Returns `true` if the registry InstallDate is within a plausible range.
/// Values below MIN_PLAUSIBLE_INSTALL_DATE_SECS are spoofed or garbage.
#[must_use]
pub fn is_plausible_install_date(unix_secs: u32) -> bool {
    unix_secs >= MIN_PLAUSIBLE_INSTALL_DATE_SECS
}

/// Returns `true` if a file's creation (born) time is *later* than its last-modified time.
///
/// # Semantics
///
/// On NTFS, the born timestamp (`$SI.$CREATED`) records when the file *arrived on this volume*.
///
/// - **born < modified** — NORMAL: file was created here, then edited one or more times.
/// - **born > modified** — FOREIGN FILE: the file was copied or extracted from elsewhere.
///   Windows preserves the source's `LastModified` but stamps `CREATED` as the arrival time.
///   Common sources: USB drops, archive extraction, downloads, lateral movement staging.
///   This is a *provenance* indicator, not necessarily tampering.
/// - **born == modified** — Newly created and never edited, or a timestomping tool set both
///   to the same value (see `is_all_macb_identical`).
///
/// # Parameters
/// - `born_ns`: `$SI.$CREATED` as Unix nanoseconds
/// - `modified_ns`: `$SI.$MODIFIED` (last-write) as Unix nanoseconds
#[must_use]
pub fn is_foreign_file(born_ns: i64, modified_ns: i64) -> bool {
    born_ns > modified_ns
}

/// Maximum plausible clock skew between two NTP-synced hosts (Unix nanoseconds).
///
/// Windows domain members sync via W32tm; Kerberos requires clocks within 5 minutes of
/// the domain controller, but typical drift is well under 1 second. Cross-host timestamps
/// (files copied over a network share, logs from a different machine) may differ by up
/// to this amount due to hardware clock differences and NTP polling intervals.
///
/// Use this constant with `is_future_timestamp` to avoid false positives on legitimately
/// synced systems: `is_future_timestamp(ts_ns, now_ns + CLOCK_SKEW_TOLERANCE_NS)`.
pub const CLOCK_SKEW_TOLERANCE_NS: i64 = 1_000_000_000; // 1 second

/// Returns `true` if a timestamp is in the future by more than `CLOCK_SKEW_TOLERANCE_NS`.
///
/// Unlike `is_future_timestamp`, this allows for typical NTP drift between hosts.
/// Use this when comparing timestamps across systems (e.g., a file's NTFS timestamp
/// vs. a log timestamp from a different machine).
///
/// # Parameters
/// - `ts_ns`: timestamp to check, as Unix nanoseconds
/// - `now_ns`: current wall-clock time, as Unix nanoseconds
#[must_use]
pub fn is_future_timestamp_beyond_skew(ts_ns: i64, now_ns: i64) -> bool {
    ts_ns > now_ns + CLOCK_SKEW_TOLERANCE_NS
}

/// Returns `true` if a timestamp is in the future relative to `now_ns`.
///
/// Future timestamps indicate clock skew, deliberate manipulation, or a
/// source system with a misconfigured clock. Any positive gap beyond a
/// small allowance is suspicious; here we treat any strictly-future value
/// as a flag (callers can apply their own tolerance before calling).
///
/// # Parameters
/// - `ts_ns`: timestamp to check, as Unix nanoseconds
/// - `now_ns`: current wall-clock time, as Unix nanoseconds
#[must_use]
pub fn is_future_timestamp(ts_ns: i64, now_ns: i64) -> bool {
    ts_ns > now_ns
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsecond_precision_nonzero_sub_second() {
        // filetime with non-zero sub-second component → true
        let filetime = 10_000_001u64; // 1 second + 1 tick
        assert!(has_subsecond_precision(filetime));
    }

    #[test]
    fn subsecond_precision_zero_sub_second() {
        // filetime % 10_000_000 == 0, != 0 → false
        let filetime = 10_000_000u64; // exactly 1 second
        assert!(!has_subsecond_precision(filetime));
    }

    #[test]
    fn low_precision_whole_second() {
        // filetime divisible by 10_000_000, not zero → true
        let filetime = 10_000_000u64;
        assert!(is_low_precision_timestamp(filetime));
    }

    #[test]
    fn low_precision_zero_filetime_returns_false() {
        // zero is not "low precision" (it's null)
        assert!(!is_low_precision_timestamp(0));
    }

    #[test]
    fn low_precision_with_sub_second_returns_false() {
        let filetime = 10_000_001u64;
        assert!(!is_low_precision_timestamp(filetime));
    }

    #[test]
    fn macb_identical_all_same() {
        assert!(is_all_macb_identical(100, 100, 100, 100));
    }

    #[test]
    fn macb_not_identical_m_differs() {
        assert!(!is_all_macb_identical(99, 100, 100, 100));
    }

    #[test]
    fn macb_not_identical_a_differs() {
        assert!(!is_all_macb_identical(100, 99, 100, 100));
    }

    #[test]
    fn round_hour_on_exact_hour() {
        // ts_ns = 3_600_000_000_000 (1970-01-01 01:00:00 UTC) → true
        assert!(is_round_hour_timestamp(3_600_000_000_000));
    }

    #[test]
    fn round_hour_not_on_hour() {
        assert!(!is_round_hour_timestamp(3_600_000_000_001));
    }

    #[test]
    fn round_hour_zero_is_not_round() {
        // ts_ns = 0 → false (guard: ts_ns > 0)
        assert!(!is_round_hour_timestamp(0));
    }

    #[test]
    fn round_hour_negative_is_not_round() {
        assert!(!is_round_hour_timestamp(-3_600_000_000_000));
    }

    #[test]
    fn plausible_install_date_above_threshold() {
        assert!(is_plausible_install_date(1_100_000_000));
    }

    #[test]
    fn plausible_install_date_at_threshold() {
        // exactly 1_000_000_000 → true
        assert!(is_plausible_install_date(MIN_PLAUSIBLE_INSTALL_DATE_SECS));
    }

    #[test]
    fn plausible_install_date_below_threshold() {
        // 999_999_999 → false
        assert!(!is_plausible_install_date(999_999_999));
    }

    // ── is_foreign_file ───────────────────────────────────────────────────────

    #[test]
    fn foreign_file_born_after_modified_is_foreign() {
        // born = 2023-06-01, modified = 2020-01-01 (came from elsewhere)
        let modified_ns = 1_577_836_800_000_000_000i64; // 2020-01-01 UTC
        let born_ns = 1_685_577_600_000_000_000i64;     // 2023-06-01 UTC
        assert!(is_foreign_file(born_ns, modified_ns));
    }

    #[test]
    fn foreign_file_born_before_modified_is_normal() {
        // born = 2020-01-01, modified = 2023-06-01 (created here, then edited)
        let born_ns = 1_577_836_800_000_000_000i64;     // 2020-01-01 UTC
        let modified_ns = 1_685_577_600_000_000_000i64; // 2023-06-01 UTC
        assert!(!is_foreign_file(born_ns, modified_ns));
    }

    #[test]
    fn foreign_file_equal_timestamps_is_not_foreign() {
        // born == modified — newly created, not edited (or same-value stomp)
        let ts = 1_600_000_000_000_000_000i64;
        assert!(!is_foreign_file(ts, ts));
    }

    #[test]
    fn foreign_file_born_one_ns_after_modified() {
        // Minimal difference → still foreign
        assert!(is_foreign_file(101, 100));
    }

    #[test]
    fn foreign_file_born_one_ns_before_modified() {
        // born just before modified → normal
        assert!(!is_foreign_file(100, 101));
    }

    // ── is_future_timestamp ───────────────────────────────────────────────────

    #[test]
    fn future_timestamp_strictly_greater_than_now() {
        let now_ns = 1_700_000_000_000_000_000i64;
        let ts_ns = now_ns + 1;
        assert!(is_future_timestamp(ts_ns, now_ns));
    }

    #[test]
    fn future_timestamp_equal_to_now_is_not_future() {
        let now_ns = 1_700_000_000_000_000_000i64;
        assert!(!is_future_timestamp(now_ns, now_ns));
    }

    #[test]
    fn future_timestamp_in_past_is_not_future() {
        let now_ns = 1_700_000_000_000_000_000i64;
        let ts_ns = now_ns - 1_000_000_000; // 1 second ago
        assert!(!is_future_timestamp(ts_ns, now_ns));
    }

    #[test]
    fn future_timestamp_far_future() {
        let now_ns = 1_700_000_000_000_000_000i64;
        let ts_ns = now_ns + 86_400_000_000_000i64; // 1 day ahead
        assert!(is_future_timestamp(ts_ns, now_ns));
    }

    // ── CLOCK_SKEW_TOLERANCE_NS ───────────────────────────────────────────────

    #[test]
    fn clock_skew_tolerance_is_one_second() {
        assert_eq!(CLOCK_SKEW_TOLERANCE_NS, 1_000_000_000i64);
    }

    // ── is_future_timestamp_beyond_skew ──────────────────────────────────────

    #[test]
    fn beyond_skew_one_ns_over_tolerance_is_future() {
        let now_ns = 1_700_000_000_000_000_000i64;
        let ts_ns = now_ns + CLOCK_SKEW_TOLERANCE_NS + 1;
        assert!(is_future_timestamp_beyond_skew(ts_ns, now_ns));
    }

    #[test]
    fn beyond_skew_exactly_at_tolerance_is_not_future() {
        // ts == now + tolerance → NOT flagged (within acceptable skew)
        let now_ns = 1_700_000_000_000_000_000i64;
        let ts_ns = now_ns + CLOCK_SKEW_TOLERANCE_NS;
        assert!(!is_future_timestamp_beyond_skew(ts_ns, now_ns));
    }

    #[test]
    fn beyond_skew_one_ns_under_tolerance_is_not_future() {
        // Sub-second future delta → allowed
        let now_ns = 1_700_000_000_000_000_000i64;
        let ts_ns = now_ns + CLOCK_SKEW_TOLERANCE_NS - 1;
        assert!(!is_future_timestamp_beyond_skew(ts_ns, now_ns));
    }

    #[test]
    fn beyond_skew_in_past_is_not_future() {
        let now_ns = 1_700_000_000_000_000_000i64;
        let ts_ns = now_ns - 1_000_000_000; // 1 second ago
        assert!(!is_future_timestamp_beyond_skew(ts_ns, now_ns));
    }

    #[test]
    fn beyond_skew_five_seconds_ahead_is_flagged() {
        // 5s ahead is well beyond normal NTP tolerance → suspicious
        let now_ns = 1_700_000_000_000_000_000i64;
        let ts_ns = now_ns + 5_000_000_000i64;
        assert!(is_future_timestamp_beyond_skew(ts_ns, now_ns));
    }
}
