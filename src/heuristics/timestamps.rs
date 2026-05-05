//! NTFS timestamp precision and MACB consistency heuristics.

// NTFS stores 100-nanosecond intervals. A timestamp divisible by 10_000_000
// (= 1 second in 100-ns ticks) was written with only second-level precision —
// a common timestomping artifact.

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
}
