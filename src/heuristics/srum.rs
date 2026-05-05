//! SRUM (System Resource Usage Monitor) resource ratio heuristics.

/// Ratio threshold above which background CPU dominates (miner indicator).
/// background_cycles / foreground_cycles >= this value is suspicious.
pub const BACKGROUND_CPU_DOMINANCE_RATIO: u64 = 10;

/// Minimum bytes-sent to bytes-received ratio indicating potential exfiltration.
pub const EXFIL_BYTES_RATIO: u64 = 10;

/// Single-session outbound volume threshold for exfiltration candidate.
pub const EXFIL_VOLUME_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB

/// Returns `true` if background CPU cycles dominate foreground cycles by the
/// dominance ratio threshold. Zero foreground cycles also returns `true`.
#[must_use]
pub fn is_background_cpu_dominant(_background_cycles: u64, _foreground_cycles: u64) -> bool {
    todo!()
}

/// Returns `true` if outbound bytes exceed inbound bytes by the exfil ratio threshold.
/// Zero bytes-received returns `true` when bytes-sent is non-zero.
#[must_use]
pub fn is_exfil_ratio(_bytes_sent: u64, _bytes_received: u64) -> bool { todo!() }

/// Returns `true` if total outbound bytes exceed the exfiltration volume threshold.
#[must_use]
pub fn is_exfil_volume(_bytes_sent: u64) -> bool { todo!() }

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_dominates_foreground_zero() {
        assert!(is_background_cpu_dominant(1000, 0));
    }

    #[test]
    fn background_dominates_ratio_10x() {
        assert!(is_background_cpu_dominant(1000, 100));
    }

    #[test]
    fn background_dominates_ratio_just_over() {
        assert!(is_background_cpu_dominant(1001, 100));
    }

    #[test]
    fn background_not_dominant_equal() {
        assert!(!is_background_cpu_dominant(100, 100));
    }

    #[test]
    fn background_not_dominant_below_ratio() {
        // 999 / 100 = 9, which is < 10
        assert!(!is_background_cpu_dominant(999, 100));
    }

    #[test]
    fn exfil_ratio_ten_to_one() {
        assert!(is_exfil_ratio(1000, 100));
    }

    #[test]
    fn exfil_ratio_recv_zero_sent_nonzero() {
        assert!(is_exfil_ratio(1, 0));
    }

    #[test]
    fn exfil_ratio_not_triggered_equal() {
        assert!(!is_exfil_ratio(100, 100));
    }

    #[test]
    fn exfil_ratio_not_triggered_below() {
        // 500 / 100 = 5, which is < 10
        assert!(!is_exfil_ratio(500, 100));
    }

    #[test]
    fn exfil_ratio_sent_zero_not_triggered() {
        assert!(!is_exfil_ratio(0, 0));
    }

    #[test]
    fn exfil_volume_above_threshold() {
        assert!(is_exfil_volume(EXFIL_VOLUME_BYTES + 1));
    }

    #[test]
    fn exfil_volume_below_threshold() {
        assert!(!is_exfil_volume(EXFIL_VOLUME_BYTES - 1));
    }

    #[test]
    fn exfil_volume_at_threshold() {
        assert!(is_exfil_volume(EXFIL_VOLUME_BYTES));
    }
}
