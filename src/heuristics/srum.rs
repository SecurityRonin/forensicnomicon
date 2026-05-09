//! SRUM (System Resource Usage Monitor) resource ratio heuristics.

/// Ratio threshold above which background CPU dominates (miner indicator).
/// background_cycles / foreground_cycles >= this value is suspicious.
pub const BACKGROUND_CPU_DOMINANCE_RATIO: u64 = 10;

/// Minimum bytes-sent to bytes-received ratio indicating potential exfiltration.
pub const EXFIL_BYTES_RATIO: u64 = 10;

/// Single-session outbound volume threshold for exfiltration candidate.
pub const EXFIL_VOLUME_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB

/// Returns `true` if background CPU cycles dominate foreground cycles by the
/// dominance ratio threshold. Zero foreground cycles returns `true` only when
/// background cycles are non-zero (idle processes are not flagged).
#[must_use]
pub fn is_background_cpu_dominant(background_cycles: u64, foreground_cycles: u64) -> bool {
    background_cycles > 0
        && (foreground_cycles == 0
            || background_cycles / foreground_cycles >= BACKGROUND_CPU_DOMINANCE_RATIO)
}

/// Returns `true` if outbound bytes exceed inbound bytes by the exfil ratio threshold.
/// Zero bytes-received returns `true` when bytes-sent is non-zero.
#[must_use]
pub fn is_exfil_ratio(bytes_sent: u64, bytes_received: u64) -> bool {
    bytes_sent > 0 && (bytes_received == 0 || bytes_sent / bytes_received >= EXFIL_BYTES_RATIO)
}

/// Returns `true` if total outbound bytes exceed the exfiltration volume threshold.
#[must_use]
pub fn is_exfil_volume(bytes_sent: u64) -> bool {
    bytes_sent >= EXFIL_VOLUME_BYTES
}

/// Minimum foreground cycles to consider a phantom-foreground anomaly meaningful.
/// Avoids flagging processes with trivially brief (sub-quantization) foreground time.
pub const PHANTOM_FOREGROUND_MIN_CYCLES: u64 = 1_000;

/// Returns `true` if a process had foreground CPU cycles but zero focus time.
///
/// A process charged foreground cycles but with no Application Timeline focus
/// is anomalous: the scheduler considered it "in front" but the user never
/// directed input to it. Possible causes: `SetForegroundWindow` abuse, or
/// a window briefly flashing to the top without user interaction.
///
/// Only meaningful when focus data is present (i.e., Application Timeline was
/// successfully merged into the record). The caller is responsible for ensuring
/// `focus_time_ms` came from a real measurement, not a missing-data default.
#[must_use]
pub fn is_phantom_foreground(foreground_cycles: u64, focus_time_ms: u64) -> bool {
    foreground_cycles >= PHANTOM_FOREGROUND_MIN_CYCLES && focus_time_ms == 0
}

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
    fn background_not_dominant_both_zero() {
        assert!(!is_background_cpu_dominant(0, 0));
    }

    #[test]
    fn background_not_dominant_background_zero_foreground_nonzero() {
        assert!(!is_background_cpu_dominant(0, 500));
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

    // ── is_automated_execution tests ─────────────────────────────────────────

    #[test]
    fn automated_execution_triggered_at_threshold_with_no_input() {
        assert!(is_automated_execution(AUTOMATED_EXECUTION_FOCUS_THRESHOLD_MS, 0));
    }

    #[test]
    fn automated_execution_triggered_above_threshold_with_no_input() {
        assert!(is_automated_execution(AUTOMATED_EXECUTION_FOCUS_THRESHOLD_MS + 1, 0));
    }

    #[test]
    fn automated_execution_not_triggered_below_threshold() {
        assert!(!is_automated_execution(AUTOMATED_EXECUTION_FOCUS_THRESHOLD_MS - 1, 0));
    }

    #[test]
    fn automated_execution_not_triggered_when_input_present() {
        assert!(!is_automated_execution(AUTOMATED_EXECUTION_FOCUS_THRESHOLD_MS, 1));
    }

    #[test]
    fn automated_execution_not_triggered_both_zero() {
        assert!(!is_automated_execution(0, 0));
    }

    // ── is_phantom_foreground tests ───────────────────────────────────────────

    #[test]
    fn phantom_foreground_triggered_when_fg_cycles_and_no_focus() {
        assert!(is_phantom_foreground(1_000, 0));
    }

    #[test]
    fn phantom_foreground_not_triggered_when_focus_present() {
        assert!(!is_phantom_foreground(1_000, 30_000));
    }

    #[test]
    fn phantom_foreground_not_triggered_below_min_cycles() {
        assert!(!is_phantom_foreground(999, 0));
    }

    #[test]
    fn phantom_foreground_not_triggered_both_zero() {
        assert!(!is_phantom_foreground(0, 0));
    }
}
