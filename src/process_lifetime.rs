//! Process-lifetime thresholds for short-lived-process triage.
//!
//! A process that starts and exits within a very short span is one component
//! signal in network-risk triage: droppers, loaders, and living-off-the-land
//! one-shots (`cmd /c`, `rundll32`, a staging binary) exec-and-exit quickly,
//! whereas interactive apps and services persist. Short lifetime alone is NOT
//! suspicious — countless benign utilities are short-lived — so this is only a
//! *contributing* signal to a composite score, never a standalone verdict.
//!
//! This module is the single source of truth for the threshold; the pairing of
//! start/exit events into a lifetime lives in the orchestration layer.
//!
//! Sources:
//! - MITRE ATT&CK T1059 (Command and Scripting Interpreter) / T1106 (Native API)
//!   — one-shot execution patterns: <https://attack.mitre.org/techniques/T1059/>.

/// A process whose lifetime (exit − start) is at or below this many seconds is
/// classified *short-lived*. 60 s separates one-shot execution from interactive
/// or service processes while staying well under any periodic-beacon cadence, so
/// a genuinely beaconing process (which must live across several intervals) is
/// not mislabelled. A component signal, tunable by the caller.
pub const SHORT_LIVED_THRESHOLD_SECONDS: i64 = 60;

/// Whether a process lifetime (in seconds) counts as short-lived under
/// [`SHORT_LIVED_THRESHOLD_SECONDS`]. A negative lifetime (exit before start —
/// malformed or clock-skewed) is not short-lived.
#[must_use]
pub fn is_short_lived(lifetime_seconds: i64) -> bool {
    (0..=SHORT_LIVED_THRESHOLD_SECONDS).contains(&lifetime_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_threshold_lifetime_is_short_lived() {
        assert!(is_short_lived(5));
        assert!(is_short_lived(SHORT_LIVED_THRESHOLD_SECONDS));
    }

    #[test]
    fn above_threshold_lifetime_is_not_short_lived() {
        assert!(!is_short_lived(SHORT_LIVED_THRESHOLD_SECONDS + 1));
        assert!(!is_short_lived(3600));
    }

    #[test]
    fn negative_lifetime_is_not_short_lived() {
        assert!(!is_short_lived(-1));
    }
}
