//! Periodicity (C2 beaconing) detection thresholds and assessment.
//!
//! Command-and-control implants commonly "beacon" — contact their controller at
//! a regular cadence to fetch tasking. The forensic signal is the **regularity of
//! the inter-arrival intervals** between connections to one destination, not their
//! absolute spacing: a human's traffic to a site is bursty and irregular, whereas
//! an automated beacon repeats on a near-constant period (often with bounded
//! jitter). This module is the single source of truth for *what interval
//! regularity counts as beaconing*; the event-grouping and wiring live in the
//! orchestration layer (issen-correlation).
//!
//! ## Metric
//!
//! Regularity is measured by the **coefficient of variation (CoV)** of the
//! inter-arrival intervals — the sample standard deviation divided by the mean.
//! CoV is scale-invariant (a 60 s beacon and a 1 h beacon with the same relative
//! jitter score identically), so one threshold covers all cadences. A perfectly
//! regular beacon has CoV ≈ 0; human/irregular traffic has CoV well above the
//! threshold. This is the interval-consistency principle popularised by RITA
//! (Active Countermeasures' Real Intelligence Threat Analytics) reduced to a
//! single defensible triage statistic.
//!
//! ## Findings are observations
//!
//! A positive assessment shows a connection pattern *consistent with* automated
//! beaconing (MITRE ATT&CK T1071 Application Layer Protocol; T1571 Non-Standard
//! Port; T1029 Scheduled Transfer). It is not proof of C2 — legitimate software
//! (update checks, NTP, telemetry) also beacons. The defaults below are triage
//! thresholds, tunable by the caller.
//!
//! Sources:
//! - RITA beacon analysis — interval dispersion/skew scoring:
//!   Active Countermeasures, <https://github.com/activecm/rita>.
//! - MITRE ATT&CK T1071 / T1571 / T1029: <https://attack.mitre.org/techniques/T1071/>.

/// Thresholds defining when a series of connections to one destination is
/// *consistent with* periodic beaconing.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BeaconingThresholds {
    /// Minimum number of connections to the destination. Four connections yield
    /// three intervals — the floor for a meaningful dispersion estimate.
    pub min_occurrences: usize,
    /// Maximum coefficient of variation (stddev / mean) of the intervals for the
    /// series to count as regular. 0.25 tolerates ~25 % relative jitter while
    /// still excluding irregular human traffic.
    pub max_coefficient_of_variation: f64,
    /// Minimum mean interval, in seconds. Excludes sub-cadence bursts (rapid
    /// back-to-back connections), which are a different signal handled elsewhere;
    /// real beacons repeat on the order of tens of seconds to hours.
    pub min_interval_seconds: f64,
}

/// Default beaconing triage thresholds (see field docs for rationale).
pub const DEFAULT_BEACONING: BeaconingThresholds = BeaconingThresholds {
    min_occurrences: 4,
    max_coefficient_of_variation: 0.25,
    min_interval_seconds: 30.0,
};

/// A positive periodicity assessment: the measured shape of a beacon-consistent
/// series. All values are derived from the observed timestamps.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BeaconAssessment {
    /// Number of connections observed to the destination.
    pub occurrences: usize,
    /// Mean inter-arrival interval, in seconds.
    pub mean_interval_seconds: f64,
    /// Coefficient of variation of the intervals (0 = perfectly regular).
    pub coefficient_of_variation: f64,
}

/// Assess whether a destination's connection timestamps are *consistent with*
/// periodic beaconing, under `thresholds`.
///
/// `sorted_timestamps_ns` must be ascending Unix-nanosecond timestamps for
/// connections to a single destination. Returns `Some(assessment)` when the
/// series clears all thresholds, `None` otherwise. Panic-free: handles empty,
/// single-element, and zero-mean inputs without dividing by zero.
#[must_use]
pub fn assess_periodicity(
    sorted_timestamps_ns: &[i64],
    thresholds: &BeaconingThresholds,
) -> Option<BeaconAssessment> {
    let occurrences = sorted_timestamps_ns.len();
    if occurrences < thresholds.min_occurrences {
        return None;
    }
    // Inter-arrival intervals in seconds. Need at least two intervals for a
    // dispersion estimate, independent of the occurrence threshold.
    let intervals: Vec<f64> = sorted_timestamps_ns
        .windows(2)
        .map(|w| (w[1] - w[0]) as f64 / 1_000_000_000.0)
        .collect();
    if intervals.len() < 2 {
        return None;
    }
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean < thresholds.min_interval_seconds {
        return None;
    }
    // Sample standard deviation (N-1); mean >= min_interval_seconds > 0 here, so
    // the coefficient of variation never divides by zero.
    let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    let coefficient_of_variation = variance.sqrt() / mean;
    if coefficient_of_variation > thresholds.max_coefficient_of_variation {
        return None;
    }
    Some(BeaconAssessment {
        occurrences,
        mean_interval_seconds: mean,
        coefficient_of_variation,
    })
}

#[cfg(test)]
mod tests {

    #[test]
    fn assess_periodicity_needs_two_intervals() {
        let thresholds = BeaconingThresholds {
            min_occurrences: 2,
            max_coefficient_of_variation: 0.25,
            min_interval_seconds: 30.0,
        };
        // Two occurrences pass min_occurrences but yield only one interval -> None.
        assert!(assess_periodicity(&[0, 1_000_000_000], &thresholds).is_none());
    }
    use super::*;

    /// Build ascending ns timestamps from a start and a list of second-gaps.
    fn ts_from_intervals(start_s: i64, gaps_s: &[i64]) -> Vec<i64> {
        let mut out = vec![start_s * 1_000_000_000];
        let mut cur = start_s;
        for g in gaps_s {
            cur += g;
            out.push(cur * 1_000_000_000);
        }
        out
    }

    #[test]
    fn perfectly_regular_series_is_beaconing() {
        // 5 connections, exactly 60 s apart → CoV 0.
        let ts = ts_from_intervals(1_000_000, &[60, 60, 60, 60]);
        let a = assess_periodicity(&ts, &DEFAULT_BEACONING).expect("should detect beacon");
        assert_eq!(a.occurrences, 5);
        assert!((a.mean_interval_seconds - 60.0).abs() < 1e-9);
        assert!(a.coefficient_of_variation < 1e-9);
    }

    #[test]
    fn low_jitter_series_within_tolerance_is_beaconing() {
        // ~300 s cadence with small jitter, CoV well under 0.25.
        let ts = ts_from_intervals(2_000_000, &[300, 305, 295, 302, 298]);
        let a = assess_periodicity(&ts, &DEFAULT_BEACONING).expect("low jitter is a beacon");
        assert!(a.coefficient_of_variation < 0.25);
        assert_eq!(a.occurrences, 6);
    }

    #[test]
    fn irregular_human_traffic_is_not_beaconing() {
        // Wildly varying gaps → high CoV → not a beacon.
        let ts = ts_from_intervals(3_000_000, &[5, 3600, 40, 900, 7200]);
        assert!(assess_periodicity(&ts, &DEFAULT_BEACONING).is_none());
    }

    #[test]
    fn too_few_occurrences_is_not_beaconing() {
        // Only 3 connections (2 intervals) — below min_occurrences=4.
        let ts = ts_from_intervals(4_000_000, &[60, 60]);
        assert!(assess_periodicity(&ts, &DEFAULT_BEACONING).is_none());
    }

    #[test]
    fn sub_min_interval_burst_is_not_beaconing() {
        // Regular but every 5 s — below the 30 s floor (a burst, not a beacon).
        let ts = ts_from_intervals(5_000_000, &[5, 5, 5, 5, 5]);
        assert!(assess_periodicity(&ts, &DEFAULT_BEACONING).is_none());
    }

    #[test]
    fn empty_and_single_are_none_not_panic() {
        assert!(assess_periodicity(&[], &DEFAULT_BEACONING).is_none());
        assert!(assess_periodicity(&[42], &DEFAULT_BEACONING).is_none());
    }
}
