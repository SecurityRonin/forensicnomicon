//! Temporal cohorts and states — the generic-over-handle `[H]` carrier types.

use crate::history::{
    clock::ClockProvenance,
    epoch::{CohortTopology, EpochTag, LsnKind, MaterializationSafety},
    identity::{ArtifactRef, IdentityDiscipline},
};

/// Unix timestamp (seconds since epoch + nanosecond subsecond component).
///
/// Chrono-free; callers that use `chrono` can convert via `DateTime::from_timestamp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    /// Seconds since Unix epoch (UTC).
    pub secs: i64,
    /// Subsecond component in nanoseconds \[0, 999_999_999\].
    pub nanos: u32,
}

impl Timestamp {
    #[must_use]
    pub fn from_secs(secs: i64) -> Self {
        Self { secs, nanos: 0 }
    }
}

/// A single temporal state of an artifact within a cohort.
///
/// The generic parameter `H` is the concrete handle type defined by the `HistoricalSource`
/// implementor (e.g. `PathBuf` for a VSS shadow mount path, `u32` for a WAL frame index,
/// `[u8; 20]` for a git commit OID). Using a generic avoids trait-object overhead while
/// preserving a uniform API for ORCHESTRATION.
#[derive(Debug)]
pub struct TemporalState<H> {
    /// Opaque identifier for this epoch; stable for the lifetime of the source.
    pub epoch: EpochTag,
    /// Source-specific ordering key (LSN, commit sequence, etc.). `None` for discrete sets.
    pub ordering_key: Option<LsnKind>,
    /// Absolute wall time for this epoch, if known. `None` when `clock.ordering_only` is true.
    pub wall_time: Option<Timestamp>,
    /// Clock provenance for `wall_time` (or for the ordering key if `ordering_only`).
    pub clock: ClockProvenance,
    /// How to safely access this state without destroying evidence.
    pub safety: MaterializationSafety,
    /// Source-defined handle for locating / materializing this state.
    pub handle: H,
}

/// Ordered set of temporal states for a single logical artifact under one identity discipline.
///
/// `states` is chronologically ordered where `wall_time` is available; ordering-only cohorts
/// are ordered by `ordering_key`. States with equal ordering are ordered arbitrarily.
///
/// Identity disagreement within a cohort (e.g. same path but diverging content hashes at an
/// unexpected point) is reported via `identity_discontinuities()`.
#[derive(Debug)]
pub struct TemporalCohort<H> {
    /// The artifact this cohort describes.
    pub artifact: ArtifactRef,
    /// The discipline under which identity was determined.
    pub discipline: IdentityDiscipline,
    /// Structural relationship between states (discrete set, linear journal, DAG, …).
    pub topology: CohortTopology,
    /// Chronologically ordered temporal states. Ordering is by `wall_time` when available,
    /// else by `ordering_key`, else arbitrary.
    pub states: Vec<TemporalState<H>>,
}

impl<H> TemporalCohort<H> {
    /// Return the state whose `wall_time` is closest to and not after `t`.
    ///
    /// Returns `None` if no state has a `wall_time` at or before `t`.
    #[must_use]
    pub fn at(&self, t: Timestamp) -> Option<&TemporalState<H>> {
        self.states
            .iter()
            .filter(|s| s.wall_time.is_some_and(|wt| wt <= t))
            .max_by_key(|s| s.wall_time)
    }

    /// Return the state whose `wall_time` is nearest to `t` (before or after).
    ///
    /// Returns `None` if no state has a `wall_time`.
    #[must_use]
    pub fn nearest(&self, t: Timestamp) -> Option<&TemporalState<H>> {
        self.states
            .iter()
            .filter(|s| s.wall_time.is_some())
            .min_by_key(|s| {
                // Safe: filtered to `Some` above.
                let wt = s.wall_time.unwrap_or(t);
                (wt.secs - t.secs).unsigned_abs()
            })
    }

    /// Epochs present in this cohort, in order.
    pub fn epochs(&self) -> impl Iterator<Item = EpochTag> + '_ {
        self.states.iter().map(|s| s.epoch)
    }
}

/// A cohort-level gap: a state that existed in an earlier epoch but is absent in a later one.
///
/// Not equivalent to file deletion — the absence may be due to pruning, compaction, or
/// selective acquisition. The interpretation requires cross-cohort context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// Epoch of the last known state before the gap.
    pub last_seen_epoch: EpochTag,
    /// Epoch of the first subsequent state in which the artifact is absent.
    pub first_absent_epoch: EpochTag,
}

/// A point in the cohort where the artifact's identity became inconsistent under a
/// secondary discipline, while remaining consistent under the primary discipline.
///
/// For example: a `PathStable` cohort where the `ContentStable` sub-grouping splits at
/// a particular epoch indicates the file at that path was silently replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDiscontinuity {
    /// The epoch at which the discontinuity was first observed.
    pub at_epoch: EpochTag,
    /// The secondary discipline that revealed the inconsistency.
    pub discipline: IdentityDiscipline,
    /// Human-readable description of the inconsistency.
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::clock::{ClockSource, TamperResistance, TrustGrade};

    fn clock() -> ClockProvenance {
        ClockProvenance {
            source: ClockSource::SequenceOnly,
            trust_grade: TrustGrade::OrderingOnly,
            tamper_resistance: TamperResistance::UserWritable,
            ordering_only: false,
            skew_known: None,
            authenticated: None,
        }
    }

    fn state(handle: u32, secs: Option<i64>) -> TemporalState<u32> {
        TemporalState {
            epoch: EpochTag([handle as u8; 32]),
            ordering_key: None,
            wall_time: secs.map(Timestamp::from_secs),
            clock: clock(),
            safety: MaterializationSafety::ReadOnlySafe,
            handle,
        }
    }

    fn cohort(states: Vec<TemporalState<u32>>) -> TemporalCohort<u32> {
        TemporalCohort {
            artifact: ArtifactRef { claims: vec![] },
            discipline: IdentityDiscipline::PathStable,
            topology: CohortTopology::DiscreteSet,
            states,
        }
    }

    #[test]
    fn from_secs_zeroes_nanos() {
        let t = Timestamp::from_secs(1_700_000_000);
        assert_eq!(t.secs, 1_700_000_000);
        assert_eq!(t.nanos, 0);
    }

    #[test]
    fn at_selects_latest_state_at_or_before_t() {
        // A `None` wall_time state must be filtered out, never selected.
        let c = cohort(vec![
            state(1, Some(100)),
            state(2, Some(200)),
            state(3, Some(300)),
            state(9, None),
        ]);
        // Between 200 and 300 -> the 200 state.
        assert_eq!(c.at(Timestamp::from_secs(250)).unwrap().handle, 2);
        // Exact match on the last state.
        assert_eq!(c.at(Timestamp::from_secs(300)).unwrap().handle, 3);
        // Before the first state -> None.
        assert!(c.at(Timestamp::from_secs(50)).is_none());
    }

    #[test]
    fn at_returns_none_when_no_state_has_wall_time() {
        let c = cohort(vec![state(1, None)]);
        assert!(c.at(Timestamp::from_secs(100)).is_none());
    }

    #[test]
    fn nearest_picks_closest_and_breaks_ties_toward_first() {
        let c = cohort(vec![
            state(1, Some(100)),
            state(2, Some(200)),
            state(3, Some(300)),
            state(9, None),
        ]);
        // 280 is closest to 300.
        assert_eq!(c.nearest(Timestamp::from_secs(280)).unwrap().handle, 3);
        // 250 is equidistant to 200 and 300; min_by_key keeps the first-seen (200).
        assert_eq!(c.nearest(Timestamp::from_secs(250)).unwrap().handle, 2);
        // A time before every state still returns the nearest (100).
        assert_eq!(c.nearest(Timestamp::from_secs(0)).unwrap().handle, 1);
    }

    #[test]
    fn nearest_returns_none_without_wall_times() {
        let c = cohort(vec![state(1, None)]);
        assert!(c.nearest(Timestamp::from_secs(100)).is_none());
    }

    #[test]
    fn epochs_yields_epoch_tags_in_state_order() {
        let c = cohort(vec![state(1, Some(100)), state(2, Some(200))]);
        let epochs: Vec<EpochTag> = c.epochs().collect();
        assert_eq!(epochs, vec![EpochTag([1u8; 32]), EpochTag([2u8; 32])]);
    }
}
