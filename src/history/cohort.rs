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
