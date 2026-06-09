//! `HistoricalSource`, `AcquisitionProtocol`, and `StateMaterializer` trait boundaries.

use crate::history::{
    cohort::TemporalCohort,
    epoch::{EpochTag, MaterializationSafety},
    identity::{ArtifactRef, IdentityDiscipline},
};

/// Opaque source identifier string (e.g. "vss:HarddiskVolumeShadowCopy3").
pub type SourceId = String;

/// Filter passed to `HistoricalSource::enumerate()`.
#[derive(Debug, Clone)]
pub struct CohortQuery {
    /// If set, restrict enumeration to artifacts matching this ref under any discipline.
    pub artifact: Option<ArtifactRef>,
    /// If set, apply this identity discipline when grouping states into cohorts.
    pub discipline: Option<IdentityDiscipline>,
}

impl CohortQuery {
    /// Enumerate all artifacts under all disciplines.
    #[must_use]
    pub fn all() -> Self {
        Self {
            artifact: None,
            discipline: None,
        }
    }
}

/// A mutable working copy of an evidence artifact, required for `Destructive` sources.
///
/// The type-system separation (`&mut WorkingCopy` vs `&Evidence`) prevents callers from
/// accidentally passing live evidence to a materializer that would modify it.
pub struct WorkingCopy {
    /// Directory containing the write-unblocked copy of the artifact(s).
    pub path: std::path::PathBuf,
}

/// Opaque evidence reference for `ReadOnlySafe` and `ReadOnlyRequiresCareful` materializers.
///
/// Concrete types in ORCHESTRATION hold the actual evidence representation.
/// This module only defines the boundary type.
pub struct Evidence {
    /// Path to the write-blocked evidence file or directory.
    pub path: std::path::PathBuf,
}

/// A source that can enumerate the temporal cohorts of the artifacts it controls.
///
/// Each concrete `[H]` crate (vss-history, wal-history, git-history, …) implements this
/// trait. The associated `Handle` type carries whatever the implementor needs to locate or
/// materialize a specific epoch (e.g. `PathBuf` for a VSS shadow mount path, `u32` for a
/// WAL frame index).
///
/// `enumerate` returns an iterator rather than a `Vec` to support streaming enumeration of
/// large sources (e.g. a git repo with millions of commits).
pub trait HistoricalSource {
    /// The concrete handle type for locating / materializing epochs from this source.
    type Handle;

    /// Stable identifier for this source instance.
    fn id(&self) -> SourceId;

    /// Identity disciplines supported by this source.
    fn supported_disciplines(&self) -> &'static [IdentityDiscipline];

    /// Enumerate all temporal cohorts matching `query`.
    fn enumerate(&self, query: &CohortQuery) -> impl Iterator<Item = TemporalCohort<Self::Handle>>;

    /// Acquisition protocol companion for this source type.
    fn acquisition_protocol(&self) -> &dyn AcquisitionProtocol;
}

/// Acquisition safety requirements and verification steps for a `HistoricalSource`.
///
/// Each `[H]` crate ships an `AcquisitionProtocol` impl describing how to safely
/// acquire evidence from its source without destroying temporal states.
pub trait AcquisitionProtocol {
    /// Preconditions that must hold before acquisition begins.
    fn preconditions(&self) -> Vec<String>;

    /// Operations that must NOT be performed on live evidence.
    fn forbidden_operations(&self) -> Vec<&'static str>;

    /// Companion artifacts that must be acquired alongside the primary artifact.
    ///
    /// Examples: `main.db-wal` + `main.db-shm` for SQLite, all `.jrs` + `.chk` for ESE.
    fn required_companion_artifacts(&self) -> Vec<String>;

    /// Temporal states that will be permanently lost if these steps are skipped.
    fn destructive_if_skipped(&self) -> Vec<&'static str>;
}

/// Type-safe materializer for a single temporal state.
///
/// Implementors that have `ReadOnlySafe` or `ReadOnlyRequiresCareful` safety provide
/// `materialize`; those with `Destructive` safety provide `materialize_via_working_copy`.
/// The Rust type system prevents calling the wrong method.
pub trait StateMaterializer {
    /// How this materializer affects the evidence during access.
    fn safety(&self) -> MaterializationSafety;

    /// Materialize a state from read-only evidence.
    ///
    /// For `ReadOnlySafe` and `ReadOnlyRequiresCareful` sources.
    fn materialize<'a>(
        &'a self,
        epoch: EpochTag,
        ev: &'a Evidence,
    ) -> Result<std::path::PathBuf, String>;

    /// Materialize a state by modifying a working copy.
    ///
    /// For `Destructive` sources. Takes `&mut WorkingCopy` rather than `&Evidence` so
    /// the compiler rejects accidental use of live evidence here.
    fn materialize_via_working_copy(
        &self,
        epoch: EpochTag,
        wc: &mut WorkingCopy,
    ) -> Result<std::path::PathBuf, String>;
}
