//! Canonical clock and materialization profiles for known `[H]` sources.
//!
//! A source profile is forensic VOCABULARY, not an algorithm: it declares what a given
//! artifact family's temporal states ARE — how their ordering key is graded, and how safe
//! materialization is — so every consumer (sqlite-forensic, Issen, a future `wal-history`
//! crate, a memory-forensic SQLite-in-VA carve) agrees on one classification instead of
//! each re-deriving it and risking drift. Pure declarative knowledge; no I/O, no parsing.

use crate::history::clock::{ClockProvenance, ClockSource, TamperResistance, TrustGrade};
use crate::history::epoch::MaterializationSafety;

/// The clock provenance shared by every SQLite WAL commit state.
///
/// A WAL frame carries no absolute wall time — only a salt-qualified sequence position
/// (`LsnKind::SqliteWalFrame`), so the clock is `ordering_only`. The frame checksums are
/// non-cryptographic (they detect corruption, not tampering), and any process able to
/// write the database can rewrite the WAL — hence `UserWritable` tamper resistance and an
/// `OrderingOnly` trust grade. No external authentication, no measurable skew.
#[must_use]
pub fn sqlite_wal_clock() -> ClockProvenance {
    ClockProvenance {
        source: ClockSource::SequenceOnly,
        trust_grade: TrustGrade::OrderingOnly,
        tamper_resistance: TamperResistance::UserWritable,
        ordering_only: true,
        skew_known: None,
        authenticated: None,
    }
}

/// Materialization safety for a SQLite WAL commit state.
///
/// libsqlite3's default `open()` auto-checkpoints, which rewrites both the main database
/// and the `-wal` sidecar. Materializing a commit state therefore requires a forensic
/// raw-WAL reader rather than the native library: [`MaterializationSafety::ReadOnlyRequiresCareful`].
pub const SQLITE_WAL_SAFETY: MaterializationSafety = MaterializationSafety::ReadOnlyRequiresCareful;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::clock::{ClockSource, TamperResistance, TrustGrade};
    use crate::history::epoch::{MaterializationSafety, TopologyKind};

    #[test]
    fn sqlite_wal_clock_is_ordering_only_and_user_writable() {
        let c = sqlite_wal_clock();
        // A WAL frame carries no wall clock — only a salt-qualified sequence position.
        assert_eq!(c.source, ClockSource::SequenceOnly);
        assert_eq!(c.trust_grade, TrustGrade::OrderingOnly);
        // WAL frame checksums are non-cryptographic: corruption detection, not tamper
        // evidence. Any process that can write the DB can rewrite the WAL.
        assert_eq!(c.tamper_resistance, TamperResistance::UserWritable);
        assert!(c.ordering_only);
        assert!(c.authenticated.is_none());
        assert!(c.skew_known.is_none());
    }

    #[test]
    fn sqlite_wal_safety_requires_careful_reader() {
        // libsqlite3's default open() auto-checkpoints, mutating BOTH files; a forensic
        // raw-WAL reader is required to materialize a commit state read-only.
        assert_eq!(
            SQLITE_WAL_SAFETY,
            MaterializationSafety::ReadOnlyRequiresCareful
        );
    }

    #[test]
    fn sqlite_wal_profile_bundles_the_four_axes_plus_ordering_shape() {
        let p = SourceTemporalProfile::sqlite_wal();
        assert_eq!(p.clock, sqlite_wal_clock());
        assert_eq!(p.safety, MaterializationSafety::ReadOnlyRequiresCareful);
        assert_eq!(p.topology, TopologyKind::SubJournalCommits);
        // WAL is a TWO-level salt-qualified sequence, not a flat one.
        assert_eq!(p.ordering, OrderingBasis::SaltQualifiedSequence);
    }

    #[test]
    fn evtx_profile_has_wall_time_unlike_wal() {
        let p = SourceTemporalProfile::evtx();
        // EVTX records carry an embedded wall clock (TimeCreated) — the axis that
        // distinguishes it from WAL.
        assert_eq!(p.clock.source, ClockSource::LogRecord);
        assert!(!p.clock.ordering_only);
        assert_eq!(p.clock.trust_grade, TrustGrade::LocalSubsystem);
        assert_eq!(p.clock.tamper_resistance, TamperResistance::AdminWritable);
        assert_eq!(p.safety, MaterializationSafety::ReadOnlySafe);
        assert_eq!(p.topology, TopologyKind::LinearJournal);
        assert_eq!(p.ordering, OrderingBasis::WallTimeWithRecordId);
        // The proving pair: WAL and EVTX disagree on the ordering axis.
        assert_ne!(p.ordering, SourceTemporalProfile::sqlite_wal().ordering);
    }

    #[test]
    fn every_source_profile_keeps_ordering_only_in_sync_with_its_clock() {
        // The cross-source invariant: a profile is `ordering_only` IFF its clock is a
        // pure sequence (no wall time). Holds by construction for every source.
        for p in SourceTemporalProfile::all() {
            assert_eq!(
                p.clock.ordering_only,
                p.clock.source == ClockSource::SequenceOnly,
                "ordering_only must track SequenceOnly for {:?}",
                p.ordering
            );
        }
    }

    #[test]
    fn registry_is_not_journal_shaped() {
        // Spot-check the non-journal topologies so the abstraction generalizes past logs.
        assert_eq!(
            SourceTemporalProfile::vss().topology,
            TopologyKind::DiscreteSet
        );
        assert_eq!(
            SourceTemporalProfile::vss().ordering,
            OrderingBasis::DiscreteSnapshotSet
        );
        assert_eq!(SourceTemporalProfile::git().topology, TopologyKind::Dag);
        assert_eq!(
            SourceTemporalProfile::git().ordering,
            OrderingBasis::ContentHashDag
        );
        // git commit timestamps are trivially forgeable (GIT_COMMITTER_DATE); the DAG's
        // integrity is a topology property, not a clock one.
        assert_eq!(
            SourceTemporalProfile::git().clock.tamper_resistance,
            TamperResistance::Trivial
        );
    }
}
