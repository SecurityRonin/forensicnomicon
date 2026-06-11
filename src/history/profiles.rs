//! Canonical clock and materialization profiles for known `[H]` sources.
//!
//! A source profile is forensic VOCABULARY, not an algorithm: it declares what a given
//! artifact family's temporal states ARE — how their ordering key is graded, and how safe
//! materialization is — so every consumer (sqlite-forensic, Issen, a future `wal-history`
//! crate, a memory-forensic SQLite-in-VA carve) agrees on one classification instead of
//! each re-deriving it and risking drift. Pure declarative knowledge; no I/O, no parsing.

use crate::history::clock::{ClockProvenance, ClockSource, TamperResistance, TrustGrade};
use crate::history::epoch::{MaterializationSafety, TopologyKind};

/// The structural shape of a source's ordering key — the *fifth* axis beyond the four
/// clock/safety classifications.
///
/// Two sources can share a clock profile yet order their states differently: a WAL is a
/// salt-qualified sequence, an EVTX log is wall-time-with-record-id. This axis records
/// that shape so a consumer knows how to compare two states' positions.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrderingBasis {
    /// Total order by a single monotonic sequence number, no wall time (ESE `.jrs` LSN).
    SequenceOnly,
    /// Total order by a TWO-level salt-qualified sequence: a generation counter (salt-1,
    /// `+1` per checkpoint-reset, random origin) plus an intra-generation frame index,
    /// with a per-generation nonce (salt-2) confirming epoch identity (SQLite WAL).
    SaltQualifiedSequence,
    /// Ordered primarily by an embedded wall-clock timestamp, tie-broken by a monotonic
    /// record id (EVTX `EventRecordID`, USN, journald seqnum).
    WallTimeWithRecordId,
    /// A content-addressed Merkle DAG: identity is the hash, order is ancestry (git).
    ContentHashDag,
    /// An unordered set of discrete snapshots, each independently wall-time-stamped (VSS).
    DiscreteSnapshotSet,
}

/// The canonical temporal characterization of one source family.
///
/// Bundles the four clock/safety classifications (via [`ClockProvenance`] +
/// [`MaterializationSafety`]) with the cohort [`TopologyKind`] and the [`OrderingBasis`].
/// One instance per source family is the fleet's single source of truth: a consumer
/// (sqlite-forensic's adapter, Issen, a future `wal-history` crate) reads the profile
/// rather than re-asserting any axis locally, so the fleet cannot drift.
///
/// Pure declarative knowledge — no parser, no I/O. A source's profile can live here even
/// when its parser lives in another repo (winevt-forensic, usnjrnl-forensic, …).
///
/// Defaults are chosen **secure-by-default**: where a source can be hardened (journald
/// FSS sealing), the profile encodes the *weaker, un-hardened* assumption so a consumer
/// never over-claims tamper resistance it has not verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTemporalProfile {
    /// Clock provenance shared by the source's temporal states (the four axes).
    pub clock: ClockProvenance,
    /// How safe it is to materialize a state without mutating the evidence.
    pub safety: MaterializationSafety,
    /// The shape of the source's temporal cohort.
    pub topology: TopologyKind,
    /// The structural shape of the source's ordering key.
    pub ordering: OrderingBasis,
}

impl SourceTemporalProfile {
    /// SQLite WAL: salt-qualified sequence, no wall time, non-crypto checksums, careful
    /// materialization (libsqlite3 auto-checkpoints on open).
    #[must_use]
    pub fn sqlite_wal() -> Self {
        Self {
            clock: sqlite_wal_clock(),
            safety: SQLITE_WAL_SAFETY,
            topology: TopologyKind::SubJournalCommits,
            ordering: OrderingBasis::SaltQualifiedSequence,
        }
    }

    /// Windows EVTX: each record carries an embedded `TimeCreated` wall clock, tie-broken
    /// by `EventRecordID`. Reading an `.evtx` never mutates it. An administrator can clear
    /// or forge the log (no cryptographic seal), so tamper resistance is `AdminWritable`.
    #[must_use]
    pub fn evtx() -> Self {
        Self {
            clock: ClockProvenance {
                source: ClockSource::LogRecord,
                trust_grade: TrustGrade::LocalSubsystem,
                tamper_resistance: TamperResistance::AdminWritable,
                ordering_only: false,
                skew_known: None,
                authenticated: None,
            },
            safety: MaterializationSafety::ReadOnlySafe,
            topology: TopologyKind::LinearJournal,
            ordering: OrderingBasis::WallTimeWithRecordId,
        }
    }

    /// NTFS USN change journal: each record carries a wall-clock `TimeStamp`, ordered by a
    /// monotonic USN offset. Read-only; admin-writable (the journal can be cleared).
    #[must_use]
    pub fn usn_journal() -> Self {
        Self {
            clock: ClockProvenance {
                source: ClockSource::LogRecord,
                trust_grade: TrustGrade::LocalSubsystem,
                tamper_resistance: TamperResistance::AdminWritable,
                ordering_only: false,
                skew_known: None,
                authenticated: None,
            },
            safety: MaterializationSafety::ReadOnlySafe,
            topology: TopologyKind::LinearJournal,
            ordering: OrderingBasis::WallTimeWithRecordId,
        }
    }

    /// ESE/JET transaction log (`.jrs`): ordered by a sequence-only LSN (no wall time in
    /// the journal coordinate). `esentutl /r` replays and mutates, so materialization is
    /// careful. Admin-writable on disk.
    #[must_use]
    pub fn ese_journal() -> Self {
        Self {
            clock: ClockProvenance {
                source: ClockSource::SequenceOnly,
                trust_grade: TrustGrade::OrderingOnly,
                tamper_resistance: TamperResistance::AdminWritable,
                ordering_only: true,
                skew_known: None,
                authenticated: None,
            },
            safety: MaterializationSafety::ReadOnlyRequiresCareful,
            topology: TopologyKind::SubJournalCommits,
            ordering: OrderingBasis::SequenceOnly,
        }
    }

    /// systemd-journald (un-sealed default): wall-clock `__REALTIME_TIMESTAMP` ordered by
    /// seqnum + boot-id. Read-only. Secure-by-default: the profile assumes NO FSS seal, so
    /// tamper resistance is `AdminWritable`; an FSS-sealed journal upgrades to
    /// [`TamperResistance::AppendOnlyLocal`] but a consumer must verify the seal first.
    #[must_use]
    pub fn journald() -> Self {
        Self {
            clock: ClockProvenance {
                source: ClockSource::LogRecord,
                trust_grade: TrustGrade::LocalSubsystem,
                tamper_resistance: TamperResistance::AdminWritable,
                ordering_only: false,
                skew_known: None,
                authenticated: None,
            },
            safety: MaterializationSafety::ReadOnlySafe,
            topology: TopologyKind::LinearJournal,
            ordering: OrderingBasis::WallTimeWithRecordId,
        }
    }

    /// Windows VSS shadow copies: an unordered set of discrete snapshots, each carrying a
    /// filesystem-metadata creation time. Mounting/reading a shadow copy is read-only;
    /// the snapshot set is admin-writable (an admin can delete shadow copies).
    #[must_use]
    pub fn vss() -> Self {
        Self {
            clock: ClockProvenance {
                source: ClockSource::FileMetadata,
                trust_grade: TrustGrade::LocalSubsystem,
                tamper_resistance: TamperResistance::AdminWritable,
                ordering_only: false,
                skew_known: None,
                authenticated: None,
            },
            safety: MaterializationSafety::ReadOnlySafe,
            topology: TopologyKind::DiscreteSet,
            ordering: OrderingBasis::DiscreteSnapshotSet,
        }
    }

    /// git: a content-addressed Merkle DAG. The commit graph's integrity is a topology
    /// property (ancestry cannot change without changing hashes), but the commit/author
    /// *timestamps* are trivially forgeable (`GIT_COMMITTER_DATE`), so the CLOCK's tamper
    /// resistance is `Trivial` and its trust grade `LocalApplication`. Reading the object
    /// store is read-only.
    #[must_use]
    pub fn git() -> Self {
        Self {
            clock: ClockProvenance {
                source: ClockSource::ApplicationEmbedded,
                trust_grade: TrustGrade::LocalApplication,
                tamper_resistance: TamperResistance::Trivial,
                ordering_only: false,
                skew_known: None,
                authenticated: None,
            },
            safety: MaterializationSafety::ReadOnlySafe,
            topology: TopologyKind::Dag,
            ordering: OrderingBasis::ContentHashDag,
        }
    }

    /// Every source family the registry characterizes — used for fleet-wide invariants.
    #[must_use]
    pub fn all() -> [Self; 7] {
        [
            Self::sqlite_wal(),
            Self::evtx(),
            Self::usn_journal(),
            Self::ese_journal(),
            Self::journald(),
            Self::vss(),
            Self::git(),
        ]
    }
}

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
