//! Epoch tags, ordering keys (LSN), cohort topology, and materialization safety.

/// Opaque 32-byte identifier for a single temporal state within a cohort.
///
/// Computed as a hash of (source_id, ordering_key, wall_time). Two states with equal
/// `EpochTag` values are considered identical snapshots of the same artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EpochTag(pub [u8; 32]);

impl EpochTag {
    /// All-zero sentinel used as a placeholder before the real tag is computed.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Construct from a pre-computed 32-byte digest.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// The ordering coordinate for a `TemporalState` within a `LinearJournal` or
/// `SubJournalCommits` cohort topology.
///
/// Carries source-specific ordering information. Not all sources have absolute wall time;
/// some are ordering-only (LSN, seqnum). The `ClockProvenance.ordering_only` flag records this.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsnKind {
    /// SQLite WAL frame coordinate, qualified by checkpoint generation.
    ///
    /// `(salt1, salt2)` pin the salt epoch: a checkpoint reset rolls both salts and
    /// renumbers frames, so `frame_seq` is only comparable within a single epoch.
    /// Ordering across epochs is therefore lexicographic on `(salt1, salt2, frame_seq)`,
    /// and the salt change marks a cohort discontinuity (see `CohortTopology`).
    SqliteWalFrame {
        /// WAL salt-1 — the checkpoint generation seed (incremented on each reset).
        salt1: u32,
        /// WAL salt-2 — a fresh random value written at each checkpoint reset.
        salt2: u32,
        /// Frame sequence within this salt epoch (0-based, file order).
        frame_seq: u32,
        /// Committed transaction sequence (increments at each COMMIT marker frame).
        commit_seq: u32,
    },
    /// ESE/JET database log sequence number (`.jrs` journal).
    EseLsn(u64),
    /// NTFS `$LogFile` LFS record number.
    NtfsLfs { record: u64 },
    /// systemd-journald sequence number (monotonic per boot + seqnum).
    JournaldSeq(u64),
    /// Git commit SHA-1 or SHA-256 (hex string).
    GitCommitSha(String),
    /// APFS transaction identifier.
    ApfsTransactionId(u64),
    /// btrfs generation number (incremented at each transaction commit).
    BtrfsGeneration(u64),
    /// Windows Volume Shadow Service shadow copy set identifier (16-byte UUID).
    VssShadowSetId([u8; 16]),
    /// NTFS USN journal record.
    UsnRecord { usn: u64 },
    /// Catch-all for source-specific ordering keys.
    Custom { name: &'static str, value: Vec<u8> },
}

/// Trigger that causes a `MaterializationSafety::AutoPruned` state to be destroyed.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PruneTrigger {
    /// `git gc` / pack-file compaction.
    GcRun,
    /// Log rotation (`logrotate`, journald vacuum, EVTX auto-archive).
    LogRotation,
    /// Volume or quota space pressure (LVM snapshot overflow, overlay2 layer eviction).
    SpacePressure,
    /// Explicit operator action (Time Machine oldest backup removed, S3 lifecycle rule).
    Manual,
    /// Background checkpoint (SQLite auto-checkpoint triggered by write-ahead threshold).
    AutoCheckpoint,
    Other(String),
}

/// How safe it is to materialize (read out) a temporal state without corrupting evidence.
///
/// The type-system contract (`StateMaterializer` trait) prevents calling the evidence-path
/// method when the source requires a working copy, without any runtime check.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializationSafety {
    /// Reading does not modify any file on disk.
    ///
    /// Examples: VSS block range, Time Machine backup directory, OCI lower layer,
    /// git object store read-only, btrfs snapshot mount.
    ReadOnlySafe,

    /// Requires a forensic-aware reader. Naively opening with the default library
    /// would destroy the state.
    ///
    /// Examples: SQLite WAL pre-replay (libsqlite3 auto-checkpoints on open),
    /// ESE journal interpretation without soft-recovery (esentutl /r would replay).
    ///
    /// Rule: use a forensic reader (`chat4n6`, raw-WAL walk) rather than the native library.
    ReadOnlyRequiresCareful,

    /// Materialization **modifies** the source on disk (irrecoverable without a copy).
    ///
    /// Examples: `esentutl /r` on an ESE journal, `fsck` on an ext4 image,
    /// libsqlite3 default open (triggers WAL checkpoint).
    ///
    /// Rule: always work on a verified write-blocked copy (`WorkingCopy`).
    Destructive,

    /// The state is ephemeral; it cannot be re-materialized after this acquisition window.
    ///
    /// Examples: LVM snapshot approaching overflow limit, ring buffer about to be overwritten.
    ///
    /// Rule: acquire now or lose forever.
    EphemeralOnce,

    /// The state will be automatically destroyed by a background process.
    ///
    /// Examples: `git gc` compacting loose objects, Time Machine deleting the oldest backup,
    /// log rotation deleting `.log.7`, SQLite WAL auto-checkpoint threshold.
    AutoPruned { trigger: PruneTrigger },
}

/// Structural shape of the ordering between states in a `TemporalCohort`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CohortTopology {
    /// Unordered set of independent snapshots.
    ///
    /// Examples: VSS shadow copies, APFS snapshots, Time Machine backups, iTunes backups.
    DiscreteSet,

    /// Totally ordered sequence of states indexed by LSN (no branching).
    ///
    /// Examples: SQLite WAL (frame granularity), ESE `.jrs`, NTFS `$LogFile`,
    /// journald sequence, PostgreSQL WAL archive.
    LinearJournal { lsn_type: LsnKind },

    /// Ordered by committed transaction boundaries within a journal.
    ///
    /// Refinement of `LinearJournal`: each state is a fully committed transaction,
    /// not an individual log record. Uncommitted tail frames are tracked separately.
    ///
    /// Examples: SQLite WAL at `COMMIT`-boundary granularity, ESE at checkpoint granularity.
    SubJournalCommits,

    /// Directed acyclic graph of states (branching, merging).
    ///
    /// Examples: git commit graph, btrfs subvolumes with `btrfs send -p`, VHDX differencing chain.
    Dag,
}
