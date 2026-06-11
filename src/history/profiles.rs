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
    use crate::history::epoch::MaterializationSafety;

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
}
