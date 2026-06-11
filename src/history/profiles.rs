//! Canonical clock and materialization profiles for known `[H]` sources.
//!
//! A source profile is forensic VOCABULARY, not an algorithm: it declares what a given
//! artifact family's temporal states ARE — how their ordering key is graded, and how safe
//! materialization is — so every consumer (sqlite-forensic, Issen, a future `wal-history`
//! crate, a memory-forensic SQLite-in-VA carve) agrees on one classification instead of
//! each re-deriving it and risking drift. Pure declarative knowledge; no I/O, no parsing.

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
