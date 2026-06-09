//! `[H]` State-History layer — zero-dep KNOWLEDGE-tier types and traits.
//!
//! `[H]` is a cross-cutting functor that lifts each base navigation primitive to a
//! time-indexed variant:
//!
//! - `[P^H]` — time-indexed disk (VSS, APFS snapshots, Time Machine, btrfs)
//! - `[M^H]` — time-indexed memory (hiberfil chain, VMware memory snapshots)
//! - `[L^H]` — time-indexed log (rotated logs, journald sealed epochs)
//! - `[Q^H]` — time-indexed live query (point-in-time osquery exports)
//! - `[C^H] ≅ [C]` — Git already encodes its own history; `[H]` on `[C]` is the identity functor.
//!
//! This module contains only type definitions and trait signatures. No parsing algorithms,
//! no file I/O, no binary deserialization. Concrete `[H]` crates (vss-history,
//! wal-history, git-history, …) implement [`source::HistoricalSource`] and depend on this.
//!
//! Distinct from [`crate::temporal`] (correlation hints for timeline/timestomp detection);
//! `history` is the state-history vocabulary, not a correlation engine.

pub mod clock;
pub mod cohort;
pub mod epoch;
pub mod identity;
pub mod source;

#[cfg(test)]
mod api_shape_tests {
    use crate::history::{
        clock::{AuthMechanism, ClockProvenance, ClockSource, TamperResistance, TrustGrade},
        cohort::{TemporalCohort, TemporalState},
        epoch::{CohortTopology, EpochTag, LsnKind, MaterializationSafety, PruneTrigger},
        identity::{ArtifactRef, CohortKey, HashAlgo, IdentityClaim, IdentityDiscipline},
    };

    // ── identity ────────────────────────────────────────────────────────────────

    #[test]
    fn epoch_tag_is_32_bytes() {
        let tag = EpochTag([0u8; 32]);
        assert_eq!(tag.0.len(), 32);
    }

    #[test]
    fn artifact_ref_content_hash_claim() {
        let ar = ArtifactRef {
            claims: vec![IdentityClaim::ContentHash {
                algo: HashAlgo::Sha256,
                digest: vec![0u8; 32],
            }],
        };
        assert_eq!(ar.claims.len(), 1);
    }

    #[test]
    fn artifact_ref_canonical_path_claim() {
        use std::path::PathBuf;
        let ar = ArtifactRef {
            claims: vec![IdentityClaim::CanonicalPath {
                volume: "C:".into(),
                path: PathBuf::from("Windows/System32/ntoskrnl.exe"),
            }],
        };
        assert_eq!(ar.claims.len(), 1);
    }

    #[test]
    fn identity_discipline_all_variants_exist() {
        let _: [IdentityDiscipline; 5] = [
            IdentityDiscipline::PathStable,
            IdentityDiscipline::ContentStable,
            IdentityDiscipline::ObjectStable,
            IdentityDiscipline::RecordStable,
            IdentityDiscipline::LogicalStable,
        ];
    }

    #[test]
    fn cohort_key_is_opaque_bytes() {
        let key = CohortKey::new([0u8; 32]);
        assert_eq!(key.as_bytes().len(), 32);
    }

    // ── clock ───────────────────────────────────────────────────────────────────

    #[test]
    fn trust_grade_all_variants_exist() {
        let _: [TrustGrade; 8] = [
            TrustGrade::ExternallyAttested,
            TrustGrade::LocallyAttested,
            TrustGrade::CustodialThirdParty,
            TrustGrade::LocalSubsystem,
            TrustGrade::LocalApplication,
            TrustGrade::OrderingOnly,
            TrustGrade::Reconstructed,
            TrustGrade::Unknown,
        ];
    }

    #[test]
    fn tamper_resistance_all_variants_exist() {
        let _: [TamperResistance; 6] = [
            TamperResistance::AppendOnlyAttested,
            TamperResistance::AppendOnlyLocal,
            TamperResistance::SignedImmutable,
            TamperResistance::AdminWritable,
            TamperResistance::UserWritable,
            TamperResistance::Trivial,
        ];
    }

    #[test]
    fn clock_provenance_minimal_construction() {
        let cp = ClockProvenance {
            source: ClockSource::FileMetadata,
            trust_grade: TrustGrade::LocalSubsystem,
            tamper_resistance: TamperResistance::AdminWritable,
            ordering_only: false,
            skew_known: None,
            authenticated: None,
        };
        assert!(!cp.ordering_only);
    }

    #[test]
    fn clock_provenance_with_auth_mechanism() {
        let cp = ClockProvenance {
            source: ClockSource::TransparencyLog,
            trust_grade: TrustGrade::ExternallyAttested,
            tamper_resistance: TamperResistance::AppendOnlyAttested,
            ordering_only: false,
            skew_known: Some(std::time::Duration::from_secs(0)),
            authenticated: Some(AuthMechanism::Rfc3161),
        };
        assert!(matches!(cp.authenticated, Some(AuthMechanism::Rfc3161)));
    }

    // ── epoch ───────────────────────────────────────────────────────────────────

    #[test]
    fn lsn_kind_sqlite_wal_frame() {
        let lsn = LsnKind::SqliteWalFrame {
            frame_seq: 7,
            commit_seq: 3,
        };
        match lsn {
            LsnKind::SqliteWalFrame {
                frame_seq,
                commit_seq,
            } => {
                assert_eq!(frame_seq, 7);
                assert_eq!(commit_seq, 3);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn lsn_kind_vss_shadow_set_id() {
        let lsn = LsnKind::VssShadowSetId([0u8; 16]);
        assert!(matches!(lsn, LsnKind::VssShadowSetId(_)));
    }

    #[test]
    fn cohort_topology_discrete_set() {
        let topo = CohortTopology::DiscreteSet;
        assert!(matches!(topo, CohortTopology::DiscreteSet));
    }

    #[test]
    fn cohort_topology_linear_journal() {
        let topo = CohortTopology::LinearJournal {
            lsn_type: LsnKind::EseLsn(42),
        };
        assert!(matches!(topo, CohortTopology::LinearJournal { .. }));
    }

    #[test]
    fn materialization_safety_all_variants_exist() {
        let _ = MaterializationSafety::ReadOnlySafe;
        let _ = MaterializationSafety::ReadOnlyRequiresCareful;
        let _ = MaterializationSafety::Destructive;
        let _ = MaterializationSafety::EphemeralOnce;
        let _ = MaterializationSafety::AutoPruned {
            trigger: PruneTrigger::LogRotation,
        };
    }

    // ── cohort ──────────────────────────────────────────────────────────────────

    #[test]
    fn temporal_cohort_generic_over_handle() {
        let cohort: TemporalCohort<()> = TemporalCohort {
            artifact: ArtifactRef { claims: vec![] },
            discipline: IdentityDiscipline::PathStable,
            topology: CohortTopology::DiscreteSet,
            states: vec![],
        };
        assert!(cohort.states.is_empty());
    }

    #[test]
    fn temporal_state_carries_concrete_handle() {
        let state: TemporalState<u64> = TemporalState {
            epoch: EpochTag([1u8; 32]),
            ordering_key: Some(LsnKind::EseLsn(100)),
            wall_time: None,
            clock: ClockProvenance {
                source: ClockSource::Unknown,
                trust_grade: TrustGrade::Unknown,
                tamper_resistance: TamperResistance::UserWritable,
                ordering_only: true,
                skew_known: None,
                authenticated: None,
            },
            safety: MaterializationSafety::ReadOnlyRequiresCareful,
            handle: 0xDEAD_BEEF,
        };
        assert_eq!(state.handle, 0xDEAD_BEEF);
        assert!(state.clock.ordering_only);
    }

    #[test]
    fn temporal_cohort_with_path_stable_states() {
        use std::path::PathBuf;
        let states: Vec<TemporalState<PathBuf>> = vec![TemporalState {
            epoch: EpochTag([0u8; 32]),
            ordering_key: None,
            wall_time: None,
            clock: ClockProvenance {
                source: ClockSource::FileMetadata,
                trust_grade: TrustGrade::LocalSubsystem,
                tamper_resistance: TamperResistance::AdminWritable,
                ordering_only: false,
                skew_known: None,
                authenticated: None,
            },
            safety: MaterializationSafety::ReadOnlySafe,
            handle: PathBuf::from("/mnt/shadow/HarddiskVolumeShadowCopy1"),
        }];
        let cohort: TemporalCohort<PathBuf> = TemporalCohort {
            artifact: ArtifactRef {
                claims: vec![IdentityClaim::CanonicalPath {
                    volume: "C:".into(),
                    path: PathBuf::from("Windows/System32/ntoskrnl.exe"),
                }],
            },
            discipline: IdentityDiscipline::PathStable,
            topology: CohortTopology::DiscreteSet,
            states,
        };
        assert_eq!(cohort.states.len(), 1);
    }
}
