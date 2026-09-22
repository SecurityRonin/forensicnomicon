//! Integrity tests over [`TOOL_BEHAVIOURS`], [`ANTI_FORENSIC_METHODS`],
//! [`INVESTIGATIVE_TECHNIQUES`] and the correlation-hint slice.

use super::*;

/// The exact number of registered tool behaviours — the single place the
/// count is written down. Adding an entry updates this constant and nothing
/// else; every other test asserts presence or invariants, not size.
const EXPECTED_TOOL_BEHAVIOUR_LEN: usize = 6;

#[test]
fn no_duplicate_ids() {
    let mut seen = std::collections::HashSet::new();
    for b in TOOL_BEHAVIOURS {
        assert!(seen.insert(b.id), "duplicate tool behaviour id: {}", b.id);
    }
}

#[test]
fn len_matches_expected() {
    assert_eq!(TOOL_BEHAVIOURS.len(), EXPECTED_TOOL_BEHAVIOUR_LEN);
}

/// The memory-forensics absorption batch: the first entries the type ever
/// held, and therefore the pattern every later batch follows.
#[test]
fn memory_forensics_batch_is_present() {
    for id in [
        "vol2_netscan_silent_gaps",
        "vol3_vmware_vmem_missing_metadata",
        "vol3_hollowprocesses_heuristic_coverage",
        "vol3_dumpfiles_zero_fill",
        "memprocfs_findevil_elastic_gate",
        "vol3_malfind_fp_profile",
    ] {
        assert!(
            TOOL_BEHAVIOURS.iter().any(|b| b.id == id),
            "missing tool behaviour: {id}"
        );
    }
}

/// Every entry must be independently verifiable: the load-bearing prose
/// fields are non-empty and every source is a resolvable HTTPS reference.
#[test]
fn every_entry_is_verifiable() {
    for b in TOOL_BEHAVIOURS {
        assert!(!b.tool.is_empty(), "{}: empty tool", b.id);
        assert!(!b.detail.is_empty(), "{}: empty detail", b.id);
        assert!(!b.consequence.is_empty(), "{}: empty consequence", b.id);
        assert!(!b.mitigation.is_empty(), "{}: empty mitigation", b.id);
        assert!(!b.sources.is_empty(), "{}: no sources", b.id);
        for s in b.sources {
            assert!(
                s.starts_with("https://"),
                "{}: source is not an https URL: {s}",
                b.id
            );
        }
    }
}

/// Behaviour changes between releases; an undated claim rots. Every entry in
/// this catalog records the version range it was verified against.
#[test]
fn every_entry_records_a_version() {
    for b in TOOL_BEHAVIOURS {
        assert!(
            b.version_range.is_some(),
            "{}: no version range recorded",
            b.id
        );
    }
}

// ── Anti-forensic methods ────────────────────────────────────────────────────

/// The exact number of registered anti-forensic methods — the single place
/// the count is written down, mirroring [`EXPECTED_TOOL_BEHAVIOUR_LEN`].
const EXPECTED_ANTI_FORENSIC_METHOD_LEN: usize = 2;

#[test]
fn anti_forensic_len_matches_expected() {
    assert_eq!(
        ANTI_FORENSIC_METHODS.len(),
        EXPECTED_ANTI_FORENSIC_METHOD_LEN
    );
}

#[test]
fn anti_forensic_no_duplicate_ids() {
    let mut seen = std::collections::HashSet::new();
    for m in ANTI_FORENSIC_METHODS {
        assert!(seen.insert(m.id), "duplicate anti-forensic id: {}", m.id);
    }
}

/// The filesystem-timestamp absorption batch: every id absorbed so far.
#[test]
fn timestamp_forgery_batch_is_present() {
    for id in ["ext4_utimensat_timestomp", "ntfs_si_only_timestomp"] {
        assert!(
            ANTI_FORENSIC_METHODS.iter().any(|m| m.id == id),
            "missing anti-forensic method: {id}"
        );
    }
}

/// Every entry must be independently verifiable, and must carry its residue
/// story: `residue` non-empty (or the emptiness deliberate — none absorbed so
/// far are), `detection` non-empty, every source a resolvable HTTPS reference.
#[test]
fn every_anti_forensic_entry_is_verifiable() {
    for m in ANTI_FORENSIC_METHODS {
        assert!(!m.name.is_empty(), "{}: empty name", m.id);
        assert!(!m.method.is_empty(), "{}: empty method", m.id);
        assert!(!m.residue.is_empty(), "{}: empty residue", m.id);
        assert!(!m.detection.is_empty(), "{}: empty detection", m.id);
        assert!(!m.sources.is_empty(), "{}: no sources", m.id);
        for s in m.sources {
            assert!(
                s.starts_with("https://"),
                "{}: source is not an https URL: {s}",
                m.id
            );
        }
    }
}

// ── Correlation hints ────────────────────────────────────────────────────────

/// The exact number of registered correlation hints — the single place the
/// count is written down, mirroring [`EXPECTED_TOOL_BEHAVIOUR_LEN`].
const EXPECTED_CORRELATION_HINT_LEN: usize = 2;

#[test]
fn correlation_len_matches_expected() {
    assert_eq!(CORRELATION_HINTS.len(), EXPECTED_CORRELATION_HINT_LEN);
}

#[test]
fn correlation_no_duplicate_ids() {
    let mut seen = std::collections::HashSet::new();
    for h in CORRELATION_HINTS {
        assert!(seen.insert(h.id), "duplicate correlation hint id: {}", h.id);
    }
}

/// The volume-provenance absorption batch: every id absorbed so far.
#[test]
fn volume_provenance_batch_is_present() {
    for id in [
        "lnk_tracker_droid_volume_match",
        "prefetch_volume_serial_boot_sector",
    ] {
        assert!(
            CORRELATION_HINTS.iter().any(|h| h.id == id),
            "missing correlation hint: {id}"
        );
    }
}

/// A correlation is a join between at least two artifacts, both sides
/// resolvable in the catalog; and both directions — agreement and
/// divergence — must be stated, since the divergence side is usually the
/// reason the pair is worth pairing.
#[test]
fn every_correlation_entry_is_verifiable() {
    let catalog_has = |id: &str| crate::catalog::CATALOG.by_id(id).is_some();
    for h in CORRELATION_HINTS {
        assert!(!h.name.is_empty(), "{}: empty name", h.id);
        assert!(h.artifacts.len() >= 2, "{}: fewer than two artifacts", h.id);
        for a in h.artifacts {
            assert!(catalog_has(a), "{}: artifact id not in catalog: {a}", h.id);
        }
        assert!(!h.agreement_means.is_empty(), "{}: empty agreement", h.id);
        assert!(!h.divergence_means.is_empty(), "{}: empty divergence", h.id);
        assert!(!h.sources.is_empty(), "{}: no sources", h.id);
        for s in h.sources {
            assert!(
                s.starts_with("https://"),
                "{}: source is not an https URL: {s}",
                h.id
            );
        }
    }
}

// ── Investigative techniques ─────────────────────────────────────────────────

/// The exact number of registered investigative techniques — the single place
/// the count is written down, mirroring [`EXPECTED_TOOL_BEHAVIOUR_LEN`].
const EXPECTED_INVESTIGATIVE_TECHNIQUE_LEN: usize = 2;

#[test]
fn investigative_len_matches_expected() {
    assert_eq!(
        INVESTIGATIVE_TECHNIQUES.len(),
        EXPECTED_INVESTIGATIVE_TECHNIQUE_LEN
    );
}

#[test]
fn investigative_no_duplicate_ids() {
    let mut seen = std::collections::HashSet::new();
    for t in INVESTIGATIVE_TECHNIQUES {
        assert!(
            seen.insert(t.id),
            "duplicate investigative technique id: {}",
            t.id
        );
    }
}

/// The analytic-frameworks absorption batch: every id absorbed so far.
#[test]
fn analytic_frameworks_batch_is_present() {
    for id in [
        "pyramid_of_pain_indicator_prioritisation",
        "diamond_model_intrusion_analysis",
    ] {
        assert!(
            INVESTIGATIVE_TECHNIQUES.iter().any(|t| t.id == id),
            "missing investigative technique: {id}"
        );
    }
}

/// Every entry must be independently verifiable, and must carry its
/// mislead story: `steps` non-empty and 1-based-ordered, `failure_modes`
/// non-empty (a technique with no recorded way to yield a confident wrong
/// answer has not been researched, only transcribed), every source a
/// resolvable HTTPS reference, and any artifact id resolvable in the catalog.
#[test]
fn every_investigative_entry_is_verifiable() {
    let catalog_has = |id: &str| crate::catalog::CATALOG.by_id(id).is_some();
    for t in INVESTIGATIVE_TECHNIQUES {
        assert!(!t.name.is_empty(), "{}: empty name", t.id);
        assert!(!t.question.is_empty(), "{}: empty question", t.id);
        assert!(!t.steps.is_empty(), "{}: no steps", t.id);
        for (i, s) in t.steps.iter().enumerate() {
            assert_eq!(
                usize::from(s.order),
                i + 1,
                "{}: step order not sequential from 1",
                t.id
            );
            assert!(
                !s.action.is_empty(),
                "{}: step {} empty action",
                t.id,
                s.order
            );
            assert!(
                !s.yields.is_empty(),
                "{}: step {} empty yields",
                t.id,
                s.order
            );
            if let Some(a) = s.artifact_id {
                assert!(
                    catalog_has(a),
                    "{}: step artifact not in catalog: {a}",
                    t.id
                );
            }
        }
        for a in t.artifacts_used {
            assert!(catalog_has(a), "{}: artifact id not in catalog: {a}", t.id);
        }
        assert!(!t.failure_modes.is_empty(), "{}: no failure modes", t.id);
        assert!(!t.sources.is_empty(), "{}: no sources", t.id);
        for s in t.sources {
            assert!(
                s.starts_with("https://"),
                "{}: source is not an https URL: {s}",
                t.id
            );
        }
    }
}

// ── Tool behaviours ──────────────────────────────────────────────────────────

/// A tool that under-reports and a tool that over-reports mislead in opposite
/// directions; the `kind` field must keep them distinguishable. malfind is a
/// false-positive profile, netscan a silent-incompleteness profile.
#[test]
fn kind_distinguishes_fp_profile_from_silent_incompleteness() {
    let by_id = |id: &str| {
        TOOL_BEHAVIOURS
            .iter()
            .find(|b| b.id == id)
            .unwrap_or_else(|| panic!("missing tool behaviour: {id}"))
    };
    assert_eq!(
        by_id("vol3_malfind_fp_profile").kind,
        ToolBehaviourKind::FalsePositiveProne
    );
    assert_eq!(
        by_id("vol2_netscan_silent_gaps").kind,
        ToolBehaviourKind::SilentlyIncomplete
    );
}
