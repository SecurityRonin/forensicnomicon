//! Integrity tests over [`TOOL_BEHAVIOURS`], [`ANTI_FORENSIC_METHODS`] and
//! the correlation-hint slice.

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
const EXPECTED_ANTI_FORENSIC_METHOD_LEN: usize = 1;

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
    for id in ["ext4_utimensat_timestomp"] {
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
