//! Integrity tests over [`TOOL_BEHAVIOURS`].

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
