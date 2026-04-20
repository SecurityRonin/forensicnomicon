/// How two artifacts' timestamps relate temporally for correlation.
///
/// Sources:
/// - Harlan Carvey — "Windows Forensic Analysis Toolkit" (4th ed.), chapters on
///   timeline analysis and timestamp correlation across artifact types.
/// - SANS FOR508 — "Advanced Incident Response, Threat Hunting, and Digital
///   Forensics", timeline analysis methodology:
///   <https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/>
/// - Mari DeGrazia — "Using Prefetch to its Fullest" (2016), Prefetch timestamp
///   correlation with $MFT and event logs:
///   <https://www.magnetforensics.com/blog/using-prefetch-to-its-fullest/>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum TemporalRelation {
    /// Artifact A timestamp should precede artifact B timestamp.
    Precedes,
    /// Both artifacts should share approximately the same timestamp.
    Concurrent,
    /// Artifact A timestamp should follow artifact B timestamp.
    Follows,
    /// Timestamps can be compared to detect manipulation.
    ManipulationDetectable,
}

/// A temporal correlation hint between two catalog artifacts.
///
/// Each hint encodes a forensically meaningful relationship between timestamps
/// from two distinct artifacts. Analysts use these to detect timestomping,
/// log clearing, or staged artifact creation.
///
/// Sources:
/// - Brian Carrier — "File System Forensic Analysis" (2005), timestamp semantics
///   across NTFS metadata attributes ($STANDARD_INFORMATION vs $FILE_NAME).
/// - Alexis Brignoni — "APOLLO: Apple Pattern of Life Lazy Output'er", temporal
///   correlation methodology adapted for Windows artifact sets:
///   <https://github.com/mac4n6/APOLLO>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TemporalHint {
    /// Primary artifact ID (must exist in [`crate::catalog::CATALOG`]).
    pub artifact_id: &'static str,
    /// Artifact ID to correlate with (must exist in [`crate::catalog::CATALOG`]).
    pub correlates_with: &'static str,
    /// Temporal relationship between them.
    pub relation: TemporalRelation,
    /// Analyst guidance for this correlation.
    pub hint: &'static str,
}

/// All known temporal correlation hints between catalog artifacts.
///
/// Entries are symmetric in interpretation: [`temporal_hints_for`] returns a hint
/// when either `artifact_id` or `correlates_with` matches the queried ID.
///
/// Sources:
/// - MITRE ATT&CK T1070.006 — Indicator Removal: Timestomp:
///   <https://attack.mitre.org/techniques/T1070/006/>
/// - Mandiant — "Timestomping: How Attackers Manipulate File Timestamps" (2013),
///   describes $STANDARD_INFORMATION vs $FILE_NAME divergence as detection signal.
/// - Eric Zimmerman — "Prefetch" tool and documentation, first-run vs last-run
///   timestamp semantics:
///   <https://ericzimmerman.github.io/#!index.md>
/// - SANS — "FOR408: Windows Forensic Analysis", Amcache vs Prefetch correlation
///   for detecting pre-compiled binaries:
///   <https://www.sans.org/cyber-security-courses/windows-forensic-analysis/>
pub static TEMPORAL_TABLE: &[TemporalHint] = &[
    TemporalHint {
        artifact_id: "prefetch_dir",
        correlates_with: "mft_file",
        relation: TemporalRelation::ManipulationDetectable,
        hint: "Compare $MFT timestamps of .pf files with Prefetch LastRun time; \
               discrepancy indicates timestomping",
    },
    TemporalHint {
        artifact_id: "prefetch_dir",
        correlates_with: "evtx_security",
        relation: TemporalRelation::Follows,
        hint: "Process creation event 4688 should precede or match first Prefetch run time",
    },
    TemporalHint {
        artifact_id: "userassist_exe",
        correlates_with: "lnk_files",
        relation: TemporalRelation::Concurrent,
        hint: "UserAssist entry and LNK file timestamps should be close; \
               divergence suggests manual artifact creation",
    },
    TemporalHint {
        artifact_id: "lnk_files",
        correlates_with: "jump_list_auto",
        relation: TemporalRelation::Concurrent,
        hint: "LNK timestamps and Jump List entries for same app should align within seconds",
    },
    TemporalHint {
        artifact_id: "amcache_app_file",
        correlates_with: "prefetch_dir",
        relation: TemporalRelation::ManipulationDetectable,
        hint: "Amcache compile time vs Prefetch first run; large gaps may indicate \
               pre-compiled binaries dropped without execution",
    },
    TemporalHint {
        artifact_id: "mft_file",
        correlates_with: "prefetch_dir",
        relation: TemporalRelation::ManipulationDetectable,
        hint: "Compare $MFT $SI timestamps of .pf files with Prefetch LastRun time; \
               divergence between $SI and $FN attributes indicates timestomping",
    },
    TemporalHint {
        artifact_id: "mft_file",
        correlates_with: "shimcache",
        relation: TemporalRelation::ManipulationDetectable,
        hint: "shimcache last modified vs $MFT $SI timestamps; compare for anti-forensics",
    },
    TemporalHint {
        artifact_id: "evtx_security",
        correlates_with: "evtx_system",
        relation: TemporalRelation::Concurrent,
        hint: "Security and System log timestamps should align; gaps indicate log clearing",
    },
    TemporalHint {
        artifact_id: "ntds_dit",
        correlates_with: "evtx_security",
        relation: TemporalRelation::Follows,
        hint: "NTDS password changes should correlate with 4723/4724 events",
    },
    TemporalHint {
        artifact_id: "bam_user",
        correlates_with: "prefetch_dir",
        relation: TemporalRelation::ManipulationDetectable,
        hint: "BAM last run vs Prefetch last run; discrepancy detects Prefetch manipulation",
    },
    TemporalHint {
        artifact_id: "scheduled_tasks_dir",
        correlates_with: "evtx_security",
        relation: TemporalRelation::Follows,
        hint: "Task creation (4698) should precede task XML on disk",
    },
];

/// Return all temporal hints where `artifact_id` matches either side of the hint.
///
/// Matches on both `artifact_id` and `correlates_with` so a single lookup
/// surfaces all known correlations for an artifact regardless of which side
/// it appears on in the table.
pub fn temporal_hints_for(artifact_id: &str) -> Vec<&'static TemporalHint> {
    TEMPORAL_TABLE
        .iter()
        .filter(|h| h.artifact_id == artifact_id || h.correlates_with == artifact_id)
        .collect()
}

/// Return all `(artifact_id, correlates_with)` pairs from the table.
pub fn correlation_pairs() -> Vec<(&'static str, &'static str)> {
    TEMPORAL_TABLE
        .iter()
        .map(|h| (h.artifact_id, h.correlates_with))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_nonempty() {
        assert!(!TEMPORAL_TABLE.is_empty());
    }

    #[test]
    fn prefetch_has_temporal_hints() {
        let hints = temporal_hints_for("prefetch_dir");
        assert!(
            !hints.is_empty(),
            "prefetch should have temporal correlation hints"
        );
    }

    #[test]
    fn mft_correlates_with_prefetch() {
        let hints = temporal_hints_for("mft_file");
        assert!(
            hints.iter().any(|h| h.correlates_with == "prefetch_dir"),
            "MFT should correlate with prefetch"
        );
    }

    #[test]
    fn unknown_returns_empty() {
        assert!(temporal_hints_for("nonexistent").is_empty());
    }

    #[test]
    fn correlation_pairs_nonempty() {
        let pairs = correlation_pairs();
        assert!(pairs.len() >= 5);
    }

    #[test]
    fn all_artifact_ids_valid() {
        use crate::catalog::CATALOG;
        let ids: std::collections::HashSet<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for hint in TEMPORAL_TABLE {
            assert!(
                ids.contains(hint.artifact_id),
                "Unknown artifact_id: {}",
                hint.artifact_id
            );
            assert!(
                ids.contains(hint.correlates_with),
                "Unknown correlates_with: {}",
                hint.correlates_with
            );
        }
    }
}
