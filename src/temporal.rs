/// How two artifacts' timestamps relate temporally for correlation.
///
/// Sources:
/// - Harlan Carvey — "Windows Forensic Analysis Toolkit" (4th ed.), chapters on
///   timeline analysis and timestamp correlation across artifact types.
/// - SANS FOR508 — "Advanced Incident Response, Threat Hunting, and Digital
///   Forensics", timeline analysis methodology:
///   <https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/>
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
pub static TEMPORAL_TABLE: &[TemporalHint] = &[];

/// Return all temporal hints where `artifact_id` matches either side.
pub fn temporal_hints_for(_artifact_id: &str) -> Vec<&'static TemporalHint> {
    vec![]
}

/// Return all `(artifact_id, correlates_with)` pairs from the table.
pub fn correlation_pairs() -> Vec<(&'static str, &'static str)> {
    vec![]
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
        assert!(!hints.is_empty(), "prefetch should have temporal correlation hints");
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
            assert!(ids.contains(hint.artifact_id), "Unknown artifact_id: {}", hint.artifact_id);
            assert!(
                ids.contains(hint.correlates_with),
                "Unknown correlates_with: {}",
                hint.correlates_with
            );
        }
    }
}
