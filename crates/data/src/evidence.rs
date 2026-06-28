//! Evidence strength helpers over the assembled global catalog.
//!
//! The [`EvidenceStrength`] rating type is defined in `forensicnomicon-core` and
//! re-exported here (so `crate::evidence::EvidenceStrength` resolves throughout the
//! descriptor dataset). The point-lookup and bulk-query helpers below resolve
//! against the global [`crate::catalog::CATALOG`].
//!
//! Use [`evidence_for`] for point-lookups, [`artifacts_with_strength`] for bulk
//! queries, and [`crate::catalog::CATALOG::unassessed`] to find gaps sorted by
//! triage priority.

pub use forensicnomicon_core::evidence::EvidenceStrength;

/// Returns the descriptor for a given artifact ID if it has been assessed.
///
/// Returns `None` when the artifact ID is unknown or has no evidence assessment yet.
/// On `Some(d)`, callers may access `d.evidence_strength`, `d.evidence_caveats`,
/// `d.volatility`, and `d.volatility_rationale` directly — all are guaranteed `Some`.
pub fn evidence_for(artifact_id: &str) -> Option<&'static crate::catalog::ArtifactDescriptor> {
    crate::catalog::CATALOG
        .by_id(artifact_id)
        .filter(|d| d.evidence_strength.is_some())
}

/// Returns all assessed descriptors with evidence strength at or above `min_strength`.
pub fn artifacts_with_strength(
    min_strength: EvidenceStrength,
) -> Vec<&'static crate::catalog::ArtifactDescriptor> {
    crate::catalog::CATALOG
        .list()
        .iter()
        .filter(|d| d.evidence_strength.is_some_and(|s| s >= min_strength))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{TriagePriority, CATALOG};

    #[test]
    fn evidence_for_returns_descriptor() {
        let result: Option<&crate::catalog::ArtifactDescriptor> = evidence_for("shimcache");
        assert!(result.is_some());
    }

    #[test]
    fn prefetch_is_definitive() {
        let e = evidence_for("prefetch_file").expect("prefetch_file must be assessed");
        assert_eq!(e.evidence_strength, Some(EvidenceStrength::Definitive));
    }

    #[test]
    fn bash_history_is_circumstantial() {
        let e = evidence_for("linux_bash_history").expect("linux_bash_history must be assessed");
        assert_eq!(e.evidence_strength, Some(EvidenceStrength::Circumstantial));
    }

    #[test]
    fn definitive_entries_have_caveats() {
        for d in CATALOG.list() {
            if d.evidence_strength == Some(EvidenceStrength::Definitive) {
                assert!(
                    !d.evidence_caveats.is_empty(),
                    "{} is Definitive but has no caveats documented",
                    d.id
                );
            }
        }
    }

    #[test]
    fn filter_by_strength_returns_subset() {
        let definitive = artifacts_with_strength(EvidenceStrength::Definitive);
        let all = artifacts_with_strength(EvidenceStrength::Unreliable);
        assert!(definitive.len() < all.len());
        assert!(definitive
            .iter()
            .all(|d| d.evidence_strength == Some(EvidenceStrength::Definitive)));
    }

    #[test]
    fn unknown_artifact_returns_none() {
        assert!(evidence_for("this_does_not_exist").is_none());
    }

    #[test]
    fn critical_triage_artifacts_have_evidence_entries() {
        let missing: Vec<&str> = CATALOG
            .for_triage()
            .into_iter()
            .filter(|d| d.triage_priority == TriagePriority::Critical)
            .filter(|d| evidence_for(d.id).is_none())
            .map(|d| d.id)
            .collect();
        assert!(
            missing.is_empty(),
            "Critical-priority artifacts missing from evidence table: {missing:?}"
        );
    }
}
