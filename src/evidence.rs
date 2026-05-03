//! Evidence strength / confidence model for forensic artifacts.
//!
//! Maps each catalog artifact to an [`EvidenceStrength`] rating and known
//! interpretation caveats, helping analysts assess the weight of evidence
//! and communicate findings in reports.
//!
//! The authoritative data now lives in [`crate::profile::ARTIFACT_PROFILES`].
//! [`evidence_for`] and [`artifacts_with_strength`] delegate to that table.

/// How strongly an artifact proves a fact in isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EvidenceStrength {
    /// Known false-positive generator; use only with strong corroboration.
    Unreliable = 0,
    /// Suggestive but easily explained by benign activity.
    Circumstantial = 1,
    /// Useful with other evidence; not standalone proof.
    Corroborative = 2,
    /// Strong evidence; edge-case alternative explanations exist.
    Strong = 3,
    /// Definitive proof of the claimed activity (e.g., Prefetch = execution occurred).
    Definitive = 4,
}

/// Returns the profile for a given artifact ID, or `None` if unknown.
///
/// Delegates entirely to [`crate::profile::profile_for`].
pub fn evidence_for(artifact_id: &str) -> Option<&'static crate::profile::ArtifactProfile> {
    crate::profile::profile_for(artifact_id)
}

/// Returns all artifact profiles at or above the given strength threshold.
pub fn artifacts_with_strength(
    min_strength: EvidenceStrength,
) -> Vec<&'static crate::profile::ArtifactProfile> {
    crate::profile::ARTIFACT_PROFILES
        .iter()
        .filter(|p| p.evidence_strength >= min_strength)
        .collect()
}

#[cfg(test)]
mod delegation_tests {
    use super::*;

    #[test]
    fn evidence_table_is_removed() {
        // EVIDENCE_TABLE should not exist — use profile_for() instead
        // This test passes when EVIDENCE_TABLE is gone and evidence_for delegates to profile
        let p = crate::profile::profile_for("prefetch_file")
            .expect("prefetch_file must have a profile");
        assert_eq!(p.evidence_strength, EvidenceStrength::Definitive);
    }

    #[test]
    fn evidence_for_delegates_to_profile() {
        // evidence_for should return ArtifactProfile, not EvidenceEntry
        // This test will fail until evidence_for() return type changes
        let result: Option<&crate::profile::ArtifactProfile> = evidence_for("shimcache");
        assert!(result.is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{TriagePriority, CATALOG};

    #[test]
    fn prefetch_is_definitive() {
        let e = evidence_for("prefetch_file").expect("prefetch_file must be in table");
        assert_eq!(e.evidence_strength, EvidenceStrength::Definitive);
    }

    #[test]
    fn bash_history_is_circumstantial() {
        let e = evidence_for("linux_bash_history").expect("linux_bash_history must be in table");
        assert_eq!(e.evidence_strength, EvidenceStrength::Circumstantial);
    }

    #[test]
    fn definitive_entries_have_caveats() {
        // Even definitive evidence should document its limitations
        for entry in crate::profile::ARTIFACT_PROFILES {
            if entry.evidence_strength == EvidenceStrength::Definitive {
                assert!(
                    !entry.evidence_caveats.is_empty(),
                    "{} is Definitive but has no caveats documented",
                    entry.id
                );
            }
        }
    }

    #[test]
    fn strength_ordering_is_consistent() {
        assert!(EvidenceStrength::Definitive > EvidenceStrength::Strong);
        assert!(EvidenceStrength::Strong > EvidenceStrength::Corroborative);
        assert!(EvidenceStrength::Corroborative > EvidenceStrength::Circumstantial);
        assert!(EvidenceStrength::Circumstantial > EvidenceStrength::Unreliable);
    }

    #[test]
    fn filter_by_strength_returns_subset() {
        let definitive = artifacts_with_strength(EvidenceStrength::Definitive);
        let all = artifacts_with_strength(EvidenceStrength::Unreliable);
        assert!(definitive.len() < all.len());
        assert!(definitive
            .iter()
            .all(|e| e.evidence_strength == EvidenceStrength::Definitive));
    }

    #[test]
    fn unknown_artifact_returns_none() {
        assert!(evidence_for("this_does_not_exist").is_none());
    }

    #[test]
    fn all_table_ids_exist_in_catalog() {
        let catalog_ids: std::collections::HashSet<&str> =
            CATALOG.list().iter().map(|d| d.id).collect();
        for entry in crate::profile::ARTIFACT_PROFILES {
            assert!(
                catalog_ids.contains(entry.id),
                "profile table references unknown catalog id: {}",
                entry.id
            );
        }
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

#[cfg(test)]
mod profile_tests {
    #[test]
    fn profile_for_mft_has_both_dimensions() {
        // profile_for doesn't exist yet — this test should fail to compile
        let p = crate::profile::profile_for("mft").expect("mft must have a profile");
        assert_eq!(p.evidence_strength, crate::evidence::EvidenceStrength::Definitive);
        assert_eq!(p.volatility, crate::volatility::VolatilityClass::Persistent);
        assert!(!p.evidence_caveats.is_empty());
        assert!(!p.volatility_rationale.is_empty());
    }

    #[test]
    fn profile_for_missing_returns_none() {
        assert!(crate::profile::profile_for("this_does_not_exist").is_none());
    }

    #[test]
    fn profiles_table_has_no_duplicate_ids() {
        let mut seen = std::collections::HashSet::new();
        for p in crate::profile::ARTIFACT_PROFILES {
            assert!(seen.insert(p.id), "duplicate profile id: {}", p.id);
        }
    }
}
