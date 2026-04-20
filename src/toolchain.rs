//! KAPE / Velociraptor / toolchain mapping.
//!
//! Maps catalog artifacts to KAPE target names, KAPE module names,
//! and Velociraptor artifact names, enabling programmatic collection
//! config generation.

/// Toolchain mapping for one catalog artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct KapeMapping {
    /// Catalog artifact ID.
    pub artifact_id: &'static str,
    /// KAPE target names that collect this artifact.
    pub kape_targets: &'static [&'static str],
    /// KAPE module names that process this artifact.
    pub kape_modules: &'static [&'static str],
    /// Velociraptor artifact names equivalent to this artifact.
    pub velociraptor_artifacts: &'static [&'static str],
}

pub static KAPE_MAPPINGS: &[KapeMapping] = &[];

/// Returns the KAPE mapping for a given artifact ID.
pub fn kape_mapping_for(_artifact_id: &str) -> Option<&'static KapeMapping> {
    todo!("implement kape_mapping_for")
}

/// Returns all unique KAPE target names needed to collect the given artifact IDs.
pub fn kape_target_set(_artifact_ids: &[&str]) -> Vec<&'static str> {
    todo!("implement kape_target_set")
}

/// Returns all unique Velociraptor artifact names for the given artifact IDs.
pub fn velociraptor_artifact_set(_artifact_ids: &[&str]) -> Vec<&'static str> {
    todo!("implement velociraptor_artifact_set")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CATALOG;

    #[test]
    fn prefetch_has_kape_mapping() {
        let m = kape_mapping_for("prefetch_file").expect("prefetch_file must have mapping");
        assert!(!m.kape_targets.is_empty());
        assert!(!m.velociraptor_artifacts.is_empty());
    }

    #[test]
    fn evtx_security_has_velociraptor_artifact() {
        let m = kape_mapping_for("evtx_security").expect("evtx_security must have mapping");
        assert!(m
            .velociraptor_artifacts
            .iter()
            .any(|a| a.contains("EventLog")));
    }

    #[test]
    fn kape_target_set_deduplicates() {
        let targets = kape_target_set(&["evtx_security", "evtx_system", "evtx_sysmon"]);
        let unique: std::collections::HashSet<_> = targets.iter().collect();
        assert_eq!(
            targets.len(),
            unique.len(),
            "kape_target_set should deduplicate"
        );
    }

    #[test]
    fn velociraptor_artifact_set_deduplicates() {
        let arts = velociraptor_artifact_set(&["evtx_security", "evtx_system"]);
        let unique: std::collections::HashSet<_> = arts.iter().collect();
        assert_eq!(arts.len(), unique.len());
    }

    #[test]
    fn unknown_artifact_returns_none() {
        assert!(kape_mapping_for("nonexistent").is_none());
    }

    #[test]
    fn all_table_ids_exist_in_catalog() {
        for mapping in KAPE_MAPPINGS {
            assert!(
                CATALOG.by_id(mapping.artifact_id).is_some(),
                "kape table references unknown artifact: {}",
                mapping.artifact_id
            );
        }
    }

    #[test]
    fn linux_artifacts_have_velociraptor_mappings() {
        let linux_with_velociraptor = KAPE_MAPPINGS
            .iter()
            .filter(|m| m.artifact_id.starts_with("linux_"))
            .filter(|m| !m.velociraptor_artifacts.is_empty())
            .count();
        assert!(
            linux_with_velociraptor >= 2,
            "Linux artifacts should have Velociraptor mappings"
        );
    }
}
