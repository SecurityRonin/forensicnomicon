//! Anti-forensics awareness layer.
//!
//! Maps each catalog artifact to known anti-forensic techniques that can
//! affect it, along with detection hints. Helps analysts know what has
//! *not* been tampered with and what evidence gaps might be intentional.

/// A specific anti-forensic technique class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AntiForensicTechnique {
    /// NTFS timestamp manipulation ($STANDARD_INFORMATION modified).
    Timestomping,
    /// Event log channel cleared (Security 1102, System 104).
    LogClearing,
    /// File securely overwritten before deletion.
    SecureOverwrite,
    /// Registry key deleted or value removed.
    RegistryDeletion,
    /// Volume Shadow Copies deleted (vssadmin delete shadows).
    ShadowCopyDeletion,
    /// Prefetch disabled via registry to suppress execution traces.
    PrefetchDisable,
    /// History/cache file manually deleted or cleared.
    HistoryClearing,
    /// Artifact encrypted so contents are inaccessible.
    Encryption,
    /// Process list manipulated to hide entries (DKOM).
    ProcessHiding,
    /// Shellbag entries deleted to hide folder browsing.
    ShellbagDeletion,
}

/// One anti-forensic risk for a specific artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AntiForensicRisk {
    pub technique: AntiForensicTechnique,
    /// What the attacker does to suppress this artifact.
    pub attacker_action: &'static str,
    /// What to look for to detect the anti-forensic action itself.
    pub detection_hint: &'static str,
}

/// Anti-forensic risks for one catalog artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ArtifactAntiForensics {
    pub artifact_id: &'static str,
    pub risks: &'static [AntiForensicRisk],
}

/// Full table of artifact anti-forensics risks.
pub static AF_RISKS_TABLE: &[ArtifactAntiForensics] = &[];

/// Return the anti-forensic risks for a catalog artifact by ID.
pub fn anti_forensics_for(artifact_id: &str) -> Option<&'static ArtifactAntiForensics> {
    todo!("not yet implemented: {}", artifact_id)
}

/// Return all artifacts vulnerable to a specific anti-forensic technique.
pub fn artifacts_vulnerable_to(technique: AntiForensicTechnique) -> Vec<&'static ArtifactAntiForensics> {
    todo!("not yet implemented: {:?}", technique)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefetch_has_prefetch_disable_risk() {
        let af = anti_forensics_for("prefetch_file")
            .expect("prefetch_file must be in table");
        assert!(
            af.risks.iter().any(|r| r.technique == AntiForensicTechnique::PrefetchDisable),
            "prefetch_file should list PrefetchDisable as a risk"
        );
    }

    #[test]
    fn evtx_security_has_log_clearing_risk() {
        let af = anti_forensics_for("evtx_security")
            .expect("evtx_security must be in table");
        assert!(
            af.risks.iter().any(|r| r.technique == AntiForensicTechnique::LogClearing),
            "evtx_security should list LogClearing as a risk"
        );
    }

    #[test]
    fn mft_has_timestomping_risk() {
        let af = anti_forensics_for("mft_file")
            .expect("mft_file must be in table");
        assert!(
            af.risks.iter().any(|r| r.technique == AntiForensicTechnique::Timestomping),
            "mft_file should list Timestomping as a risk"
        );
    }

    #[test]
    fn unknown_artifact_returns_none() {
        assert!(anti_forensics_for("nonexistent_artifact_xyz").is_none());
    }

    #[test]
    fn log_clearing_affects_multiple_evtx_artifacts() {
        let vulnerable = artifacts_vulnerable_to(AntiForensicTechnique::LogClearing);
        let evtx_count = vulnerable.iter()
            .filter(|e| e.artifact_id.starts_with("evtx_"))
            .count();
        assert!(evtx_count >= 3, "At least 3 evtx_ artifacts should be vulnerable to LogClearing");
    }

    #[test]
    fn all_risks_have_non_empty_detection_hints() {
        for entry in AF_RISKS_TABLE {
            for risk in entry.risks {
                assert!(
                    !risk.detection_hint.is_empty(),
                    "artifact '{}' has empty detection_hint for {:?}",
                    entry.artifact_id, risk.technique
                );
            }
        }
    }

    #[test]
    fn all_table_ids_exist_in_catalog() {
        use crate::catalog::CATALOG;
        let catalog_ids: std::collections::HashSet<&str> =
            CATALOG.list().iter().map(|d| d.id).collect();
        for entry in AF_RISKS_TABLE {
            assert!(
                catalog_ids.contains(entry.artifact_id),
                "AF table references unknown catalog id: {}", entry.artifact_id
            );
        }
    }
}
