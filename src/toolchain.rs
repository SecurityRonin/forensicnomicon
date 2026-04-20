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

pub static KAPE_MAPPINGS: &[KapeMapping] = &[
    // ── Execution ──────────────────────────────────────────────────────────────
    KapeMapping {
        artifact_id: "prefetch_dir",
        kape_targets: &["!BasicCollection", "Prefetch"],
        kape_modules: &["PECmd"],
        velociraptor_artifacts: &["Windows.Forensics.Prefetch"],
    },
    KapeMapping {
        artifact_id: "prefetch_file",
        kape_targets: &["!BasicCollection", "Prefetch"],
        kape_modules: &["PECmd"],
        velociraptor_artifacts: &["Windows.Forensics.Prefetch"],
    },
    KapeMapping {
        artifact_id: "amcache_app_file",
        kape_targets: &["Amcache", "!BasicCollection"],
        kape_modules: &["AmcacheParser"],
        velociraptor_artifacts: &["Windows.Forensics.Amcache"],
    },
    KapeMapping {
        artifact_id: "shimcache",
        kape_targets: &["AppCompatCache", "!BasicCollection"],
        kape_modules: &["AppCompatCacheParser"],
        velociraptor_artifacts: &["Windows.Registry.AppCompatCache"],
    },
    KapeMapping {
        artifact_id: "userassist_exe",
        kape_targets: &["!BasicCollection", "RegistryHives"],
        kape_modules: &["RECmd"],
        velociraptor_artifacts: &["Windows.Registry.UserAssist"],
    },
    KapeMapping {
        artifact_id: "userassist_folder",
        kape_targets: &["!BasicCollection", "RegistryHives"],
        kape_modules: &["RECmd"],
        velociraptor_artifacts: &["Windows.Registry.UserAssist"],
    },
    KapeMapping {
        artifact_id: "bam_user",
        kape_targets: &["BAM_DAM", "!BasicCollection"],
        kape_modules: &["RECmd"],
        velociraptor_artifacts: &["Windows.Registry.BAM"],
    },
    // ── File System / MFT ──────────────────────────────────────────────────────
    KapeMapping {
        artifact_id: "mft_file",
        kape_targets: &["$MFT", "!BasicCollection"],
        kape_modules: &["MFTECmd"],
        velociraptor_artifacts: &["Windows.NTFS.MFT"],
    },
    // ── LNK / Jump Lists ──────────────────────────────────────────────────────
    KapeMapping {
        artifact_id: "lnk_files",
        kape_targets: &["LNKFilesAndJumpLists", "!BasicCollection"],
        kape_modules: &["LECmd"],
        velociraptor_artifacts: &["Windows.Forensics.Lnk"],
    },
    KapeMapping {
        artifact_id: "lnk_files_office",
        kape_targets: &["LNKFilesAndJumpLists", "!BasicCollection"],
        kape_modules: &["LECmd"],
        velociraptor_artifacts: &["Windows.Forensics.Lnk"],
    },
    // ── Event Logs ────────────────────────────────────────────────────────────
    KapeMapping {
        artifact_id: "evtx_dir",
        kape_targets: &["EventLogs", "!SANS_Triage"],
        kape_modules: &["EvtxECmd"],
        velociraptor_artifacts: &["Windows.EventLogs.Evtx"],
    },
    KapeMapping {
        artifact_id: "evtx_security",
        kape_targets: &["EventLogs", "!SANS_Triage"],
        kape_modules: &["EvtxECmd"],
        velociraptor_artifacts: &["Windows.EventLogs.Evtx"],
    },
    KapeMapping {
        artifact_id: "evtx_system",
        kape_targets: &["EventLogs", "!SANS_Triage"],
        kape_modules: &["EvtxECmd"],
        velociraptor_artifacts: &["Windows.EventLogs.Evtx"],
    },
    KapeMapping {
        artifact_id: "evtx_powershell",
        kape_targets: &["EventLogs", "!SANS_Triage"],
        kape_modules: &["EvtxECmd"],
        velociraptor_artifacts: &[
            "Windows.EventLogs.Evtx",
            "Windows.EventLogs.PowerShell.ScriptBlock",
        ],
    },
    KapeMapping {
        artifact_id: "evtx_sysmon",
        kape_targets: &["EventLogs", "!SANS_Triage"],
        kape_modules: &["EvtxECmd"],
        velociraptor_artifacts: &["Windows.EventLogs.Evtx", "Windows.Sysmon.Events"],
    },
    // ── Registry / Credentials ────────────────────────────────────────────────
    KapeMapping {
        artifact_id: "sam_users",
        kape_targets: &["SAM", "!SANS_Triage"],
        kape_modules: &["RECmd"],
        velociraptor_artifacts: &["Windows.Registry.SAM"],
    },
    KapeMapping {
        artifact_id: "ntds_dit",
        kape_targets: &["NTDS", "!SANS_Triage"],
        kape_modules: &["ntdsutil"],
        velociraptor_artifacts: &["Windows.Carving.NTDS"],
    },
    // ── Linux — shell history & sessions ──────────────────────────────────────
    KapeMapping {
        artifact_id: "linux_bash_history",
        kape_targets: &[],
        kape_modules: &[],
        velociraptor_artifacts: &["Linux.Forensics.BashHistory"],
    },
    KapeMapping {
        artifact_id: "linux_zsh_history",
        kape_targets: &[],
        kape_modules: &[],
        velociraptor_artifacts: &["Linux.Forensics.ZshHistory"],
    },
    KapeMapping {
        artifact_id: "linux_wtmp",
        kape_targets: &[],
        kape_modules: &[],
        velociraptor_artifacts: &["Linux.Sys.Wtmp"],
    },
    // ── Linux — logs ──────────────────────────────────────────────────────────
    KapeMapping {
        artifact_id: "linux_auth_log",
        kape_targets: &[],
        kape_modules: &[],
        velociraptor_artifacts: &["Linux.Sys.AuthLog"],
    },
    KapeMapping {
        artifact_id: "linux_journal_dir",
        kape_targets: &[],
        kape_modules: &[],
        velociraptor_artifacts: &["Linux.Sys.Journal"],
    },
    // ── Linux — accounts / credentials ───────────────────────────────────────
    KapeMapping {
        artifact_id: "linux_passwd",
        kape_targets: &[],
        kape_modules: &[],
        velociraptor_artifacts: &["Linux.Sys.Users"],
    },
    KapeMapping {
        artifact_id: "linux_shadow",
        kape_targets: &[],
        kape_modules: &[],
        velociraptor_artifacts: &["Linux.Sys.Users"],
    },
    // ── Linux — persistence ───────────────────────────────────────────────────
    KapeMapping {
        artifact_id: "linux_user_crontab",
        kape_targets: &[],
        kape_modules: &[],
        velociraptor_artifacts: &["Linux.Sys.Crontab"],
    },
    KapeMapping {
        artifact_id: "linux_crontab_system",
        kape_targets: &[],
        kape_modules: &[],
        velociraptor_artifacts: &["Linux.Sys.Crontab"],
    },
    KapeMapping {
        artifact_id: "linux_ssh_authorized_keys",
        kape_targets: &[],
        kape_modules: &[],
        velociraptor_artifacts: &["Linux.Forensics.SSH.AuthorizedKeys"],
    },
];

/// Returns the KAPE mapping for a given artifact ID.
pub fn kape_mapping_for(artifact_id: &str) -> Option<&'static KapeMapping> {
    KAPE_MAPPINGS.iter().find(|m| m.artifact_id == artifact_id)
}

/// Returns all unique KAPE target names needed to collect the given artifact IDs.
pub fn kape_target_set(artifact_ids: &[&str]) -> Vec<&'static str> {
    let mut targets: Vec<&'static str> = artifact_ids
        .iter()
        .filter_map(|id| kape_mapping_for(id))
        .flat_map(|m| m.kape_targets.iter().copied())
        .collect();
    targets.sort_unstable();
    targets.dedup();
    targets
}

/// Returns all unique Velociraptor artifact names for the given artifact IDs.
pub fn velociraptor_artifact_set(artifact_ids: &[&str]) -> Vec<&'static str> {
    let mut arts: Vec<&'static str> = artifact_ids
        .iter()
        .filter_map(|id| kape_mapping_for(id))
        .flat_map(|m| m.velociraptor_artifacts.iter().copied())
        .collect();
    arts.sort_unstable();
    arts.dedup();
    arts
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
