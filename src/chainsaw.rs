//! Chainsaw / Hayabusa EVTX detection rule mapping.
//!
//! Maps catalog artifacts to detection rules used by the
//! [Chainsaw](https://github.com/WithSecureLabs/chainsaw) and
//! [Hayabusa](https://github.com/Yamato-Security/hayabusa) hunt tools.

/// Which hunt tool a rule bundle belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum HuntTool {
    /// WithSecure Chainsaw (<https://github.com/WithSecureLabs/chainsaw>).
    Chainsaw,
    /// Yamato Security Hayabusa (<https://github.com/Yamato-Security/hayabusa>).
    Hayabusa,
    /// Compatible with both tools (standard Sigma rule).
    Both,
}

/// Reference to a Chainsaw or Hayabusa detection rule for a catalog artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct HuntRuleRef {
    /// Catalog artifact ID this rule targets.
    pub artifact_id: &'static str,
    /// Tool the rule targets.
    pub tool: HuntTool,
    /// Rule name / title.
    pub rule_title: &'static str,
    /// Rule category (maps to the event log channel, e.g. `"Security"`, `"System"`).
    pub log_channel: &'static str,
    /// MITRE ATT&CK techniques detected.
    pub mitre_techniques: &'static [&'static str],
}

/// All Chainsaw / Hayabusa hunt rule references known to the catalog.
///
/// Sources:
/// - Chainsaw rule pack: <https://github.com/WithSecureLabs/chainsaw/tree/master/rules>
/// - Hayabusa rules: <https://github.com/Yamato-Security/hayabusa-rules>
/// - SigmaHQ (rules compatible with both tools): <https://github.com/SigmaHQ/sigma>
pub static HUNT_RULE_TABLE: &[HuntRuleRef] = &[
    // ── evtx_security ────────────────────────────────────────────────────────
    // Chainsaw: sigma/rules/windows/builtin/security/win_security_mimikatz_lsass_memdump.yml
    HuntRuleRef {
        artifact_id: "evtx_security",
        tool: HuntTool::Chainsaw,
        rule_title: "Credential Dumping",
        log_channel: "Security",
        mitre_techniques: &["T1003.001"],
    },
    // Hayabusa: hayabusa-rules/sigma/builtin/security/4624_Admin_Logon.yml
    HuntRuleRef {
        artifact_id: "evtx_security",
        tool: HuntTool::Hayabusa,
        rule_title: "Admin Logon",
        log_channel: "Security",
        mitre_techniques: &["T1078"],
    },
    // SigmaHQ: rules/windows/builtin/security/win_security_schtask_creation.yml
    HuntRuleRef {
        artifact_id: "evtx_security",
        tool: HuntTool::Both,
        rule_title: "Scheduled Task Created via Event 4698",
        log_channel: "Security",
        mitre_techniques: &["T1053.005"],
    },

    // ── evtx_system ──────────────────────────────────────────────────────────
    // Chainsaw: sigma/rules/windows/builtin/system/win_system_service_install.yml
    HuntRuleRef {
        artifact_id: "evtx_system",
        tool: HuntTool::Chainsaw,
        rule_title: "Service Installed",
        log_channel: "System",
        mitre_techniques: &["T1543.003"],
    },
    // Hayabusa: hayabusa-rules/sigma/builtin/system/7045_Service_Installed.yml
    HuntRuleRef {
        artifact_id: "evtx_system",
        tool: HuntTool::Hayabusa,
        rule_title: "Service Installed",
        log_channel: "System",
        mitre_techniques: &["T1543.003"],
    },

    // ── scheduled_tasks_dir ──────────────────────────────────────────────────
    // SigmaHQ: rules/windows/file/file_event/file_event_win_susp_scheduled_task.yml
    HuntRuleRef {
        artifact_id: "scheduled_tasks_dir",
        tool: HuntTool::Both,
        rule_title: "Suspicious Scheduled Task Names",
        log_channel: "Security",
        mitre_techniques: &["T1053.005"],
    },

    // ── prefetch_dir ─────────────────────────────────────────────────────────
    // Hayabusa: hayabusa-rules/sigma/builtin/security/susp_prefetch_execution.yml
    HuntRuleRef {
        artifact_id: "prefetch_dir",
        tool: HuntTool::Hayabusa,
        rule_title: "Suspicious Process Launch from Prefetch",
        log_channel: "Security",
        mitre_techniques: &["T1059"],
    },

    // ── run_key_hklm ─────────────────────────────────────────────────────────
    // SigmaHQ: rules/windows/registry/registry_set/registry_set_run_key_startup.yml
    HuntRuleRef {
        artifact_id: "run_key_hklm",
        tool: HuntTool::Both,
        rule_title: "Registry Run Key Modified",
        log_channel: "Security",
        mitre_techniques: &["T1547.001"],
    },

    // ── lnk_files ────────────────────────────────────────────────────────────
    // Hayabusa: hayabusa-rules/sigma/builtin/security/susp_lnk_file_temp.yml
    HuntRuleRef {
        artifact_id: "lnk_files",
        tool: HuntTool::Hayabusa,
        rule_title: "Suspicious LNK File in Temp",
        log_channel: "Security",
        mitre_techniques: &["T1547.009"],
    },

    // ── mft_file ─────────────────────────────────────────────────────────────
    // Chainsaw: sigma/rules/windows/builtin/system/win_system_ntfs_journal_susp.yml
    HuntRuleRef {
        artifact_id: "mft_file",
        tool: HuntTool::Chainsaw,
        rule_title: "NTFS Journal Entry Suspicious",
        log_channel: "System",
        mitre_techniques: &["T1070.004"],
    },
];

/// Return all hunt rule references for a catalog artifact.
pub fn hunt_rules_for(artifact_id: &str) -> Vec<&'static HuntRuleRef> {
    HUNT_RULE_TABLE
        .iter()
        .filter(|r| r.artifact_id == artifact_id)
        .collect()
}

/// Return all artifact IDs that have hunt rule coverage.
///
/// The returned list is sorted and deduplicated.
pub fn covered_artifact_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = HUNT_RULE_TABLE.iter().map(|r| r.artifact_id).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Return all rules for a specific tool.
///
/// Rules with [`HuntTool::Both`] are included for every tool variant.
pub fn rules_for_tool(tool: HuntTool) -> Vec<&'static HuntRuleRef> {
    HUNT_RULE_TABLE
        .iter()
        .filter(|r| r.tool == tool || r.tool == HuntTool::Both)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_nonempty() {
        assert!(!HUNT_RULE_TABLE.is_empty());
    }

    #[test]
    fn evtx_security_has_hunt_rules() {
        let rules = hunt_rules_for("evtx_security");
        assert!(!rules.is_empty());
    }

    #[test]
    fn unknown_artifact_returns_empty() {
        assert!(hunt_rules_for("this_does_not_exist").is_empty());
    }

    #[test]
    fn covered_artifacts_nonempty() {
        let ids = covered_artifact_ids();
        assert!(ids.len() >= 5);
    }

    #[test]
    fn chainsaw_rules_exist() {
        let rules = rules_for_tool(HuntTool::Chainsaw);
        assert!(!rules.is_empty());
    }

    #[test]
    fn hayabusa_rules_exist() {
        let rules = rules_for_tool(HuntTool::Hayabusa);
        assert!(!rules.is_empty());
    }

    #[test]
    fn all_artifact_ids_valid() {
        use crate::catalog::CATALOG;
        let ids: std::collections::HashSet<&str> =
            CATALOG.list().iter().map(|d| d.id).collect();
        for r in HUNT_RULE_TABLE {
            assert!(
                ids.contains(r.artifact_id),
                "Unknown artifact_id: {}",
                r.artifact_id
            );
        }
    }
}
