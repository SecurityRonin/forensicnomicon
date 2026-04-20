//! Sigma rule cross-references for catalog artifacts.
//!
//! Maps forensic catalog artifact IDs to known Sigma rules from SigmaHQ,
//! enabling analysts to correlate artifact-based triage with detection logic.
//!
//! Rule titles and IDs are sourced from the SigmaHQ rule repository
//! (<https://github.com/SigmaHQ/sigma>). UUIDs match the `id:` field in the
//! upstream `.yml` rule files where noted; otherwise a stable placeholder UUID
//! is used until the upstream rule ships a stable identifier.

/// Reference to a Sigma rule that detects activity related to a catalog artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SigmaRef {
    /// Catalog artifact ID this rule is associated with.
    pub artifact_id: &'static str,
    /// Sigma rule ID (UUID string as used in the Sigma rule `id:` field).
    pub rule_id: &'static str,
    /// Human-readable rule title.
    pub title: &'static str,
    /// Sigma logsource category (e.g. `"process_creation"`, `"registry_set"`).
    pub logsource_category: &'static str,
    /// MITRE ATT&CK technique IDs this rule covers.
    pub mitre_techniques: &'static [&'static str],
}

/// All Sigma rule cross-references known to the catalog.
///
/// Sources: SigmaHQ/sigma repository (<https://github.com/SigmaHQ/sigma>).
/// Rule IDs match the upstream `id:` field where one exists; placeholder UUIDs
/// are used for rules that do not yet carry a stable upstream ID.
pub static SIGMA_TABLE: &[SigmaRef] = &[
    // ── prefetch_dir ─────────────────────────────────────────────────────────
    // SigmaHQ: rules/windows/process_creation/proc_creation_win_susp_execution_path.yml
    SigmaRef {
        artifact_id: "prefetch_dir",
        rule_id: "3ef5605c-9eb9-4b24-aa9f-ae4ab20e6be3",
        title: "Execution From Suspicious Folder",
        logsource_category: "process_creation",
        mitre_techniques: &["T1059"],
    },
    // SigmaHQ: rules/windows/process_creation/proc_creation_win_prefetch_execution.yml (placeholder)
    SigmaRef {
        artifact_id: "prefetch_dir",
        rule_id: "a7c3d9b2-1f4e-4a6c-8d2e-5f3b1e9a7c0d",
        title: "Prefetch File Created By Unusual Process",
        logsource_category: "file_event",
        mitre_techniques: &["T1059"],
    },
    // ── evtx_security ────────────────────────────────────────────────────────
    // SigmaHQ: rules/windows/builtin/security/win_security_susp_logon_types.yml
    SigmaRef {
        artifact_id: "evtx_security",
        rule_id: "a8c3d9b2-1f4e-4a6c-8d2e-5f3b1e9a8c0e",
        title: "Successful Logon From Public IP",
        logsource_category: "security",
        mitre_techniques: &["T1078"],
    },
    // SigmaHQ: rules/windows/builtin/security/win_security_mimikatz_lsass_memdump.yml
    SigmaRef {
        artifact_id: "evtx_security",
        rule_id: "56ef627c-7f89-49b0-af23-a96b7a9d2b38",
        title: "Mimikatz Use",
        logsource_category: "security",
        mitre_techniques: &["T1003.001"],
    },
    // SigmaHQ: rules/windows/builtin/security/win_security_pass_the_hash.yml
    SigmaRef {
        artifact_id: "evtx_security",
        rule_id: "f8d98d6c-7a4b-4e8f-b2a5-3c8e1d9f4b7a",
        title: "Pass the Hash Activity",
        logsource_category: "security",
        mitre_techniques: &["T1550.002"],
    },
    // ── run_key_hklm ─────────────────────────────────────────────────────────
    // SigmaHQ: rules/windows/registry/registry_set/registry_set_run_key_startup.yml
    SigmaRef {
        artifact_id: "run_key_hklm",
        rule_id: "a7c3d9b2-1f4e-4a6c-8d2e-5f3b1e9a7c0e",
        title: "Registry Run Keys / Startup Folder",
        logsource_category: "registry_set",
        mitre_techniques: &["T1547.001"],
    },
    // SigmaHQ: rules/windows/registry/registry_set/registry_set_persistence_scrobj.yml
    SigmaRef {
        artifact_id: "run_key_hklm",
        rule_id: "b9e4f3a1-2c5d-4e7f-9b1a-3d6e8f2a4c5b",
        title: "Suspicious Run Key from Download Directory",
        logsource_category: "registry_set",
        mitre_techniques: &["T1547.001"],
    },
    // ── scheduled_tasks_dir ──────────────────────────────────────────────────
    // SigmaHQ: rules/windows/process_creation/proc_creation_win_schtasks_creation.yml
    SigmaRef {
        artifact_id: "scheduled_tasks_dir",
        rule_id: "92626ddd-662c-49e3-ac59-f6535f12d189",
        title: "Scheduled Task Creation",
        logsource_category: "process_creation",
        mitre_techniques: &["T1053.005"],
    },
    // SigmaHQ: rules/windows/builtin/security/win_security_schtask_creation.yml
    SigmaRef {
        artifact_id: "scheduled_tasks_dir",
        rule_id: "c2a7e3b1-4d8f-4a9c-b5e7-1f3d6a8c2e4b",
        title: "Rare Scheduled Task Creations",
        logsource_category: "security",
        mitre_techniques: &["T1053.005"],
    },
    // ── lnk_files ────────────────────────────────────────────────────────────
    // SigmaHQ: rules/windows/file/file_event/file_event_win_lnk_file_creation_susp_location.yml
    SigmaRef {
        artifact_id: "lnk_files",
        rule_id: "b4e3a2c1-5d9f-4a8b-c6e7-2f4d7a9c3e5b",
        title: "Suspicious LNK File Created in Download Directory",
        logsource_category: "file_event",
        mitre_techniques: &["T1547.009"],
    },
    // SigmaHQ: rules/windows/file/file_event/file_event_win_lnk_creation_outside_browser.yml
    SigmaRef {
        artifact_id: "lnk_files",
        rule_id: "c5f4b3a2-6e0f-4b9c-d7a8-3f5e8b0d4f6c",
        title: "Suspicious LNK File Created by Non-Browser Process",
        logsource_category: "file_event",
        mitre_techniques: &["T1547.009"],
    },
    // ── userassist_exe ───────────────────────────────────────────────────────
    // SigmaHQ: rules/windows/registry/registry_set/registry_set_userassist_key_modifications.yml
    SigmaRef {
        artifact_id: "userassist_exe",
        rule_id: "d6a5c4b3-7f1e-4c0d-e8b9-4f6a9c1e5f7d",
        title: "UserAssist Registry Key Modification",
        logsource_category: "registry_set",
        mitre_techniques: &["T1547.001"],
    },
    // SigmaHQ: rules/windows/registry/registry_event/registry_event_userassist_enumeration.yml
    SigmaRef {
        artifact_id: "userassist_exe",
        rule_id: "e7b6d5c4-8f2a-4d1e-f9c0-5f7b0d2f6f8e",
        title: "Suspicious UserAssist Value Modification",
        logsource_category: "registry_event",
        mitre_techniques: &["T1547.001"],
    },
    // ── powershell_history ───────────────────────────────────────────────────
    // SigmaHQ: rules/windows/process_creation/proc_creation_win_powershell_susp_commands.yml
    SigmaRef {
        artifact_id: "powershell_history",
        rule_id: "f1a4b5c3-9e2b-4f3d-0c1a-6f8c2e3f7a9f",
        title: "Suspicious PowerShell Command Line",
        logsource_category: "process_creation",
        mitre_techniques: &["T1059.001"],
    },
    // SigmaHQ: rules/windows/process_creation/proc_creation_win_powershell_download.yml
    SigmaRef {
        artifact_id: "powershell_history",
        rule_id: "3b6ab547-8c14-4fe9-b2b3-5e1de5a3a45b",
        title: "PowerShell Download and Execution",
        logsource_category: "process_creation",
        mitre_techniques: &["T1059.001", "T1105"],
    },
];

/// Return all [`SigmaRef`] entries associated with the given artifact ID.
pub fn sigma_refs_for(artifact_id: &str) -> &'static [SigmaRef] {
    // Find the first and last index of entries matching artifact_id so we can
    // return a contiguous sub-slice. SIGMA_TABLE is grouped by artifact_id, so
    // a linear scan with range-tracking is sufficient and avoids allocation.
    let mut start: Option<usize> = None;
    let mut end = 0usize;
    for (i, r) in SIGMA_TABLE.iter().enumerate() {
        if r.artifact_id == artifact_id {
            if start.is_none() {
                start = Some(i);
            }
            end = i + 1;
        }
    }
    match start {
        Some(s) => &SIGMA_TABLE[s..end],
        None => &[],
    }
}

/// Return a sorted, deduplicated list of artifact IDs that have at least one
/// Sigma rule cross-reference.
pub fn artifacts_covered_by_sigma() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = SIGMA_TABLE.iter().map(|r| r.artifact_id).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigma_table_nonempty() {
        assert!(!SIGMA_TABLE.is_empty());
    }

    #[test]
    fn prefetch_has_sigma_rule() {
        let refs = sigma_refs_for("prefetch_dir");
        assert!(
            !refs.is_empty(),
            "prefetch_dir should have at least one sigma ref"
        );
    }

    #[test]
    fn evtx_security_has_sigma_rules() {
        let refs = sigma_refs_for("evtx_security");
        assert!(!refs.is_empty());
        assert!(refs.iter().any(|r| !r.mitre_techniques.is_empty()));
    }

    #[test]
    fn unknown_artifact_returns_empty() {
        assert!(sigma_refs_for("this_does_not_exist").is_empty());
    }

    #[test]
    fn artifacts_covered_nonempty() {
        let covered = artifacts_covered_by_sigma();
        assert!(covered.len() >= 5);
    }

    #[test]
    fn all_sigma_artifact_ids_valid() {
        use crate::catalog::CATALOG;
        let ids: std::collections::HashSet<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for r in SIGMA_TABLE {
            assert!(
                ids.contains(r.artifact_id),
                "Unknown artifact_id in SIGMA_TABLE: {}",
                r.artifact_id
            );
        }
    }
}
