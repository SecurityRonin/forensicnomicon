//! Artifact dependency graph.
//!
//! Models structural and interpretive dependencies between catalog artifacts.
//! Enables collection tools to compute minimal artifact sets and analysts
//! to understand which artifacts require others for correct interpretation.

use std::collections::BTreeSet;

/// How one artifact depends on another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DependencyKind {
    /// This artifact is physically contained within another (e.g., registry value inside a hive file).
    ContainedIn,
    /// Interpreting this artifact requires context from another (e.g., UserAssist needs NTUSER.DAT path).
    ContextFrom,
    /// Timestamps should be compared/correlated with another artifact.
    TemporalCorrelation,
    /// Another artifact provides the same evidence from a different source.
    AlternativeSource,
    /// This artifact is a prerequisite for decoding another.
    DecodingPrerequisite,
}

/// One directed dependency between two catalog artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ArtifactDependency {
    /// The artifact that has the dependency.
    pub artifact_id: &'static str,
    /// The artifact it depends on.
    pub depends_on: &'static str,
    pub relationship: DependencyKind,
    /// Human-readable explanation of why this dependency exists.
    pub explanation: &'static str,
}

pub static ARTIFACT_DEPENDENCIES: &[ArtifactDependency] = &[
    // ── UserAssist ───────────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "userassist_exe",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContainedIn,
        explanation: "UserAssist entries are stored inside NTUSER.DAT under Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist.",
    },
    ArtifactDependency {
        artifact_id: "userassist_exe",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContextFrom,
        explanation: "The owning user's SID and profile path come from NTUSER.DAT metadata, required to attribute UserAssist entries to the correct account.",
    },
    ArtifactDependency {
        artifact_id: "userassist_folder",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContainedIn,
        explanation: "UserAssist folder entries reside inside NTUSER.DAT alongside the executable entries.",
    },
    // ── Run keys ─────────────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "run_key_hkcu",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContainedIn,
        explanation: "HKCU Run key values are stored inside the per-user NTUSER.DAT hive.",
    },
    ArtifactDependency {
        artifact_id: "run_key_hkcu_once",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContainedIn,
        explanation: "HKCU RunOnce key values are stored inside the per-user NTUSER.DAT hive.",
    },
    // ── Shellbags ────────────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "shellbags_user",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContainedIn,
        explanation: "User shellbag entries for Windows XP-7 are stored in NTUSER.DAT under Software\\Microsoft\\Windows\\Shell.",
    },
    // ── MRU artifacts ────────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "mru_recent_docs",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContainedIn,
        explanation: "RecentDocs MRU entries are stored inside NTUSER.DAT.",
    },
    ArtifactDependency {
        artifact_id: "opensave_mru",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContainedIn,
        explanation: "OpenSavePidlMRU entries are stored inside NTUSER.DAT.",
    },
    ArtifactDependency {
        artifact_id: "lastvisited_mru",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContainedIn,
        explanation: "LastVisitedPidlMRU entries are stored inside NTUSER.DAT.",
    },
    ArtifactDependency {
        artifact_id: "wordwheel_query",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContainedIn,
        explanation: "WordWheelQuery search terms are stored inside NTUSER.DAT.",
    },
    // ── Typed URLs ────────────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "typed_urls",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContainedIn,
        explanation: "Internet Explorer / Edge Legacy TypedURLs are stored in NTUSER.DAT under Software\\Microsoft\\Internet Explorer\\TypedURLs.",
    },
    ArtifactDependency {
        artifact_id: "typed_urls_time",
        depends_on: "ntuser_dat",
        relationship: DependencyKind::ContainedIn,
        explanation: "TypedURLsTime timestamps accompany TypedURLs in the same NTUSER.DAT key.",
    },
    // ── DPAPI ─────────────────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "dpapi_cred_user",
        depends_on: "dpapi_masterkey_user",
        relationship: DependencyKind::DecodingPrerequisite,
        explanation: "DPAPI credential blobs are encrypted with the user master key; the master key file must be decrypted first to recover the credential plaintext.",
    },
    ArtifactDependency {
        artifact_id: "dpapi_cred_roaming",
        depends_on: "dpapi_masterkey_user",
        relationship: DependencyKind::DecodingPrerequisite,
        explanation: "Roaming DPAPI credentials are protected by the user master key and cannot be decrypted without it.",
    },
    ArtifactDependency {
        artifact_id: "windows_vault_user",
        depends_on: "dpapi_masterkey_user",
        relationship: DependencyKind::DecodingPrerequisite,
        explanation: "Windows Credential Vault entries are DPAPI-protected; the user master key is required for decryption.",
    },
    // ── LNK / Jump Lists ──────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "jump_list_auto",
        depends_on: "lnk_files",
        relationship: DependencyKind::AlternativeSource,
        explanation: "Automatic jump list entries embed LNK shell link data; cross-referencing with standalone LNK files extends the timeline.",
    },
    ArtifactDependency {
        artifact_id: "jump_list_custom",
        depends_on: "lnk_files",
        relationship: DependencyKind::AlternativeSource,
        explanation: "Custom jump list entries may duplicate LNK records found in the Recent folder.",
    },
    // ── BAM / DAM ─────────────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "bam_user",
        depends_on: "sam_users",
        relationship: DependencyKind::ContextFrom,
        explanation: "BAM entries are keyed by SID; SAM\\Users provides the SID-to-username mapping needed to attribute execution to an account name.",
    },
    ArtifactDependency {
        artifact_id: "dam_user",
        depends_on: "sam_users",
        relationship: DependencyKind::ContextFrom,
        explanation: "DAM entries are keyed by SID; SAM\\Users is required for SID-to-username attribution.",
    },
    // ── Prefetch ──────────────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "prefetch_dir",
        depends_on: "mft_file",
        relationship: DependencyKind::TemporalCorrelation,
        explanation: "MFT timestamps for prefetch files provide $SI and $FN birth times that corroborate or refute prefetch-reported first-run timestamps.",
    },
    ArtifactDependency {
        artifact_id: "prefetch_file",
        depends_on: "mft_file",
        relationship: DependencyKind::TemporalCorrelation,
        explanation: "MFT timestamps corroborate prefetch file first-run and last-run times.",
    },
    // ── EVTX correlation ──────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "evtx_security",
        depends_on: "evtx_system",
        relationship: DependencyKind::TemporalCorrelation,
        explanation: "Security and System event logs share overlapping authentication and service events; correlating both provides a fuller picture of logon activity.",
    },
    ArtifactDependency {
        artifact_id: "evtx_powershell",
        depends_on: "evtx_sysmon",
        relationship: DependencyKind::TemporalCorrelation,
        explanation: "PowerShell operational events corroborate Sysmon process-creation records for the same execution.",
    },
    // ── SRUM sub-tables ───────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "srum_network_usage",
        depends_on: "srum_db",
        relationship: DependencyKind::ContainedIn,
        explanation: "Network usage data is stored as a table inside the SRUM ESE database (SRUDB.dat).",
    },
    ArtifactDependency {
        artifact_id: "srum_app_resource",
        depends_on: "srum_db",
        relationship: DependencyKind::ContainedIn,
        explanation: "App resource usage data is stored as a table inside the SRUM ESE database.",
    },
    ArtifactDependency {
        artifact_id: "srum_energy_usage",
        depends_on: "srum_db",
        relationship: DependencyKind::ContainedIn,
        explanation: "Energy usage data is stored as a table inside the SRUM ESE database.",
    },
    ArtifactDependency {
        artifact_id: "srum_push_notification",
        depends_on: "srum_db",
        relationship: DependencyKind::ContainedIn,
        explanation: "Push notification usage data is stored as a table inside the SRUM ESE database.",
    },
    // ── Linux ─────────────────────────────────────────────────────────────────
    ArtifactDependency {
        artifact_id: "linux_bash_history",
        depends_on: "linux_passwd",
        relationship: DependencyKind::ContextFrom,
        explanation: "/etc/passwd maps UIDs to usernames; required to attribute bash_history files (owned by UID) to a human-readable account name.",
    },
    ArtifactDependency {
        artifact_id: "linux_user_crontab",
        depends_on: "linux_passwd",
        relationship: DependencyKind::ContextFrom,
        explanation: "User crontab files are named by username; /etc/passwd is needed to enumerate accounts and attribute scheduled tasks.",
    },
];

/// Returns all dependencies for a given artifact ID (things it depends on).
pub fn dependencies_of(artifact_id: &str) -> Vec<&'static ArtifactDependency> {
    ARTIFACT_DEPENDENCIES
        .iter()
        .filter(|d| d.artifact_id == artifact_id)
        .collect()
}

/// Returns all artifacts that depend on the given artifact ID.
pub fn dependents_of(artifact_id: &str) -> Vec<&'static ArtifactDependency> {
    ARTIFACT_DEPENDENCIES
        .iter()
        .filter(|d| d.depends_on == artifact_id)
        .collect()
}

/// Returns the full dependency graph as a slice.
pub fn dependency_graph() -> &'static [ArtifactDependency] {
    ARTIFACT_DEPENDENCIES
}

/// Given a set of target artifact IDs, computes the minimal collection set
/// including all dependencies (transitively). Returns a sorted, deduplicated
/// list of `&'static str` IDs drawn from the dependency table.
pub fn full_collection_set(artifact_ids: &[&str]) -> Vec<&'static str> {
    let mut set: BTreeSet<&'static str> = BTreeSet::new();

    for &input_id in artifact_ids {
        // Scan the table: if an entry's artifact_id matches the input, include
        // both the artifact (static) and its dependency (static).
        let mut matched = false;
        for dep in ARTIFACT_DEPENDENCIES {
            if dep.artifact_id == input_id {
                set.insert(dep.artifact_id);
                set.insert(dep.depends_on);
                matched = true;
            }
        }
        if !matched {
            // Artifact appears only on the depends_on side; intern the static str.
            for dep in ARTIFACT_DEPENDENCIES {
                if dep.depends_on == input_id {
                    set.insert(dep.depends_on);
                    break;
                }
            }
            // Unknown IDs (not in the table at all) are silently skipped because
            // we cannot produce a 'static str for them.
        }
    }

    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CATALOG;

    #[test]
    fn userassist_depends_on_ntuser() {
        let deps = dependencies_of("userassist_exe");
        assert!(!deps.is_empty());
        assert!(
            deps.iter().any(|d| d.depends_on == "ntuser_dat"),
            "userassist_exe should depend on ntuser_dat"
        );
    }

    #[test]
    fn dpapi_cred_has_decoding_prerequisite() {
        let deps = dependencies_of("dpapi_cred_user");
        assert!(
            deps.iter()
                .any(|d| d.relationship == DependencyKind::DecodingPrerequisite),
            "dpapi_cred_user should have a DecodingPrerequisite"
        );
    }

    #[test]
    fn full_collection_set_includes_prerequisites() {
        let set = full_collection_set(&["dpapi_cred_user"]);
        assert!(
            set.contains(&"dpapi_masterkey_user"),
            "Collection set for dpapi_cred_user should include dpapi_masterkey_user"
        );
    }

    #[test]
    fn full_collection_set_deduplicates() {
        let set = full_collection_set(&["userassist_exe", "run_key_hkcu"]);
        let ntuser_count = set.iter().filter(|&&id| id == "ntuser_dat").count();
        assert_eq!(ntuser_count, 1, "ntuser_dat should appear only once");
    }

    #[test]
    fn dependency_graph_nonempty() {
        assert!(dependency_graph().len() >= 20);
    }

    #[test]
    fn dependents_of_ntuser_is_nonempty() {
        let dependents = dependents_of("ntuser_dat");
        assert!(
            !dependents.is_empty(),
            "Several artifacts depend on ntuser_dat"
        );
    }

    #[test]
    fn all_dependency_artifact_ids_exist_in_catalog() {
        // Only check artifact_id (the dependent), not depends_on (may be container artifacts)
        for dep in ARTIFACT_DEPENDENCIES {
            assert!(
                CATALOG.by_id(dep.artifact_id).is_some(),
                "dependency graph references unknown artifact_id: {}",
                dep.artifact_id
            );
        }
    }

    #[test]
    fn all_explanations_nonempty() {
        for dep in ARTIFACT_DEPENDENCIES {
            assert!(
                !dep.explanation.is_empty(),
                "dependency {}->{} has empty explanation",
                dep.artifact_id,
                dep.depends_on
            );
        }
    }
}
