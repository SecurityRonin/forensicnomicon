//! STIX 2.1 observable mapping.
//!
//! Maps catalog artifacts to STIX 2.1 Cyber Observable types and
//! indicator patterns, enabling integration with threat intelligence
//! platforms and SIEM systems.

/// STIX 2.1 Cyber Observable type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum StixObservableType {
    /// file (SCO).
    File,
    /// windows-registry-key (SCO).
    WindowsRegistryKey,
    /// process (SCO).
    Process,
    /// network-traffic (SCO).
    NetworkTraffic,
    /// user-account (SCO).
    UserAccount,
    /// directory (SCO).
    Directory,
    /// software (SCO).
    Software,
    /// artifact (SCO) — binary content.
    Artifact,
    /// domain-name (SCO).
    DomainName,
    /// email-message (SCO).
    EmailMessage,
}

/// STIX mapping for one catalog artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct StixMapping {
    pub artifact_id: &'static str,
    pub stix_type: StixObservableType,
    /// STIX Indicator pattern template (use {value} as placeholder for extracted value).
    pub stix_pattern: Option<&'static str>,
    /// Human description of the mapping.
    pub mapping_notes: &'static str,
}

pub static STIX_MAPPINGS: &[StixMapping] = &[
    // ── Windows Registry Keys ──────────────────────────────────────────────
    StixMapping {
        artifact_id: "userassist_exe",
        stix_type: StixObservableType::WindowsRegistryKey,
        stix_pattern: Some(
            "[windows-registry-key:key = 'HKEY_CURRENT_USER\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\UserAssist']",
        ),
        mapping_notes: "UserAssist tracks GUI program launches via ROT13-encoded value names under the HKCU UserAssist key.",
    },
    StixMapping {
        artifact_id: "run_key_hklm",
        stix_type: StixObservableType::WindowsRegistryKey,
        stix_pattern: Some(
            "[windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run']",
        ),
        mapping_notes: "HKLM Run key is a classic persistence mechanism that auto-starts programs for all users on login.",
    },
    StixMapping {
        artifact_id: "run_key_hkcu",
        stix_type: StixObservableType::WindowsRegistryKey,
        stix_pattern: Some(
            "[windows-registry-key:key = 'HKEY_CURRENT_USER\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run']",
        ),
        mapping_notes: "HKCU Run key provides per-user persistence; values are auto-started when the user logs on.",
    },
    StixMapping {
        artifact_id: "run_key_hklm_once",
        stix_type: StixObservableType::WindowsRegistryKey,
        stix_pattern: Some(
            "[windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce']",
        ),
        mapping_notes: "RunOnce entries execute once on next login and are deleted; sometimes used for installer-triggered payloads.",
    },
    StixMapping {
        artifact_id: "run_key_hkcu_once",
        stix_type: StixObservableType::WindowsRegistryKey,
        stix_pattern: Some(
            "[windows-registry-key:key = 'HKEY_CURRENT_USER\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce']",
        ),
        mapping_notes: "Per-user RunOnce entries auto-delete after one execution at next logon.",
    },
    StixMapping {
        artifact_id: "amcache_app_file",
        stix_type: StixObservableType::WindowsRegistryKey,
        stix_pattern: Some(
            "[windows-registry-key:key LIKE '%\\\\Amcache.hve\\\\Root\\\\InventoryApplicationFile%']",
        ),
        mapping_notes: "Amcache.hve records SHA1 hashes, paths, and timestamps for executed and installed applications.",
    },
    StixMapping {
        artifact_id: "shimcache",
        stix_type: StixObservableType::WindowsRegistryKey,
        stix_pattern: Some(
            "[windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\AppCompatCache']",
        ),
        mapping_notes: "AppCompatCache (ShimCache) stores executable path and last-modified timestamp for compatibility shimming.",
    },
    StixMapping {
        artifact_id: "bam_user",
        stix_type: StixObservableType::WindowsRegistryKey,
        stix_pattern: Some(
            "[windows-registry-key:key LIKE 'HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\bam\\\\State\\\\UserSettings\\\\%']",
        ),
        mapping_notes: "Background Activity Moderator (BAM) records last-execution timestamps per user SID for background processes.",
    },
    StixMapping {
        artifact_id: "sam_users",
        stix_type: StixObservableType::WindowsRegistryKey,
        stix_pattern: None,
        mapping_notes: "SAM hive holds local account password hashes (NTLM/LM); registry key content is encrypted and requires SYSTEM privileges.",
    },
    StixMapping {
        artifact_id: "wifi_profiles",
        stix_type: StixObservableType::WindowsRegistryKey,
        stix_pattern: Some(
            "[windows-registry-key:key LIKE 'HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\NetworkList\\\\Profiles\\\\%']",
        ),
        mapping_notes: "Network list profiles record SSIDs, adapter GUIDs, first/last connection times, and whether the network was domain-joined.",
    },
    StixMapping {
        artifact_id: "ifeo_debugger",
        stix_type: StixObservableType::WindowsRegistryKey,
        stix_pattern: Some(
            "[windows-registry-key:key LIKE 'HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\%']",
        ),
        mapping_notes: "IFEO Debugger values intercept process creation and are abused for persistence or privilege escalation (e.g. sticky-keys bypass).",
    },
    // ── Files ──────────────────────────────────────────────────────────────
    StixMapping {
        artifact_id: "prefetch_file",
        stix_type: StixObservableType::File,
        stix_pattern: Some(
            "[file:name LIKE '%.pf' AND file:parent_directory_ref.path = 'C:\\\\Windows\\\\Prefetch']",
        ),
        mapping_notes: "Windows Prefetch (.pf) files record executable name, run count, last-run timestamp, and referenced file paths.",
    },
    StixMapping {
        artifact_id: "evtx_security",
        stix_type: StixObservableType::File,
        stix_pattern: Some(
            "[file:name = 'Security.evtx' AND file:parent_directory_ref.path = 'C:\\\\Windows\\\\System32\\\\winevt\\\\Logs']",
        ),
        mapping_notes: "Security.evtx contains logon/logoff (4624/4634), privilege use, object access, and account-management events.",
    },
    StixMapping {
        artifact_id: "evtx_system",
        stix_type: StixObservableType::File,
        stix_pattern: Some(
            "[file:name = 'System.evtx' AND file:parent_directory_ref.path = 'C:\\\\Windows\\\\System32\\\\winevt\\\\Logs']",
        ),
        mapping_notes: "System.evtx records driver loads, service start/stop, and system-level operational events.",
    },
    StixMapping {
        artifact_id: "evtx_sysmon",
        stix_type: StixObservableType::File,
        stix_pattern: Some(
            "[file:name = 'Microsoft-Windows-Sysmon%4Operational.evtx']",
        ),
        mapping_notes: "Sysmon operational log captures process creation (EID 1), network connections (EID 3), file create (EID 11), and more.",
    },
    StixMapping {
        artifact_id: "mft_file",
        stix_type: StixObservableType::File,
        stix_pattern: Some("[file:name = '$MFT']"),
        mapping_notes: "The Master File Table ($MFT) indexes every file and directory on an NTFS volume with timestamps and attribute data.",
    },
    StixMapping {
        artifact_id: "ntds_dit",
        stix_type: StixObservableType::File,
        stix_pattern: Some(
            "[file:name = 'ntds.dit' AND file:parent_directory_ref.path LIKE '%\\\\NTDS']",
        ),
        mapping_notes: "ntds.dit is the Active Directory database; contains all domain object attributes including password hashes.",
    },
    StixMapping {
        artifact_id: "lnk_files",
        stix_type: StixObservableType::File,
        stix_pattern: Some("[file:name LIKE '%.lnk']"),
        mapping_notes: "Windows Shell Link (.lnk) files embed original file path, volume serial, timestamps, and NetBIOS hostname of the source machine.",
    },
    StixMapping {
        artifact_id: "linux_bash_history",
        stix_type: StixObservableType::File,
        stix_pattern: Some("[file:name = '.bash_history']"),
        mapping_notes: "Bash history records commands typed interactively; timestamps are optional and depend on HISTTIMEFORMAT.",
    },
    StixMapping {
        artifact_id: "linux_auth_log",
        stix_type: StixObservableType::File,
        stix_pattern: Some(
            "[file:name = 'auth.log' AND file:parent_directory_ref.path = '/var/log']",
        ),
        mapping_notes: "auth.log (Debian/Ubuntu) records PAM authentication events, sudo usage, sshd logins, and su invocations.",
    },
    StixMapping {
        artifact_id: "macos_launch_agents_user",
        stix_type: StixObservableType::File,
        stix_pattern: Some(
            "[file:name LIKE '%.plist' AND file:parent_directory_ref.path LIKE '%/Library/LaunchAgents']",
        ),
        mapping_notes: "User LaunchAgent plists are loaded by launchd on user login; a common macOS persistence mechanism.",
    },
    StixMapping {
        artifact_id: "wmi_subscriptions",
        stix_type: StixObservableType::File,
        stix_pattern: Some(
            "[file:name = 'OBJECTS.DATA' AND file:parent_directory_ref.path LIKE '%\\\\wbem\\\\Repository']",
        ),
        mapping_notes: "WMI permanent event subscriptions persist across reboots and are a fileless persistence mechanism; stored in the WMI repository.",
    },
    // ── Directories ────────────────────────────────────────────────────────
    StixMapping {
        artifact_id: "prefetch_dir",
        stix_type: StixObservableType::Directory,
        stix_pattern: Some("[directory:path = 'C:\\\\Windows\\\\Prefetch']"),
        mapping_notes: "The Prefetch directory contains .pf files for up to 128 most-recently prefetched executables.",
    },
    StixMapping {
        artifact_id: "scheduled_tasks_dir",
        stix_type: StixObservableType::Directory,
        stix_pattern: Some("[directory:path = 'C:\\\\Windows\\\\System32\\\\Tasks']"),
        mapping_notes: "Windows scheduled tasks are stored as XML files under System32\\Tasks; each file encodes triggers, actions, and principals.",
    },
    StixMapping {
        artifact_id: "recycle_bin",
        stix_type: StixObservableType::Directory,
        stix_pattern: Some("[directory:path LIKE '%\\\\$Recycle.Bin\\\\%']"),
        mapping_notes: "The Recycle Bin stores deleted files as $I (metadata) and $R (content) pairs, recording original path and deletion timestamp.",
    },
];

/// Returns the STIX mapping for a given artifact ID.
pub fn stix_mapping_for(artifact_id: &str) -> Option<&'static StixMapping> {
    STIX_MAPPINGS.iter().find(|m| m.artifact_id == artifact_id)
}

/// Returns all artifacts mapping to a given STIX observable type.
pub fn artifacts_for_stix_type(stix_type: StixObservableType) -> Vec<&'static StixMapping> {
    STIX_MAPPINGS
        .iter()
        .filter(|m| m.stix_type == stix_type)
        .collect()
}

/// Returns all artifact IDs that have STIX patterns defined.
pub fn artifacts_with_patterns() -> Vec<&'static StixMapping> {
    STIX_MAPPINGS
        .iter()
        .filter(|m| m.stix_pattern.is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CATALOG;

    #[test]
    fn userassist_maps_to_registry_key() {
        let m = stix_mapping_for("userassist_exe").expect("userassist_exe must have STIX mapping");
        assert_eq!(m.stix_type, StixObservableType::WindowsRegistryKey);
        assert!(m.stix_pattern.is_some());
    }

    #[test]
    fn prefetch_maps_to_file() {
        let m = stix_mapping_for("prefetch_file").expect("prefetch_file must have STIX mapping");
        assert_eq!(m.stix_type, StixObservableType::File);
    }

    #[test]
    fn registry_type_has_multiple_mappings() {
        let mappings = artifacts_for_stix_type(StixObservableType::WindowsRegistryKey);
        assert!(
            mappings.len() >= 3,
            "Should have multiple registry key mappings"
        );
    }

    #[test]
    fn artifacts_with_patterns_nonempty() {
        let patterns = artifacts_with_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().all(|m| m.stix_pattern.is_some()));
    }

    #[test]
    fn unknown_artifact_returns_none() {
        assert!(stix_mapping_for("nonexistent").is_none());
    }

    #[test]
    fn all_table_ids_exist_in_catalog() {
        for mapping in STIX_MAPPINGS {
            assert!(
                CATALOG.by_id(mapping.artifact_id).is_some(),
                "stix table references unknown artifact: {}",
                mapping.artifact_id
            );
        }
    }

    #[test]
    fn all_mappings_have_notes() {
        for mapping in STIX_MAPPINGS {
            assert!(
                !mapping.mapping_notes.is_empty(),
                "stix mapping for '{}' has empty mapping_notes",
                mapping.artifact_id
            );
        }
    }
}
