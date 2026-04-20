//! Authoritative reference catalog for each public module.
//!
//! The smaller indicator-table modules expose static data and helper functions,
//! but their provenance previously lived only in Rust doc comments. This module
//! makes those references queryable so downstream tools can surface source
//! material alongside detections, triage hints, or generated reports.

/// Curated source bundle for one public module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleReference {
    /// Public module name, e.g. `ports` or `persistence`.
    pub module: &'static str,
    /// Short summary of what the module covers.
    pub focus: &'static str,
    /// Primary reference URLs used to justify the module's coverage.
    pub urls: &'static [&'static str],
}

pub const PORTS_REFERENCES: &[&str] = &[
    "https://isc.sans.edu/port.html",
    "https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management",
    "https://support.torproject.org/tbb/tbb-firewall-ports/",
    "https://attack.mitre.org/techniques/T1071/",
];

pub const LOLBINS_REFERENCES: &[&str] = &[
    "https://lolbas-project.github.io/",
    "https://gtfobins.github.io/",
    "https://attack.mitre.org/techniques/T1218/",
    "https://attack.mitre.org/techniques/T1059/",
];

pub const PROCESSES_REFERENCES: &[&str] = &[
    "https://attack.mitre.org/techniques/T1036/",
    "https://attack.mitre.org/techniques/T1036/005/",
    "https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring",
    "https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication",
];

pub const COMMANDS_REFERENCES: &[&str] = &[
    "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md",
    "https://attack.mitre.org/techniques/T1059/",
    "https://attack.mitre.org/techniques/T1059/001/",
    "https://attack.mitre.org/techniques/T1105/",
];

pub const PATHS_REFERENCES: &[&str] = &[
    "https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file",
    "https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html",
    "https://attack.mitre.org/techniques/T1574/001/",
    "https://attack.mitre.org/techniques/T1574/006/",
];

pub const PERSISTENCE_REFERENCES: &[&str] = &[
    "https://attack.mitre.org/techniques/T1547/",
    "https://attack.mitre.org/techniques/T1053/003/",
    "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    "http://windowsir.blogspot.com/2013/07/howto-detecting-persistence-mechanisms.html",
    "https://github.com/mkorman90/regipy",
    "https://github.com/EricZimmerman/RECmd",
    "https://github.com/EricZimmerman/RegistryPlugins",
];

pub const ANTIFORENSICS_REFERENCES: &[&str] = &[
    "https://attack.mitre.org/techniques/T1070/",
    "https://attack.mitre.org/techniques/T1070/001/",
    "https://attack.mitre.org/techniques/T1070/006/",
    "http://windowsir.blogspot.com/2023/10/investigating-time-stomping.html",
];

pub const ENCRYPTION_REFERENCES: &[&str] = &[
    "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-group-policy-settings",
    "https://learn.microsoft.com/en-us/windows/win32/fileio/file-encryption",
    "https://belkasoft.com/veracrypt-forensics",
    "https://tb-manual.torproject.org/installation/",
];

pub const REMOTE_ACCESS_REFERENCES: &[&str] = &[
    "https://lolrmm.io/",
    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a",
    "https://redcanary.com/blog/threat-intelligence/remote-monitoring-management/",
    "https://www.huntress.com/blog/no-longer-low-hanging-fruit-hunting-for-risky-rmm-tools",
];

pub const THIRD_PARTY_REFERENCES: &[&str] = &[
    "https://the.earth.li/~sgtatham/putty/0.78/htmldoc/AppendixC.html",
    "https://winscp.net/eng/docs/ui_pref_storage",
    "https://learn.microsoft.com/en-us/sharepoint/sync-client-administration-settings",
    "https://chromeenterprise.google/policies/",
    "https://github.com/mkorman90/regipy",
    "https://github.com/EricZimmerman/LECmd",
    "https://github.com/EricZimmerman/Lnk",
];

pub const PCA_REFERENCES: &[&str] = &[
    "https://andreafortuna.org/2024/windows11-pca-artifact/",
    "https://attack.mitre.org/techniques/T1204/",
    "https://attack.mitre.org/techniques/T1059/",
];

pub const ARTIFACT_REFERENCES: &[&str] = &[
    "https://docs.rs/forensicnomicon",
    "https://attack.mitre.org/",
    "http://windowsir.blogspot.com/",
    "https://ericzimmerman.github.io/#!index.md",
    "https://github.com/mkorman90/regipy",
    "https://github.com/EricZimmerman/evtx",
    "https://github.com/EricZimmerman/MFTECmd",
    "https://github.com/EricZimmerman/JLECmd",
    "https://github.com/EricZimmerman/LECmd",
    "https://github.com/EricZimmerman/PECmd",
    "https://github.com/EricZimmerman/AppCompatCacheParser",
    "https://github.com/EricZimmerman/AmcacheParser",
    "https://github.com/EricZimmerman/Srum",
    "https://github.com/EricZimmerman/RBCmd",
    "https://github.com/EricZimmerman/RECmd",
    "https://github.com/EricZimmerman/RegistryPlugins",
    "https://github.com/EricZimmerman/Registry",
    "https://github.com/EricZimmerman/SQLECmd",
    "https://github.com/EricZimmerman/WxTCmd",
    "https://github.com/EricZimmerman/OleCf",
    "https://github.com/EricZimmerman/MFT",
    "https://github.com/EricZimmerman/RecentFileCacheParser",
    "https://github.com/EricZimmerman/WinSearchDBAnalyzer",
    "https://github.com/EricZimmerman/USBDevices",
    "https://github.com/EricZimmerman/ExtensionBlocks",
    "https://github.com/EricZimmerman/GuidMapping",
    "https://github.com/EricZimmerman/DFIR-SQL-Query-Repo",
    "https://github.com/EricZimmerman/RegistryExplorerBookmarks",
    "https://github.com/EricZimmerman/TLEFilePlugins",
    "https://github.com/EricZimmerman/KapeFiles",
    "https://github.com/EricZimmerman/KapeDocs",
    "https://github.com/EricZimmerman/documentation",
    "https://github.com/EricZimmerman/Get-ZimmermanTools",
];

pub const MODULE_REFERENCES: &[ModuleReference] = &[
    ModuleReference {
        module: "artifact",
        focus: "Unified forensic artifact descriptors with decode logic, triage priority, ATT&CK mappings, and embedded source URLs.",
        urls: ARTIFACT_REFERENCES,
    },
    ModuleReference {
        module: "ports",
        focus: "Suspicious or attacker-favored network ports tied to C2, Tor, WinRM, and remote administration.",
        urls: PORTS_REFERENCES,
    },
    ModuleReference {
        module: "lolbins",
        focus: "Trusted Windows and Linux binaries commonly abused for proxy execution, scripting, and download/execution chains.",
        urls: LOLBINS_REFERENCES,
    },
    ModuleReference {
        module: "processes",
        focus: "Masquerade targets and offensive-tool process names useful for triage and process tree review.",
        urls: PROCESSES_REFERENCES,
    },
    ModuleReference {
        module: "commands",
        focus: "Reverse shell, PowerShell abuse, and ingress-tool-transfer command fragments.",
        urls: COMMANDS_REFERENCES,
    },
    ModuleReference {
        module: "paths",
        focus: "Trusted library paths and suspicious staging locations across Windows and Linux.",
        urls: PATHS_REFERENCES,
    },
    ModuleReference {
        module: "persistence",
        focus: "Windows autoruns and cross-platform persistence locations including cron, systemd, launchd, and registry hijacks.",
        urls: PERSISTENCE_REFERENCES,
    },
    ModuleReference {
        module: "antiforensics",
        focus: "Log wiping, timestomping, and rootkit indicators aligned to defense-evasion behavior.",
        urls: ANTIFORENSICS_REFERENCES,
    },
    ModuleReference {
        module: "encryption",
        focus: "Registry evidence for disk encryption, credential stores, and dual-use secrecy tools.",
        urls: ENCRYPTION_REFERENCES,
    },
    ModuleReference {
        module: "remote_access",
        focus: "Remote monitoring and management tool indicators, especially LOLRMM software frequently abused in intrusions.",
        urls: REMOTE_ACCESS_REFERENCES,
    },
    ModuleReference {
        module: "third_party",
        focus: "Forensically valuable artifact paths for SSH clients, cloud sync apps, and browsers.",
        urls: THIRD_PARTY_REFERENCES,
    },
    ModuleReference {
        module: "pca",
        focus: "Windows 11 Program Compatibility Assistant execution artifacts and decoding guidance.",
        urls: PCA_REFERENCES,
    },
];

/// Returns all module reference bundles.
pub fn all_module_references() -> &'static [ModuleReference] {
    MODULE_REFERENCES
}

/// Returns the curated source bundle for a module name.
pub fn module_references(name: &str) -> Option<&'static ModuleReference> {
    MODULE_REFERENCES
        .iter()
        .find(|entry| entry.module.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_reference_index_covers_public_modules() {
        let modules: Vec<&str> = MODULE_REFERENCES.iter().map(|entry| entry.module).collect();
        for expected in [
            "artifact",
            "ports",
            "lolbins",
            "processes",
            "commands",
            "paths",
            "persistence",
            "antiforensics",
            "encryption",
            "remote_access",
            "third_party",
            "pca",
        ] {
            assert!(
                modules.contains(&expected),
                "missing module reference for {expected}"
            );
        }
    }

    #[test]
    fn every_module_has_at_least_one_url() {
        for entry in MODULE_REFERENCES {
            assert!(
                !entry.urls.is_empty(),
                "module {} should expose at least one authoritative source",
                entry.module
            );
        }
    }

    #[test]
    fn module_lookup_is_case_insensitive() {
        let entry = module_references("Remote_Access").unwrap();
        assert_eq!(entry.module, "remote_access");
    }

    #[test]
    fn all_module_references_returns_static_slice() {
        assert_eq!(all_module_references().len(), MODULE_REFERENCES.len());
    }
}
