//! NirSoft tool artifact path definitions.
//!
//! NirSoft tools each document specific forensic artifact paths.
//! These are defined as a static list (no HTTP scraping needed).

use crate::record::{IngestRecord, IngestType};

/// Return all NirSoft-documented forensic artifact records.
pub fn nirsoft_artifacts() -> Vec<IngestRecord> {
    vec![
        // LastActivityView — recent execution and user activity
        IngestRecord {
            id: "nirsoft_last_activity_recent_items".to_string(),
            name: "LastActivityView — Recent Items".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\Microsoft\Windows\Recent\*".to_string()),
            meaning: "Recent files and folders accessed by the user (LNK shortcuts). \
                     Documented by NirSoft LastActivityView."
                .to_string(),
            mitre_techniques: vec!["T1547.009".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/computer_activity_view.html".to_string()],
        },
        // BrowsingHistoryView — browser history locations
        IngestRecord {
            id: "nirsoft_browsing_history_chrome".to_string(),
            name: "BrowsingHistoryView — Chrome History".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History".to_string()),
            meaning: "Chrome browsing history SQLite DB as parsed by NirSoft BrowsingHistoryView."
                .to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/browsing_history_view.html".to_string()],
        },
        IngestRecord {
            id: "nirsoft_browsing_history_firefox".to_string(),
            name: "BrowsingHistoryView — Firefox History".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%APPDATA%\Mozilla\Firefox\Profiles\*.default-release\places.sqlite".to_string(),
            ),
            meaning:
                "Firefox browsing history (places.sqlite) as parsed by NirSoft BrowsingHistoryView."
                    .to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/browsing_history_view.html".to_string()],
        },
        // NetworkConnectLog — network log files
        IngestRecord {
            id: "nirsoft_network_connect_log".to_string(),
            name: "NetworkConnectLog — System Log Files".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%SystemRoot%\System32\LogFiles\*".to_string()),
            meaning: "Network connection log files in System32\\LogFiles. \
                     Parsed by NirSoft NetworkConnectLog."
                .to_string(),
            mitre_techniques: vec!["T1049".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/network_connect_log.html".to_string()],
        },
        // USBDeview — USB device history
        IngestRecord {
            id: "nirsoft_usbdeview_enum_usb".to_string(),
            name: "USBDeview — USB Device Enumeration".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKLM\\SYSTEM".to_string()),
            key_path: r"CurrentControlSet\Enum\USB".to_string(),
            value_name: None,
            file_path: None,
            meaning: "USB device enumeration entries in HKLM\\SYSTEM. \
                     Parsed by NirSoft USBDeview to list connected USB devices."
                .to_string(),
            mitre_techniques: vec!["T1052".to_string(), "T1025".to_string()],
            triage_priority: "High".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/usb_devices_view.html".to_string()],
        },
        IngestRecord {
            id: "nirsoft_usbdeview_enum_usbstor".to_string(),
            name: "USBDeview — USB Storage Device History".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKLM\\SYSTEM".to_string()),
            key_path: r"CurrentControlSet\Enum\USBSTOR".to_string(),
            value_name: None,
            file_path: None,
            meaning: "USB mass storage device history in HKLM\\SYSTEM\\USBSTOR. \
                     Records device serial numbers and connection history."
                .to_string(),
            mitre_techniques: vec!["T1052".to_string(), "T1025".to_string()],
            triage_priority: "High".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/usb_devices_view.html".to_string()],
        },
        // ShellBagsView — ShellBags (folder access)
        IngestRecord {
            id: "nirsoft_shellbags_usrclass_bags".to_string(),
            name: "ShellBagsView — UsrClass ShellBags".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKCU\\Software\\Classes".to_string()),
            key_path: r"Local Settings\Software\Microsoft\Windows\Shell\Bags".to_string(),
            value_name: None,
            file_path: None,
            meaning: "ShellBag entries in UsrClass.dat recording folder view settings — \
                     proves folder access even after deletion. Parsed by NirSoft ShellBagsView."
                .to_string(),
            mitre_techniques: vec!["T1083".to_string()],
            triage_priority: "High".to_string(),
            sources: vec![
                "https://www.nirsoft.net/utils/shell_bags_view.html".to_string(),
                "https://www.sans.org/blog/computer-forensic-artifacts-windows-7-shellbags/"
                    .to_string(),
            ],
        },
        IngestRecord {
            id: "nirsoft_shellbags_ntuser_bags".to_string(),
            name: "ShellBagsView — NTUSER ShellBags".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKCU".to_string()),
            key_path: r"Software\Microsoft\Windows\Shell\BagMRU".to_string(),
            value_name: None,
            file_path: None,
            meaning: "ShellBag MRU entries in NTUSER.DAT. Tracks folder navigation history."
                .to_string(),
            mitre_techniques: vec!["T1083".to_string()],
            triage_priority: "High".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/shell_bags_view.html".to_string()],
        },
        // JumpListsView — Jump Lists
        IngestRecord {
            id: "nirsoft_jumplists_automatic_destinations".to_string(),
            name: "JumpListsView — Automatic Destinations".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations".to_string(),
            ),
            meaning: "Automatic Jump List files (*.automaticDestinations-ms) — records recent \
                     files opened by each application. Parsed by NirSoft JumpListsView."
                .to_string(),
            mitre_techniques: vec!["T1547.009".to_string()],
            triage_priority: "High".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/jump_lists_view.html".to_string()],
        },
        IngestRecord {
            id: "nirsoft_jumplists_custom_destinations".to_string(),
            name: "JumpListsView — Custom Destinations".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\Microsoft\Windows\Recent\CustomDestinations".to_string()),
            meaning: "Custom Jump List files (*.customDestinations-ms) — pinned items and tasks \
                     defined by applications."
                .to_string(),
            mitre_techniques: vec!["T1547.009".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/jump_lists_view.html".to_string()],
        },
        // MUICache — program execution evidence
        IngestRecord {
            id: "nirsoft_muicache_local_settings".to_string(),
            name: "MUICache — Program Execution Evidence".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKCU\\Software\\Classes".to_string()),
            key_path: r"Local Settings\Software\Microsoft\Windows\Shell\MuiCache".to_string(),
            value_name: None,
            file_path: None,
            meaning: "MUICache stores program display names for executables that have run — \
                     evidence of program execution even after binary deletion. \
                     Documented by NirSoft MUICacheView."
                .to_string(),
            mitre_techniques: vec!["T1059".to_string()],
            triage_priority: "High".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/muicache_view.html".to_string()],
        },
        // RecentFilesView — recent documents
        IngestRecord {
            id: "nirsoft_recentfiles_recentdocs_key".to_string(),
            name: "RecentFilesView — RecentDocs Registry Key".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKCU".to_string()),
            key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs".to_string(),
            value_name: None,
            file_path: None,
            meaning: "Registry key tracking recently opened documents — per-extension MRU lists. \
                     Parsed by NirSoft RecentFilesView."
                .to_string(),
            mitre_techniques: vec!["T1083".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/recent_files_view.html".to_string()],
        },
        // WifiHistoryView — wireless network history
        IngestRecord {
            id: "nirsoft_wifi_history_profiles_dir".to_string(),
            name: "WifiHistoryView — WLAN Profiles Directory".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%SystemRoot%\System32\wlansvc\Profiles\Interfaces".to_string()),
            meaning: "WLAN XML profile files listing previously connected Wi-Fi networks \
                     (includes SSID). Parsed by NirSoft WifiHistoryView."
                .to_string(),
            mitre_techniques: vec!["T1049".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/wifi_history_view.html".to_string()],
        },
        // NetworkPasswordRecovery — cached credentials
        IngestRecord {
            id: "nirsoft_network_passwords_cred_dir".to_string(),
            name: "NetworkPasswordRecovery — Credentials Store".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\Microsoft\Credentials".to_string()),
            meaning: "Windows Credential Manager store. May contain cached network passwords \
                     and domain credentials. Parsed by NirSoft NetworkPasswordRecovery."
                .to_string(),
            mitre_techniques: vec!["T1555.004".to_string()],
            triage_priority: "Critical".to_string(),
            sources: vec![
                "https://www.nirsoft.net/utils/network_password_recovery.html".to_string(),
            ],
        },
        // ProductKeyDecryptor / EncryptedRegView — SAM key
        IngestRecord {
            id: "nirsoft_sam_hive_reg".to_string(),
            name: "SAM Hive — Account Database".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKLM\\SAM".to_string()),
            key_path: r"SAM\Domains\Account\Users".to_string(),
            value_name: None,
            file_path: None,
            meaning: "SAM hive users sub-key contains NT/LM password hashes for local accounts. \
                     Relevant to NirSoft's password recovery tools."
                .to_string(),
            mitre_techniques: vec!["T1003.002".to_string()],
            triage_priority: "Critical".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/sam_password_recovery.html".to_string()],
        },
        // RegistryChangesView — registry comparison baseline
        IngestRecord {
            id: "nirsoft_registry_changes_ntuser".to_string(),
            name: "RegistryChangesView — NTUSER.DAT".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%USERPROFILE%\NTUSER.DAT".to_string()),
            meaning: "User registry hive (NTUSER.DAT) — source for RegistryChangesView \
                     to diff registry before/after malware execution."
                .to_string(),
            mitre_techniques: vec!["T1112".to_string()],
            triage_priority: "High".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/registry_changes_view.html".to_string()],
        },
        // OpenedFilesView — open file handles (live system)
        IngestRecord {
            id: "nirsoft_opened_files_view_handle".to_string(),
            name: "OpenedFilesView — Open File Handles".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"\\.\PhysicalDrive0".to_string()),
            meaning: "NirSoft OpenedFilesView queries the OS for open file handles — \
                     live artifact useful during triage to identify locked files."
                .to_string(),
            mitre_techniques: vec!["T1083".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/opened_files_view.html".to_string()],
        },
        // ProcessActivityView — prefetch-based execution
        IngestRecord {
            id: "nirsoft_process_activity_prefetch".to_string(),
            name: "ProcessActivityView — Prefetch Files".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%SystemRoot%\Prefetch\*.pf".to_string()),
            meaning: "Windows Prefetch files used by NirSoft ProcessActivityView to reconstruct \
                     process execution history."
                .to_string(),
            mitre_techniques: vec!["T1059".to_string()],
            triage_priority: "High".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/process_activity_view.html".to_string()],
        },
        // InstalledCodec — registered codecs
        IngestRecord {
            id: "nirsoft_installed_codec_audio".to_string(),
            name: "InstalledCodec — Audio/Video Codec Registry".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKLM\\SOFTWARE".to_string()),
            key_path: r"Microsoft\Windows NT\CurrentVersion\Drivers32".to_string(),
            value_name: None,
            file_path: None,
            meaning: "Audio/video codec registrations — sometimes abused for persistence \
                     (DLL hijacking via codec paths). Documented by NirSoft InstalledCodec."
                .to_string(),
            mitre_techniques: vec!["T1546".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/installed_codec.html".to_string()],
        },
        // StartupRun (autoruns equivalent)
        IngestRecord {
            id: "nirsoft_startup_run_hklm_run".to_string(),
            name: "Startup Run — HKLM Run Key".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKLM\\SOFTWARE".to_string()),
            key_path: r"Microsoft\Windows\CurrentVersion\Run".to_string(),
            value_name: None,
            file_path: None,
            meaning: "System-wide Run key — programs listed here launch for all users at logon. \
                     A primary persistence mechanism documented by NirSoft StartupRun."
                .to_string(),
            mitre_techniques: vec!["T1547.001".to_string()],
            triage_priority: "High".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/startup_run_view.html".to_string()],
        },
        IngestRecord {
            id: "nirsoft_startup_run_hkcu_run".to_string(),
            name: "Startup Run — HKCU Run Key".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKCU".to_string()),
            key_path: r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            value_name: None,
            file_path: None,
            meaning:
                "Per-user Run key — programs listed here launch when the current user logs on. \
                     Common persistence mechanism."
                    .to_string(),
            mitre_techniques: vec!["T1547.001".to_string()],
            triage_priority: "High".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/startup_run_view.html".to_string()],
        },
        // AppCrashView — application crash dumps
        IngestRecord {
            id: "nirsoft_app_crash_dumps_dir".to_string(),
            name: "AppCrashView — Crash Dump Directory".to_string(),
            source_name: "nirsoft",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%LOCALAPPDATA%\CrashDumps".to_string()),
            meaning: "Application crash dump files. May contain credential material or memory \
                     forensics artefacts. Listed by NirSoft AppCrashView."
                .to_string(),
            mitre_techniques: vec!["T1003".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec!["https://www.nirsoft.net/utils/app_crash_view.html".to_string()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_at_least_15_artifacts() {
        let artifacts = nirsoft_artifacts();
        assert!(
            artifacts.len() >= 15,
            "expected >= 15 nirsoft artifacts, got {}",
            artifacts.len()
        );
    }

    #[test]
    fn all_ids_unique_snake_case_with_prefix() {
        let artifacts = nirsoft_artifacts();
        let mut seen = std::collections::HashSet::new();
        for rec in &artifacts {
            assert!(
                seen.insert(rec.id.clone()),
                "duplicate nirsoft ID: {}",
                rec.id
            );
            assert!(
                rec.id.starts_with("nirsoft_"),
                "ID missing nirsoft_ prefix: {}",
                rec.id
            );
            assert!(
                rec.id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "ID not snake_case: {}",
                rec.id
            );
        }
    }

    #[test]
    fn all_source_names_are_nirsoft() {
        let artifacts = nirsoft_artifacts();
        for rec in &artifacts {
            assert_eq!(
                rec.source_name, "nirsoft",
                "wrong source_name for {}",
                rec.id
            );
        }
    }

    #[test]
    fn credential_artifacts_are_critical() {
        let artifacts = nirsoft_artifacts();
        let crit: Vec<_> = artifacts
            .iter()
            .filter(|r| {
                r.id.contains("sam")
                    || r.id.contains("password")
                    || r.id.contains("credentials")
                    || r.id.contains("network_passwords")
            })
            .collect();
        assert!(!crit.is_empty(), "expected critical credential artifacts");
        for rec in crit {
            assert!(
                rec.triage_priority == "Critical",
                "credential artifact {} not Critical: {}",
                rec.id,
                rec.triage_priority
            );
        }
    }

    #[test]
    fn usb_artifacts_are_high_priority() {
        let artifacts = nirsoft_artifacts();
        let usb: Vec<_> = artifacts.iter().filter(|r| r.id.contains("usb")).collect();
        assert!(!usb.is_empty(), "expected USB artifacts");
        for rec in usb {
            assert!(
                rec.triage_priority == "High" || rec.triage_priority == "Critical",
                "USB artifact {} has low priority: {}",
                rec.id,
                rec.triage_priority
            );
        }
    }

    #[test]
    fn meanings_are_non_empty() {
        let artifacts = nirsoft_artifacts();
        for rec in &artifacts {
            assert!(!rec.meaning.is_empty(), "empty meaning for {}", rec.id);
        }
    }
}
