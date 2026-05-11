//! Extended Windows registry artifact descriptors — Phase 3: net-new Autoruns persistence.
//!
//! Contains only artifacts not already present in the main catalog or earlier extension
//! modules. Many classic Autoruns categories (WinLogon Shell/Userinit, AppInit DLLs,
//! BootExecute, IFEO Debugger, Netsh Helper DLLs, MountPoints2) were already present
//! in the original catalog under the same IDs.
//!
//! New artifacts added here:
//!
//! | Artifact | MITRE Sub-technique |
//! |---|---|
//! | Active Setup Installed Components | T1547.014 |
//! | LSA Authentication Packages | T1547.002 |
//! | LSA Security Packages | T1547.005 |
//! | LSA Notification Packages | T1547.008 |
//! | Screensaver Persistence (SCRNSAVE.EXE) | T1546.002 |
//! | Print Monitor DLLs | T1547.010 |
//! | Windows Services (HKLM\\Services) | T1543.003 |
//!
//! Sources: Sysinternals Autoruns (<https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns>),
//! Resplendence Registrar pre-loaded bookmarks, MITRE ATT&CK Enterprise, SigmaHQ,
//! Hexacorn "Beyond good ol' Run key" series.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactType, DataScope, Decoder, FieldSchema, HiveTarget, OsScope,
    TriagePriority, ValueType,
};

// ── T1547.014 — Active Setup ──────────────────────────────────────────────────

/// `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\`
///
/// Active Setup runs once-per-user stubs at first logon. Microsoft uses it to
/// initialise per-user settings for system components (e.g., Internet Explorer).
/// Attackers add sub-keys with a `StubPath` value pointing to a malicious
/// executable that runs once for every new user who logs in.
///
/// The original catalog has `active_setup_hklm` and `active_setup_hkcu` as separate
/// entries. This combined entry covers the HKLM (system-wide) attack surface.
pub(crate) static ACTIVE_SETUP: ArtifactDescriptor = ArtifactDescriptor {
    id: "active_setup",
    name: "Active Setup Installed Components",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Active Setup\Installed Components",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Active Setup runs StubPath commands once per user at first logon. Attackers add sub-keys with a StubPath pointing to a malicious executable. The command runs as each new user logs in, providing user-level persistence across all accounts without requiring admin re-execution (T1547.014). One of Autoruns' 'Logon' category entries.",
    mitre_techniques: &["T1547.014", "T1547"],
    fields: &[FieldSchema {
        name: "stub_path",
        value_type: ValueType::Text,
        description: "Command line to execute on first user logon; check for suspicious paths",
        is_uid_component: false,
    }],
    retention: Some("Persistent until key deletion"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["active_setup_hklm", "run_key_hklm", "scheduled_task_registry_cache"],
    sources: &[
        "https://learn.microsoft.com/en-us/archive/blogs/arunjoshi_iis/what-is-active-setup",
        "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.014/T1547.014.md",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Rogue sub-key presence is definitive; compare StubPath against known-good baseline; last-write time indicates installation"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key persists until explicitly deleted",
};

// ── T1547.002/005/008 — LSA Providers ────────────────────────────────────────

/// `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages`
///
/// Lists DLLs loaded by the Local Security Authority (LSA) as authentication
/// packages. Normally `msv1_0`. Attackers add their DLL here to intercept
/// plaintext credentials during authentication (T1547.002).
///
/// The original catalog has `lsa_auth_pkgs` (abbreviated). This entry uses
/// the full name `lsa_auth_packages` matching Autoruns' display label.
pub(crate) static LSA_AUTH_PACKAGES: ArtifactDescriptor = ArtifactDescriptor {
    id: "lsa_auth_packages",
    name: "LSA Authentication Packages",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Lsa",
    value_name: Some("Authentication Packages"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Multi-string list of DLLs loaded into lsass.exe as authentication packages. Normally contains only 'msv1_0'. Adding a malicious DLL here grants it access to plaintext credentials during interactive/network logon (T1547.002 — Authentication Package). One of Autoruns' 'LSA Providers' category entries.",
    mitre_techniques: &["T1547.002", "T1547"],
    fields: &[FieldSchema {
        name: "auth_dlls",
        value_type: ValueType::List,
        description: "Multi-string DLL names; normally ['msv1_0'] only",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["lsa_security_packages", "lsa_notification_packages", "lsa_secrets"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-packages",
        "https://www.hexacorn.com/blog/2013/09/17/beyond-good-ol-run-key-part-8/",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Any non-msv1_0 DLL is definitive IOC; requires reboot to activate; compare against Windows baseline"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value persists across reboots; requires reboot to take effect",
};

/// `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`
///
/// Lists DLLs loaded by LSA as security packages (Security Support Providers).
/// Normally includes `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg`,
/// `pku2u`. Attackers add their DLL to intercept credentials (T1547.005).
///
/// The original catalog has `lsa_security_pkgs` (abbreviated). This entry uses
/// the full name `lsa_security_packages` matching Autoruns' display label.
pub(crate) static LSA_SECURITY_PACKAGES: ArtifactDescriptor = ArtifactDescriptor {
    id: "lsa_security_packages",
    name: "LSA Security Packages",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Lsa",
    value_name: Some("Security Packages"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Multi-string list of Security Support Provider DLLs loaded into lsass.exe. Normally contains the built-in SSP list. Adding a rogue SSP grants access to every authentication negotiation, including NTLM and Kerberos plaintext tokens (T1547.005 — Security Support Provider).",
    mitre_techniques: &["T1547.005", "T1547"],
    fields: &[FieldSchema {
        name: "ssp_dlls",
        value_type: ValueType::List,
        description: "Multi-string SSP DLL names; any non-Microsoft entries are suspicious",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["lsa_auth_packages", "lsa_notification_packages", "lsa_secrets"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/ssp-packages-provided-by-microsoft",
        "https://www.hexacorn.com/blog/2013/09/17/beyond-good-ol-run-key-part-8/",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Any non-Microsoft SSP DLL is definitive IOC; cross-reference DLL hash with threat intel"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value persists across reboots; requires reboot to take effect",
};

/// `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`
///
/// Lists DLLs called by LSA when a password change occurs. Normally `scecli`.
/// Attackers add a DLL here to harvest new plaintext passwords every time
/// any user changes their password (T1547.008).
pub(crate) static LSA_NOTIFICATION_PACKAGES: ArtifactDescriptor = ArtifactDescriptor {
    id: "lsa_notification_packages",
    name: "LSA Notification Packages",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Lsa",
    value_name: Some("Notification Packages"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Multi-string list of DLLs notified by LSA when a password change occurs. Normally 'scecli'. A rogue DLL here receives plaintext old and new passwords for every account password change on the system (T1547.008 — Password Filter DLL). Particularly dangerous on domain controllers.",
    mitre_techniques: &["T1547.008", "T1547"],
    fields: &[FieldSchema {
        name: "notification_dlls",
        value_type: ValueType::List,
        description: "Multi-string DLL names; normally ['scecli'] only",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["lsa_auth_packages", "lsa_security_packages", "lsa_secrets"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/password-filter-programming-considerations",
        "https://www.hexacorn.com/blog/2013/09/17/beyond-good-ol-run-key-part-8/",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Default 'scecli' is normal; presence of additional DLLs is the IOC",
        "Some enterprise password-policy products legitimately register here",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicit modification (changes apply at reboot)",
};

// ── T1546.002 — Screensaver Persistence ──────────────────────────────────────

/// `HKCU\Control Panel\Desktop\SCRNSAVE.EXE`
///
/// Windows launches the screensaver executable set in this value after the
/// configured idle timeout. Attackers replace the screensaver path with a
/// malicious executable that runs in the user's session (T1546.002).
///
/// The original catalog has `screensaver_exe` which tracks the file path.
/// This entry specifically covers the registry persistence vector.
pub(crate) static SCREENSAVER_PERSISTENCE: ArtifactDescriptor = ArtifactDescriptor {
    id: "screensaver_persistence",
    name: "Screensaver Persistence (SCRNSAVE.EXE)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Control Panel\Desktop",
    value_name: Some("SCRNSAVE.EXE"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Path to the screensaver executable launched after idle timeout. Normally a .scr file in System32. Attackers replace this with a malicious .exe or .scr to run code in the user's session after an inactivity period (T1546.002 — Screensaver). No admin rights required — purely user-scope persistence.",
    mitre_techniques: &["T1546.002", "T1546"],
    fields: &[FieldSchema {
        name: "screensaver_path",
        value_type: ValueType::Text,
        description: "Full path to screensaver; anything outside System32 is suspicious",
        is_uid_component: true,
    }],
    retention: Some("Persistent until user changes screensaver settings"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["screensaver_exe", "run_key_hkcu", "winlogon_shell"],
    sources: &[
        "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.002/T1546.002.md",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Some users legitimately configure custom .scr screensavers — verify path and signature"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicit modification",
};

// ── T1547.010 — Print Monitor DLLs ───────────────────────────────────────────

/// `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\`
///
/// Print monitor DLLs are loaded by spoolsv.exe (Print Spooler) with SYSTEM
/// privileges. Attackers register a malicious DLL here to achieve persistent
/// SYSTEM-level code execution (T1547.010 — Print Processors).
///
/// The original catalog has `print_monitors` (abbreviated). This entry uses
/// the full name `print_monitor_dlls` and adds PrintNightmare context.
pub(crate) static PRINT_MONITOR_DLLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "print_monitor_dlls",
    name: "Print Monitor DLLs",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Print\Monitors",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Sub-keys under this path register print monitor DLLs loaded by spoolsv.exe (Print Spooler) at SYSTEM privilege level. The Driver value in each sub-key names the DLL. Attackers add a rogue sub-key here to load their DLL into the SYSTEM-privileged Spooler process at every boot (T1547.010 — Print Processors). Notable: used by PrintNightmare exploitation (CVE-2021-1675).",
    mitre_techniques: &["T1547.010", "T1547"],
    fields: &[FieldSchema {
        name: "monitor_driver",
        value_type: ValueType::Text,
        description: "DLL filename loaded by Print Spooler; non-Windows DLLs are suspicious",
        is_uid_component: false,
    }],
    retention: Some("Persistent until key deletion"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["print_monitors", "lsa_auth_packages", "services_hklm"],
    sources: &[
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675",
        "https://www.hexacorn.com/blog/2013/10/20/beyond-good-ol-run-key-part-7/",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Rogue Driver value in any sub-key is definitive; PrintNightmare (CVE-2021-1675) may leave forensic artifacts"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key persists until explicitly deleted",
};

// ── T1543.003 — Windows Services ─────────────────────────────────────────────

/// `HKLM\SYSTEM\CurrentControlSet\Services\`
///
/// Every Windows service — legitimate and malicious — has a sub-key here.
/// Attackers register malicious services for persistence with SYSTEM or
/// LocalSystem privileges, or modify existing service ImagePaths to hijack
/// legitimate services (T1543.003).
pub(crate) static SERVICES_HKLM: ArtifactDescriptor = ArtifactDescriptor {
    id: "services_hklm",
    name: "Windows Services Registry (HKLM\\Services)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Registry root of all Windows service definitions. Each sub-key's Start (0=Boot,1=System,2=Auto,3=Demand,4=Disabled) and ImagePath values determine when and what runs. Attackers create new sub-keys (often with inconspicuous names) or modify ImagePath of disabled services to install persistent SYSTEM-privilege code (T1543.003 — Windows Service). The most comprehensive persistence class.",
    mitre_techniques: &["T1543.003", "T1543"],
    fields: &[
        FieldSchema {
            name: "image_path",
            value_type: ValueType::Text,
            description: "Executable path for the service; check for unusual directories",
            is_uid_component: false,
        },
        FieldSchema {
            name: "start_type",
            value_type: ValueType::Integer,
            description: "0=Boot,1=System,2=Automatic,3=Manual,4=Disabled",
            is_uid_component: false,
        },
        FieldSchema {
            name: "service_type",
            value_type: ValueType::Integer,
            description: "Service type bitmask: 0x10=own process, 0x20=shared, 0x100=interactive",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until service key deletion"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["boot_execute", "lsa_auth_packages", "scheduled_task_registry_cache"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/win32/services/services",
        "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["New service sub-key creation time is definitive; ImagePath outside System32/SysWOW64 is suspicious; correlate with EVTX 7045"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key persists until service key deletion",
};

/// Windows OS installation date — unreliable after Feature Updates.
///
/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate` (REG_DWORD)
/// stores the OS installation timestamp as Unix epoch seconds. However, Windows
/// Feature Updates (starting with v.1607 / Anniversary Update, 2016) RESET this
/// value to the update installation date, not the original OS install. Event logs
/// are also wiped/recreated on Feature Update, so log creation dates likewise
/// reflect the Feature Update.
///
/// **Evidence reliability: Low** without corroboration from CBS.log, Windows Update
/// history, or setup*.log files.
///
/// # Sources
/// - <https://az4n6.blogspot.com/2017/02/when-windows-lies.html> — Feature Update
///   1607 resets InstallDate on multiple tested systems; log timestamps cleared too
pub(crate) static WINDOWS_INSTALL_DATE: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_install_date",
    name: "Windows Install Date",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    value_name: Some("InstallDate"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::DwordLe,
    meaning: "OS installation timestamp (REG_DWORD, Unix epoch seconds). \
        CAUTION: Windows Feature Updates (starting v.1607/Anniversary Update, 2016) \
        reset this value to the update date, not the original install. \
        The `systeminfo` command also reflects this incorrect date. \
        Event logs are also wiped on Feature Update. \
        In civil/criminal cases a recent install date may suggest evidence spoliation, \
        but Feature Updates produce the same pattern — do not conclude spoliation \
        without corroborating CBS.log, Windows Update history \
        (Software\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results), \
        or setupapi.upgrade.log. \
        In corporate environments, OS clone/image deployments also produce \
        misleading install dates (reflecting the original image build, not deployment). \
        Cross-validate: if InstallDate matches a known Feature Update KB date, \
        the original install date is unknown.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema {
            name: "install_date",
            value_type: ValueType::Timestamp,
            description: "REG_DWORD Unix epoch seconds; reflects latest Feature Update date \
                on Win10+ systems that received Anniversary Update or later",
            is_uid_component: false,
        },
        FieldSchema {
            name: "install_time",
            value_type: ValueType::Timestamp,
            description: "InstallTime REG_QWORD FILETIME (same key, same caveat); \
                higher precision but same reset behaviour as InstallDate",
            is_uid_component: false,
        },
    ],
    retention: None,
    triage_priority: TriagePriority::Low,
    related_artifacts: &["cbs_log", "setupapi_upgrade_log", "windows_update_session"],
    sources: &[
        // Source: Feature Update 1607 resets InstallDate; tested on multiple systems
        "https://az4n6.blogspot.com/2017/02/when-windows-lies.html",
        "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-log-files-and-event-logs",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "Reset by Windows Feature Updates — does not reflect original install date",
        "OEM/corporate image deployments inherit the original image build date",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until next Feature Update or reinstall",
};

/// Windows Clipboard History registry settings.
///
/// Windows 10 1809+ introduced a persistent clipboard history feature
/// (Win+V) that stores the last 25 copied items, optionally synced across
/// devices via Microsoft account. The feature is controlled by:
///
/// - `HKCU\Software\Microsoft\Clipboard\EnableClipboardHistory` (DWORD 1=on)
/// - GPO: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowClipboardHistory`
/// - GPO: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowCrossDeviceClipboard`
///
/// Clipboard history data is stored as JSON files under
/// `%LOCALAPPDATA%\Microsoft\Windows\Clipboard\`.
///
/// Forensic significance: if enabled, the clipboard retains copied text,
/// images, and HTML — potential exfiltration channel (especially with
/// cross-device sync). Infostealers and clipboard hijackers (bitcoin
/// address swappers) target this. The `ClipboardHistoryThief` tool
/// demonstrates extraction of the full history buffer.
///
/// Windows Timeline (ActivitiesCache.db) Activity_Type 16 (CopyPaste)
/// records clipboard text independently — cross-correlate both sources.
///
// Source: https://windowsir.blogspot.com/2026/01/whats-on-your-clipboard.html
// Source: https://stackoverflow.com/questions/60802854/enabling-clipboard-history-in-windows-10
pub(crate) static WINDOWS_CLIPBOARD_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_clipboard_history",
    name: "Windows Clipboard History Settings",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    // Source: https://stackoverflow.com/questions/60802854/enabling-clipboard-history-in-windows-10
    key_path: "HKCU\\Software\\Microsoft\\Clipboard",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::DwordLe,
    meaning: "Controls Windows Clipboard History (Win+V). When EnableClipboardHistory=1, \
              the OS retains the last 25 copied items (text, images, HTML) across \
              application switches. Data persists in JSON files under \
              %LOCALAPPDATA%\\Microsoft\\Windows\\Clipboard\\. \
              If 'Sync across devices' is enabled, clipboard contents replicate to \
              other devices via Microsoft account — a potential data exfiltration \
              channel for insider threat cases. Infostealers and clipboard hijackers \
              (e.g. bitcoin address swappers) exploit clipboard access (T1115). \
              Cross-correlate with Windows Timeline Activity_Type 16 (CopyPaste) \
              entries in ActivitiesCache.db for clipboard text content.",
    mitre_techniques: &["T1115"],
    fields: &[
        FieldSchema {
            name: "enable_clipboard_history",
            value_type: ValueType::UnsignedInt,
            description: "EnableClipboardHistory DWORD: 0=disabled (default), 1=enabled; \
                controls whether Win+V clipboard history is active",
            is_uid_component: false,
        },
        FieldSchema {
            name: "allow_cross_device_clipboard",
            value_type: ValueType::UnsignedInt,
            description: "AllowCrossDeviceClipboard GPO DWORD at \
                HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System; \
                0=blocked, 1=allowed; controls clipboard sync across devices \
                via Microsoft account",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until user clears history or disables feature"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["windows_timeline"],
    sources: &[
        // Source: Harlan Carvey analysis of clipboard history, ClipboardHistoryThief tool,
        // and forensic implications of clipboard sync across devices
        "https://windowsir.blogspot.com/2026/01/whats-on-your-clipboard.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "Only indicates the feature is enabled, not actual clipboard contents",
        "Disabled by default on most Windows installations",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until user toggles the feature",
};

// ── Valley RAT Registry Persistence ─────────────────────────────────────────
/// Valley RAT (Silver Fox / 银狐) stores its configuration and downloaded
/// plugins under `HKCU\Console`, abusing a legitimate-looking path that
/// blends with the default Console subsystem key. Config values sit directly
/// under `HKCU\Console`; plugins are stored in subkeys such as
/// `HKCU\Console\0\<md5_hash>`.
///
/// Because the data lives under HKCU, it is tied to a specific user account,
/// providing attribution. The `HKCU\Console` key normally contains only a
/// handful of well-known values (FaceName, FontSize, etc.); unexpected
/// subkeys or values are strong indicators of compromise.
///
// Source: https://www.cloudsek.com/blog/silver-fox-targeting-india-using-tax-themed-phishing-lures
// Source: https://windowsir.blogspot.com/2026/01/grab-bag.html
pub(crate) static VALLEY_RAT_REGISTRY: ArtifactDescriptor = ArtifactDescriptor {
    id: "valley_rat_registry",
    name: "Valley RAT Registry Config & Plugins",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    // Source: https://www.cloudsek.com/blog/silver-fox-targeting-india-using-tax-themed-phishing-lures
    key_path: "HKCU\\Console",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Valley RAT (Silver Fox / 银狐 campaign) stores its configuration \
              directly under HKCU\\Console and downloaded plugins under \
              HKCU\\Console\\0\\<md5_hash>. The legitimate Console key normally \
              holds only display settings (FaceName, FontSize, etc.), so \
              unexpected subkeys or binary values are strong IOCs. Data is \
              per-user — useful for attribution. During timeline analysis, \
              any non-standard Console subkey should stand out immediately.",
    mitre_techniques: &[
        "T1547.001", // Boot or Logon Autostart Execution: Registry Run Keys
        "T1005",     // Data from Local System
    ],
    fields: &[
        FieldSchema {
            name: "config_data",
            value_type: ValueType::Bytes,
            description: "RAT configuration values stored directly under HKCU\\Console; \
                          may include C2 addresses, encryption keys, or campaign identifiers",
            is_uid_component: false,
        },
        FieldSchema {
            name: "plugin_subkey",
            value_type: ValueType::Text,
            description: "Plugin storage subkey path, typically HKCU\\Console\\0\\<md5_hash>; \
                          contains downloaded RAT modules and their configuration",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until manually removed or user profile deleted"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["run_key_hkcu"],
    sources: &[
        // Source: CloudSEK Silver Fox campaign analysis — Valley RAT Stage 4 registry paths
        "https://www.cloudsek.com/blog/silver-fox-targeting-india-using-tax-themed-phishing-lures",
        // Source: Harlan Carvey commentary on Valley RAT registry storage
        "https://windowsir.blogspot.com/2026/01/grab-bag.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Legitimate Console key holds only display settings — unexpected subkeys/binary values are the IOC"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

// ── Hyper-V Guest Parameters ────────────────────────────────────────────────

/// Hyper-V Guest Parameters — hypervisor host discovery via registry query.
///
/// On any Windows VM running under Hyper-V, the Integration Services (vmickvpexchange)
/// populate this key with metadata about the physical host. The most forensically
/// relevant value is `PhysicalHostName` (REG_SZ), which contains the hostname of the
/// Hyper-V server. `PhysicalHostNameFullyQualified` provides the FQDN.
///
/// Threat actors query this key (`reg query HKLM\SOFTWARE\Microsoft\Virtual Machine\
/// Guest\Parameters`) during discovery to identify hypervisor infrastructure for
/// lateral movement to virtualization hosts. This was observed in the DFIR Report
/// Lynx Ransomware case (2025-12-17), where the threat actor used this key to
/// locate Hyper-V servers before deploying ransomware to backup infrastructure.
///
/// Also useful defensively: if this key exists on a host, the host is a Hyper-V guest,
/// which itself is useful context during triage.
///
// Source: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-integration-services
// Source: https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/
pub(crate) static HYPERV_GUEST_PARAMS: ArtifactDescriptor = ArtifactDescriptor {
    id: "hyperv_guest_params",
    name: "Hyper-V Guest Parameters",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    // Source: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-integration-services
    key_path: r"Microsoft\Virtual Machine\Guest\Parameters",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Hyper-V Integration Services populate this key on guest VMs with metadata \
              about the physical host. PhysicalHostName reveals the hypervisor hostname; \
              PhysicalHostNameFullyQualified provides the FQDN. Threat actors query this \
              key during discovery to identify virtualization infrastructure for lateral \
              movement. Key existence confirms the host is a Hyper-V guest VM.",
    mitre_techniques: &[
        "T1082", // System Information Discovery
        "T1012", // Query Registry
    ],
    fields: &[
        FieldSchema {
            name: "physical_host_name",
            value_type: ValueType::Text,
            description: "Hostname of the Hyper-V physical host running this guest VM",
            is_uid_component: false,
        },
        FieldSchema {
            name: "physical_host_name_fqdn",
            value_type: ValueType::Text,
            description: "Fully qualified domain name of the Hyper-V physical host",
            is_uid_component: false,
        },
        FieldSchema {
            name: "virtual_machine_name",
            value_type: ValueType::Text,
            description: "Name assigned to this VM in Hyper-V Manager",
            is_uid_component: true,
        },
    ],
    retention: Some("Persistent while VM runs under Hyper-V; updated on boot by Integration Services"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        // Source: Microsoft Hyper-V Integration Services documentation
        "https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-integration-services",
        // Source: DFIR Report — Lynx Ransomware case, threat actor queries this key for hypervisor discovery
        "https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Only present on Hyper-V guest VMs with Integration Services installed"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists for life of the guest VM",
};

// ── Registry: FeatureUsage (Win10 1903+ taskbar telemetry) ────────────────────

/// `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage`
///
/// FeatureUsage is a per-user registry key introduced in Windows 10 version 1903
/// that records taskbar interaction counters for GUI applications. The key only
/// exists if the account has logged on **interactively** (console or RDP) — pure
/// non-interactive sessions (network logons, services running as the user) leave
/// no trace here.
///
/// # Subkeys
///
/// Each subkey contains REG_DWORD values keyed by application path or AppID,
/// where the data is a monotonic counter incremented by `explorer.exe`:
///
/// - **AppSwitched** — Number of times the app was left-clicked on the taskbar
///   to switch focus (minimize/maximize cycles).
/// - **AppLaunch** — Number of times an app pinned to the taskbar was launched.
/// - **ShowJumpView** — Number of times the app was right-clicked on the taskbar
///   (Jump List opened).
/// - **AppBadgeUpdated** — Number of times a running app's taskbar badge icon was
///   updated (notification count, unread badge, etc.). Useful for inferring usage
///   of messaging or mail apps that have since been wiped.
/// - **TrayButtonClicked** — Number of times the user clicked notification-area
///   buttons (clock, action centre, etc.).
///
/// `KeyCreationTime` (REG_QWORD, FILETIME) at the root records when the key was
/// first created — i.e. the timestamp of the user's first interactive logon on
/// the system. This is a strong artefact for proving an account's first
/// interactive presence on a host.
///
/// # Forensic value
///
/// Complements UserAssist (which only records desktop/start-menu launches) and
/// RecentApps. Because increments persist even after binaries are deleted, the
/// values can corroborate execution of malware that was wiped post-incident.
///
/// Sources:
/// - <https://www.crowdstrike.com/en-us/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/>
///   (Jai Minton, 2020 — original publication of all 5 subkeys + KeyCreationTime)
/// - <https://windowsir.blogspot.com/2025/11/registry-featureusage.html>
///   (H. Carvey, 2025-11 — refresher prompted by Maurice Fielenbach LinkedIn post
///   on infostealer hunting via AppSwitched)
/// - <https://github.com/keydet89/RegRipper3.0/blob/master/plugins/featureusage.pl>
///   (RegRipper plugin — confirms NTUSER.DAT hive + key path + parser semantics)
pub static REGISTRY_FEATUREUSAGE: ArtifactDescriptor = ArtifactDescriptor {
    id: "registry_featureusage",
    name: "FeatureUsage (Taskbar Telemetry)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    // Source: https://www.crowdstrike.com/en-us/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/
    // Source: https://github.com/keydet89/RegRipper3.0/blob/master/plugins/featureusage.pl
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    // Source: CrowdStrike post — "found in builds of Windows 10 version 1903 and later"
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Per-user taskbar interaction counters populated by explorer.exe on Windows 10 1903+. \
              The key is created only after the user logs on interactively (console or RDP), so its \
              KeyCreationTime (REG_QWORD FILETIME) is a reliable artefact for first interactive \
              logon. Five subkeys (AppSwitched, AppLaunch, ShowJumpView, AppBadgeUpdated, \
              TrayButtonClicked) record monotonic REG_DWORD click/launch counts keyed by executable \
              path or AppID — counters survive uninstall and binary deletion, so they corroborate \
              GUI execution of wiped malware. Complements UserAssist for taskbar-pinned apps that \
              UserAssist does not capture.",
    mitre_techniques: &[
        "T1204.002", // User Execution: Malicious File
        "T1012",     // Query Registry (defender pivot)
    ],
    fields: &[
        FieldSchema {
            name: "KeyCreationTime",
            value_type: ValueType::Timestamp,
            description: "REG_QWORD FILETIME — timestamp of the user's first interactive logon on this system",
            is_uid_component: false,
        },
        FieldSchema {
            name: "AppSwitched",
            value_type: ValueType::UnsignedInt,
            description: "Subkey of REG_DWORD counters: number of times each application was left-clicked on the taskbar to switch focus",
            is_uid_component: false,
        },
        FieldSchema {
            name: "AppLaunch",
            value_type: ValueType::UnsignedInt,
            description: "Subkey of REG_DWORD counters: number of times each taskbar-pinned application was launched",
            is_uid_component: false,
        },
        FieldSchema {
            name: "ShowJumpView",
            value_type: ValueType::UnsignedInt,
            description: "Subkey of REG_DWORD counters: number of times each application was right-clicked on the taskbar (Jump List opened)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "AppBadgeUpdated",
            value_type: ValueType::UnsignedInt,
            description: "Subkey of REG_DWORD counters: number of times a running application's taskbar badge icon was updated (notification counts)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "TrayButtonClicked",
            value_type: ValueType::UnsignedInt,
            description: "Subkey of REG_DWORD counters: number of times the user clicked notification-area / system-tray buttons (clock, action centre)",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent for the lifetime of the user profile; counters monotonically increment and are not cleared by uninstall"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["userassist_exe", "shimcache", "amcache_app_file"],
    sources: &[
        // Source: CrowdStrike — Jai Minton's 2020 publication of all 5 subkeys + KeyCreationTime
        "https://www.crowdstrike.com/en-us/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/",
        // Source: WindowsIR — Carvey 2025-11 refresher on AppSwitched for infostealer hunting
        "https://windowsir.blogspot.com/2025/11/registry-featureusage.html",
        // Source: RegRipper plugin — confirms NTUSER.DAT hive + key path + traversal logic
        "https://github.com/keydet89/RegRipper3.0/blob/master/plugins/featureusage.pl",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Only populated on Win10 1903+ after first interactive logon",
        "Counters may be reset by user via Settings > Privacy",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Counters incremented per taskbar interaction; persist in NTUSER.DAT",
};

// ── EnablePeriodicBackup — registry-key time-stomping detection enabler ──────

/// `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\EnablePeriodicBackup`
///
/// REG_DWORD (1 = enabled). Starting with Windows 10 v1803 (Redstone 4, April
/// 2018), Microsoft disabled the legacy 10-day periodic backup of the SYSTEM,
/// SOFTWARE, SAM, SECURITY, and DEFAULT hives to `%SystemRoot%\System32\config\RegBack`.
/// As a result, on a default Win10 1803+ installation the RegBack directory
/// contains 0-byte stub files (or pre-1803 backups frozen at upgrade time) and
/// is no longer a usable forensic baseline.
///
/// Setting `EnablePeriodicBackup` to `1` and rebooting restores the original
/// behaviour: the `RegIdleBackup` Scheduled Task runs every 10 days and
/// rewrites the RegBack hives. Carvey explicitly recommends configuring this
/// value on managed endpoints as a way to detect registry-key time stomping
/// (T1070.006): with two snapshots of every monitored hive separated by up to
/// 10 days, an analyst can compare LastWrite timestamps between the live hive
/// and the most recent RegBack copy. If a Run-key (or other) LastWrite in the
/// live hive predates the RegBack copy of the same key (i.e. the timestamp
/// went backwards), the live timestamp has been tampered with.
///
/// **Forensic value**:
/// - Presence of this value (set to 1) on a Win10 1803+/Win11 system means the
///   analyst has access to a periodic baseline of the SYSTEM/SOFTWARE/SAM/
///   SECURITY/DEFAULT hives. Pull `%SystemRoot%\System32\config\RegBack\*`
///   alongside the live hives during triage.
/// - Absence/value 0 on Win10 1803+ means RegBack is empty — Carvey's
///   recommended Run-key time-stomp comparison is not possible from this host.
/// - Pair with `Microsoft-Windows-Shell-Core/Operational.evtx` event ID 9707
///   (Run-value processed at logon): a Run value that fires at logon but whose
///   parent key LastWrite is years old is the classic time-stomp constellation.
///
/// **OS scope caveat**: The value technically existed on Win7/Win8 too (where
/// RegBack was on by default and toggled by this same key), but its forensic
/// relevance — and Carvey's 2023 recommendation — applies specifically to
/// Win10 1803+ where RegBack is *off* by default.
pub(crate) static ENABLE_PERIODIC_BACKUP: ArtifactDescriptor = ArtifactDescriptor {
    id: "enable_periodic_backup",
    name: "EnablePeriodicBackup (RegBack toggle)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    // Source: https://learn.microsoft.com/en-us/troubleshoot/windows-client/deployment/system-registry-no-backed-up-regback-folder
    key_path: r"CurrentControlSet\Control\Session Manager\Configuration Manager",
    value_name: Some("EnablePeriodicBackup"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::DwordLe,
    meaning: "REG_DWORD that re-enables the 10-day periodic RegBack hive backup that Windows 10 \
        v1803 disabled by default. When set to 1 (and after reboot), the RegIdleBackup Scheduled \
        Task copies SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT hives to %SystemRoot%\\System32\\config\\\
        RegBack every ~10 days. Carvey's 2023-10 'Investigating Time Stomping' EndNote recommends \
        configuring this on managed endpoints as a detection enabler for registry-key time \
        stomping (T1070.006): with periodic snapshots of every hive, analysts can compare \
        LastWrite timestamps between the live hive and the most recent RegBack copy — a Run-key \
        LastWrite in the live hive that predates the RegBack copy of the same key indicates \
        timestamp tampering. Cross-correlate with Microsoft-Windows-Shell-Core/Operational.evtx \
        Run/RunOnce processed events. CAVEAT: on Win10 1803+ default installs the value is absent \
        or 0 and RegBack contains 0-byte stubs — no usable baseline.",
    mitre_techniques: &["T1070.006"],
    fields: &[FieldSchema {
        name: "enabled",
        value_type: ValueType::Bool,
        description: "1 = periodic RegBack backups re-enabled; 0/absent = RegBack disabled \
            (Win10 1803+ default, RegBack hives are 0-byte stubs)",
        is_uid_component: false,
    }],
    retention: None,
    triage_priority: TriagePriority::Low,
    related_artifacts: &[
        // RegBack destination — direct artifact this toggle controls
        "fa_file_regback_system",
        // Cross-correlation log per Carvey: Run/RunOnce processed events
        "evtx_microsoft_windows_shell_core_operational",
        // Time-stomping target — file-system equivalent of the same TTP
        "fa_file_environ_systemdrive_mft",
        // USN journal — corroborates file-system time stomp via change records
        "fa_file_extend_usnjrnl",
    ],
    sources: &[
        // Source: Microsoft KB documenting EnablePeriodicBackup value name, type, and
        // the 1803+ default-disabled behaviour. This is the value's authoritative reference.
        "https://learn.microsoft.com/en-us/troubleshoot/windows-client/deployment/system-registry-no-backed-up-regback-folder",
        // Source: Carvey 2023-10 — EndNote explicitly recommends enabling this value
        // as a means to detect registry time stomping by hive-vs-RegBack comparison.
        "https://windowsir.blogspot.com/2023/10/investigating-time-stomping.html",
        // Source: Lina Lau's defence-evasion timestomping reference (cited by Carvey)
        // documents the $SI/$FN attack model and Run-key tampering technique.
        "https://www.inversecos.com/2022/04/malicious-registry-timestamp.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &["Only relevant if value is 1 and reboot has occurred — otherwise RegBack contains 0-byte stubs"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicit modification",
};

// ── T1021.001 / T1112 — fDenyTSConnections (RDP Enable) ──────────────────────

/// `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
/// value: `fDenyTSConnections` (REG_DWORD)
///
/// Controls whether inbound Remote Desktop Protocol connections are accepted.
/// 0 = RDP enabled (connections permitted); 1 = RDP disabled (default on
/// workstation SKUs). Carvey (2023-05) documents threat actors setting this
/// value to 0 — typically via batch file or reg.exe — as a standard first step
/// in lateral-movement playbooks observed on Win10/11 endpoints.
///
/// The last-write timestamp on the parent Terminal Server key reveals when RDP
/// was toggled. Correlate with prefetch for reg.exe/sc.exe and Security.evtx
/// Event ID 4624 logon type 10 (RemoteInteractive) to confirm exploitation.
pub(crate) static RDP_ENABLE_REGISTRY: ArtifactDescriptor = ArtifactDescriptor {
    id: "rdp_enable_registry",
    name: "fDenyTSConnections (RDP Enable)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Terminal Server",
    value_name: Some("fDenyTSConnections"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::DwordLe,
    meaning: "REG_DWORD controlling Remote Desktop Protocol access. \
        0 = RDP enabled (connections permitted); 1 = RDP disabled (workstation default). \
        Threat actors set this to 0 — via batch file, reg.exe, or sc.exe — to enable \
        inbound RDP for lateral movement. Carvey (2023-05) documents this as a common \
        threat-actor pattern on Win10/11. The Terminal Server key last-write timestamp \
        reveals when RDP was toggled; correlate with prefetch for reg.exe/sc.exe and \
        Security.evtx EID 4624 logon type 10 (RemoteInteractive).",
    mitre_techniques: &["T1021.001", "T1112"],
    fields: &[FieldSchema {
        name: "fDenyTSConnections",
        value_type: ValueType::UnsignedInt,
        description: "0 = RDP enabled (deny=false); 1 = RDP disabled (deny=true, workstation default). \
            Threat-actor-modified systems show 0.",
        is_uid_component: false,
    }],
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "special_accounts_userlist",
        "logontype_winlogon",
    ],
    sources: &[
        "https://windowsir.blogspot.com/2023/05/the-windows-registry.html",
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/enable-remote-desktop-remotely",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Many enterprises legitimately enable RDP — value alone is not malicious without context"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicit modification",
};

// ── T1564.002 / T1136.001 — SpecialAccounts\UserList (Hidden Users) ──────────

/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`
///
/// Any user account name added as a REG_DWORD value (data=0) under this key is
/// hidden from the Windows Welcome Screen / logon UI. The account still exists
/// and can be used for interactive or remote logons — it simply does not appear
/// in the user-picker.
///
/// Carvey (2023-05) documents threat actors routinely pairing this with RDP
/// enablement: they create a new local account, add it to Remote Desktop Users,
/// then hide it here to reduce visibility. Absence of this key is normal;
/// any value under it on a managed endpoint warrants immediate investigation.
pub(crate) static SPECIAL_ACCOUNTS_USERLIST: ArtifactDescriptor = ArtifactDescriptor {
    id: "special_accounts_userlist",
    name: "SpecialAccounts\\UserList (Hidden Users)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Registry key whose value names are local account names hidden from the \
        Windows Welcome Screen. Each value is REG_DWORD with data 0 to suppress display. \
        The hidden account remains fully functional for interactive, network, and RDP logons. \
        Carvey (2023-05) documents this as a standard step in threat-actor RDP-enablement \
        batch scripts. Any value under this key on a managed endpoint is high-confidence \
        malicious activity. Cross-correlate with Security.evtx EID 4720 (account created) \
        and EID 4732 (added to Remote Desktop Users group).",
    mitre_techniques: &["T1564.002", "T1136.001"],
    fields: &[FieldSchema {
        name: "username",
        value_type: ValueType::Text,
        description: "Value name is the local account name being hidden. \
            Data REG_DWORD 0 = suppressed from Welcome Screen.",
        is_uid_component: false,
    }],
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["rdp_enable_registry", "logontype_winlogon"],
    sources: &["https://windowsir.blogspot.com/2023/05/the-windows-registry.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Some enterprise SOEs legitimately hide service accounts from the welcome screen",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

// ── T1112 — LogonType (Winlogon, XP-era value planted by threat-actor scripts) ─

/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
/// value: `LogonType` (REG_DWORD)
///
/// A legacy Windows XP–era value that controlled the logon UI style (0=classic
/// dialog, 1=Welcome Screen). On Vista+ it has no functional effect.
///
/// Carvey (2023-05) documents threat actors creating this value on Win10 endpoints
/// as part of batch-file RDP-enablement scripts. Its presence on a modern Windows
/// system has no legitimate administrative purpose. The consistent position of this
/// value within batch-file write sequences across unrelated victim organisations
/// indicates a shared pre-packaged script (likely developed against XP-era targets
/// and reused unchanged). Presence alongside `fDenyTSConnections=0` and a new
/// SpecialAccounts\UserList entry is a strong indicator of the full playbook.
pub(crate) static LOGONTYPE_WINLOGON: ArtifactDescriptor = ArtifactDescriptor {
    id: "logontype_winlogon",
    name: "LogonType (Winlogon, XP-era value)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Winlogon",
    value_name: Some("LogonType"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::DwordLe,
    meaning: "Legacy XP-era REG_DWORD controlling logon UI style (0=classic, 1=Welcome Screen). \
        On Vista+ has no functional effect. Carvey (2023-05) documents threat actors creating \
        this value on Win10 endpoints via batch file as part of an RDP-enablement script carried \
        forward from XP-era tooling. Presence on Win10/11 with no admin justification is anomalous. \
        Correlate Winlogon key last-write timestamp with nearby writes to fDenyTSConnections and \
        SpecialAccounts\\UserList to reconstruct the full RDP-enablement batch execution window.",
    mitre_techniques: &["T1112"],
    fields: &[FieldSchema {
        name: "LogonType",
        value_type: ValueType::UnsignedInt,
        description: "0 = classic logon dialog (XP); 1 = Welcome Screen (XP). \
            On Vista+ ignored by OS. Presence on Win10/11 is anomalous.",
        is_uid_component: false,
    }],
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[
        "rdp_enable_registry",
        "special_accounts_userlist",
    ],
    sources: &[
        "https://windowsir.blogspot.com/2023/05/the-windows-registry.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Has no functional effect on Vista+; presence on modern Windows indicates legacy-script execution"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicit deletion",
};

// ── RunServices / RunServicesOnce (T1547.001) ─────────────────────────────────

/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`
///
/// Win9x/NT4-era autostart key for background service-like programs that predates
/// the Service Control Manager. Still parsed and executed by some Windows versions.
/// Modern malware uses these keys to evade tools that check only the canonical `Run`
/// key. Also check the Wow6432Node mirror for 32-bit persistence on 64-bit hosts.
pub(crate) static RUN_SERVICES_HKLM: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_services_hklm",
    name: "RunServices (HKLM)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\RunServices",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Win9x-era autostart key that executes programs as background service-like processes \
        before logon. Predates SCM; still processed by some Windows builds. \
        Modern malware abuses this key to evade detection tools that enumerate only the canonical \
        Run key. Also mirror-check HKLM\\SOFTWARE\\Wow6432Node\\...\\RunServices for 32-bit \
        persistence on 64-bit hosts.",
    mitre_techniques: &["T1547.001"],
    fields: &[FieldSchema {
        name: "value_name",
        value_type: ValueType::Text,
        description: "Arbitrary value name; data is the command line to execute",
        is_uid_component: true,
    }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["run_key_hklm", "run_services_hkcu"],
    sources: &[
        "https://support.microsoft.com/en-us/kb/179365",
        "https://threatvector.cylance.com/en_us/home/windows-registry-persistence-part-2-the-run-keys-and-search-order.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Wow6432Node mirror (HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices) \
        serves 32-bit processes on 64-bit Windows; check both branches",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicitly deleted",
};

/// `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`
///
/// User-scoped equivalent of RunServices HKLM. Executes as the current user at
/// logon without requiring elevated privileges.
pub(crate) static RUN_SERVICES_HKCU: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_services_hkcu",
    name: "RunServices (HKCU)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Microsoft\Windows\CurrentVersion\RunServices",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "User-scoped Win9x-era autostart key. Executes programs as the logged-on user at \
        shell startup, requiring no administrative privilege. Lower-privilege attackers use this \
        variant when they cannot write HKLM. Pair with HKLM variant during triage.",
    mitre_techniques: &["T1547.001"],
    fields: &[FieldSchema {
        name: "value_name",
        value_type: ValueType::Text,
        description: "Arbitrary value name; data is the command line to execute",
        is_uid_component: true,
    }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["run_key_hkcu", "run_services_hklm"],
    sources: &[
        "https://support.microsoft.com/en-us/kb/179365",
        "https://threatvector.cylance.com/en_us/home/windows-registry-persistence-part-2-the-run-keys-and-search-order.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["No elevation required; accessible to unprivileged malware"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicitly deleted",
};

/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`
///
/// One-shot variant of RunServices HKLM: entries are deleted after execution.
/// Harder to detect post-execution; useful for dropper stagers.
pub(crate) static RUN_SERVICES_ONCE_HKLM: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_services_once_hklm",
    name: "RunServicesOnce (HKLM)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\RunServicesOnce",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "One-shot system-scope autostart: each value executes once at startup then is \
        deleted. Used by dropper stagers and first-stage loaders that must survive a single \
        reboot but should not persist afterwards. The self-deleting nature makes it harder to \
        detect retrospectively — check VSS snapshots or event log timestamps for execution \
        evidence if the key is now empty.",
    mitre_techniques: &["T1547.001"],
    fields: &[FieldSchema {
        name: "value_name",
        value_type: ValueType::Text,
        description: "Arbitrary value name; deleted after execution",
        is_uid_component: true,
    }],
    retention: Some("Single-execution then self-deleted"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["run_key_hklm_once", "run_services_hklm"],
    sources: &[
        "https://support.microsoft.com/en-us/kb/179365",
        "https://threatvector.cylance.com/en_us/home/windows-registry-persistence-part-2-the-run-keys-and-search-order.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "Value is deleted after first execution; key may appear empty on a live system post-execution",
        "VSS or registry transaction log may retain deleted value",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Residual),
    volatility_rationale: "Self-deletes after single execution",
};

/// `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`
///
/// User-scoped one-shot RunServicesOnce. Executes once as the logged-on user.
pub(crate) static RUN_SERVICES_ONCE_HKCU: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_services_once_hkcu",
    name: "RunServicesOnce (HKCU)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Microsoft\Windows\CurrentVersion\RunServicesOnce",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "User-scoped one-shot autostart: executes once as the current user at logon then \
        self-deletes. Used by low-privilege dropper stagers that need to survive a single reboot. \
        Self-deletion makes retrospective detection difficult; correlate with prefetch, event \
        logs, or registry transaction log to establish execution.",
    mitre_techniques: &["T1547.001"],
    fields: &[FieldSchema {
        name: "value_name",
        value_type: ValueType::Text,
        description: "Arbitrary value name; deleted after execution",
        is_uid_component: true,
    }],
    retention: Some("Single-execution then self-deleted"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["run_key_hkcu_once", "run_services_hkcu"],
    sources: &[
        "https://support.microsoft.com/en-us/kb/179365",
        "https://threatvector.cylance.com/en_us/home/windows-registry-persistence-part-2-the-run-keys-and-search-order.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &["Value is deleted after first execution; may be absent on a live system"],
    volatility: Some(crate::volatility::VolatilityClass::Residual),
    volatility_rationale: "Self-deletes after single execution",
};

// ── Windows Firewall Authorized Applications (T1562.004) ─────────────────────

/// Windows Firewall AuthorizedApplications list.
///
/// Registry values under HKLM and via policy that permit named applications
/// to communicate through the firewall. Emotet and other commodity malware
/// add entries here to ensure C2 channels pass through host-based filtering.
pub(crate) static FIREWALL_AUTHORIZED_APPS: ArtifactDescriptor = ArtifactDescriptor {
    id: "firewall_authorized_apps",
    name: "Windows Firewall Authorized Applications",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Policies\Microsoft\WindowsFirewall\StandardProfile\AuthorizedApplications\List",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Registry keys that enumerate applications explicitly permitted to receive inbound \
        connections through the Windows Firewall. Emotet modifies these settings after gaining \
        execution to ensure its C2 channel passes through host-based filtering. Also abused by \
        EyePyramid. Check all four path variants: StandardProfile and DomainProfile under both \
        SOFTWARE\\Policies\\Microsoft\\WindowsFirewall and \
        SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy.",
    mitre_techniques: &["T1562.004"],
    fields: &[FieldSchema {
        name: "application_path",
        value_type: ValueType::Text,
        description: "Full path to the permitted executable with scope suffix (e.g., :*:Enabled:AppName)",
        is_uid_component: true,
    }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["firewall_rules"],
    sources: &[
        "https://threatvector.cylance.com/en_us/home/threat-spotlight-eyepyramid-malware.html",
        "https://blog.talosintelligence.com/2019/05/threat-roundup-0524-0531.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Legitimate software installers (e.g., remote desktop tools, backup agents) also add entries here",
        "Check both StandardProfile and DomainProfile under Policies and CurrentControlSet paths",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicitly removed",
};

// ── ShellServiceObjectDelayLoad (SSODL) — T1546.013 ──────────────────────────

/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad`
///
/// COM objects registered here are loaded by Explorer during shell initialisation
/// via `CoCreateInstance`. Unlike Run keys, this mechanism loads a DLL in-process
/// to Explorer, giving the payload access to the Explorer process memory and token.
pub(crate) static SSODL: ArtifactDescriptor = ArtifactDescriptor {
    id: "ssodl",
    name: "ShellServiceObjectDelayLoad (SSODL)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "COM objects registered here are instantiated by Explorer.exe during shell \
        initialisation via CoCreateInstance. The CLSID resolves to a DLL that is loaded \
        in-process inside Explorer, granting the payload access to Explorer's process space \
        and security token. Extremely rare legitimately on modern Windows; any entry not \
        present by default warrants immediate investigation. Correlate with \
        HKCR\\CLSID\\{<value>}\\InprocServer32 to find the DLL path.",
    mitre_techniques: &["T1546.013"],
    fields: &[FieldSchema {
        name: "clsid",
        value_type: ValueType::Text,
        description: "CLSID of the COM object to load in-process within Explorer",
        is_uid_component: true,
    }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["shell_execute_hooks", "shared_task_scheduler"],
    sources: &[
        "https://www.hexacorn.com/blog/2013/07/04/beyond-good-ol-run-key-part-15/",
        "https://www.sans.org/blog/opensecurity-persistence/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Very few legitimate entries on modern Windows — any unknown CLSID here is highly suspicious",
        "Resolve CLSID in HKCR to find the backing DLL path",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicitly deleted",
};

// ── SharedTaskScheduler — T1546.013 ──────────────────────────────────────────

/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler`
///
/// COM objects registered here are instantiated by Explorer at shell startup via
/// `ISharedTaskScheduler`. Like SSODL, this is an in-process COM load mechanism;
/// the registered DLL runs inside Explorer. Used by rootkit-level persistence.
pub(crate) static SHARED_TASK_SCHEDULER: ArtifactDescriptor = ArtifactDescriptor {
    id: "shared_task_scheduler",
    name: "SharedTaskScheduler",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "COM objects registered here are loaded in-process inside Explorer.exe at shell \
        startup via the ISharedTaskScheduler interface. The mechanism provides rootkit-grade \
        persistence: the payload DLL runs with Explorer's token and inherits all its privileges. \
        Historically abused by Bagle, Rustock, and other rootkits. Nearly always empty on clean \
        systems — any entry warrants immediate COM registration analysis.",
    mitre_techniques: &["T1546.013"],
    fields: &[FieldSchema {
        name: "clsid",
        value_type: ValueType::Text,
        description: "CLSID of the COM object implementing ISharedTaskScheduler",
        is_uid_component: true,
    }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["ssodl", "shell_execute_hooks"],
    sources: &[
        "https://www.hexacorn.com/blog/2013/07/04/beyond-good-ol-run-key-part-15/",
        "https://www.sans.org/blog/opensecurity-persistence/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Should be empty on clean modern Windows — any CLSID here is anomalous",
        "Resolve CLSID in HKCR\\CLSID to identify the DLL",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicitly deleted",
};
