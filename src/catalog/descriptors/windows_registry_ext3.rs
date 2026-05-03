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
        "https://attack.mitre.org/techniques/T1547/014/",
        "https://learn.microsoft.com/en-us/archive/blogs/arunjoshi_iis/what-is-active-setup",
        "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.014/T1547.014.md",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
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
        "https://attack.mitre.org/techniques/T1547/002/",
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-packages",
        "https://www.hexacorn.com/blog/2013/09/17/beyond-good-ol-run-key-part-8/",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
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
        "https://attack.mitre.org/techniques/T1547/005/",
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/ssp-packages-provided-by-microsoft",
        "https://www.hexacorn.com/blog/2013/09/17/beyond-good-ol-run-key-part-8/",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
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
        "https://attack.mitre.org/techniques/T1547/008/",
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/password-filter-programming-considerations",
        "https://www.hexacorn.com/blog/2013/09/17/beyond-good-ol-run-key-part-8/",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
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
        "https://attack.mitre.org/techniques/T1546/002/",
        "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.002/T1546.002.md",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
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
        "https://attack.mitre.org/techniques/T1547/010/",
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675",
        "https://www.hexacorn.com/blog/2013/10/20/beyond-good-ol-run-key-part-7/",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
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
        "https://attack.mitre.org/techniques/T1543/003/",
        "https://learn.microsoft.com/en-us/windows/win32/services/services",
        "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    ],
};
