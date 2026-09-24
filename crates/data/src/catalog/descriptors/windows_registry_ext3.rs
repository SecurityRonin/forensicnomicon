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
//! | Windows Services (HKLM\\Services) | T1543.003, T1574.009 |
//! | Service Failure Actions (FailureActions / FailureCommand) | T1543.003 |
//! | Service Trigger-Start Registration (TriggerInfo) | T1543.003 |
//! | UAC Remote Restriction (LocalAccountTokenFilterPolicy) | T1112, T1021.002 |
//! | LSA LAN Manager Authentication Level (LmCompatibilityLevel) | T1557.001, T1110.002 |
//! | System Restore Snapshot Scoping (ScopeSnapshots) | — |
//! | Crash Dump Configuration (Control\\CrashControl) | — |
//! | Windows Build Identification (Windows NT\\CurrentVersion) | — |
//! | Capability Access Manager ConsentStore | T1125, T1123 |
//! | Explorer Programs Cache (StartPage / StartPage2) | — |
//!
//! Sources: Sysinternals Autoruns (<https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns>),
//! Resplendence Registrar pre-loaded bookmarks, MITRE ATT&CK Enterprise, SigmaHQ,
//! Hexacorn "Beyond good ol' Run key" series.
//!
//! The service-configuration, host-configuration and build-identification entries
//! above are written from Microsoft's own references for the structures and values
//! concerned (`SERVICE_FAILURE_ACTIONS`, `SC_ACTION`, `SERVICE_TRIGGER`,
//! `SRSetRestorePoint`, KB951016, the LAN Manager authentication level policy
//! reference, and the CrashControl value list), with the registry layout taken from
//! libyal's winreg-kb; per-descriptor `Source:` lines carry the specific citation.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, HiveTarget, OsScope,
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryValue,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryValue,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryValue,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryValue,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
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
///
/// Two properties of a service key that an autostart sweep keyed on
/// `Start`/`ImagePath` alone does not reach are modelled on the fields below:
/// the *quoting state* of `ImagePath` (an unquoted path containing spaces is
/// resolved by prefix probing, T1574.009), and trigger-start registration
/// (`Start` = 3 does not mean "does not start by itself"). The recovery-action
/// values and the trigger registration have their own descriptors —
/// `service_failure_actions` and `service_trigger_info`.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw>
/// Source: <https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Services-and-drivers.html>
pub(crate) static SERVICES_HKLM: ArtifactDescriptor = ArtifactDescriptor {
    id: "services_hklm",
    name: "Windows Services Registry (HKLM\\Services)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Registry root of all Windows service definitions. Each sub-key's Start (0=Boot,1=System,2=Auto,3=Demand,4=Disabled) and ImagePath values determine when and what runs. Attackers create new sub-keys (often with inconspicuous names) or modify ImagePath of disabled services to install persistent SYSTEM-privilege code (T1543.003 — Windows Service). The most comprehensive persistence class.",
    mitre_techniques: &["T1543.003", "T1543", "T1574.009"],
    fields: &[
        FieldSchema {
            name: "image_path",
            value_type: ValueType::Text,
            description: "Executable path for the service; check for unusual directories. \
                The QUOTING STATE of the value is evidence in its own right: when the path is \
                unquoted and contains spaces, the module name is taken as the leading \
                white-space-delimited token and each prefix is tried in turn with .exe appended \
                — for C:\\Program Files\\Sub Dir\\Program Name the order is C:\\Program.exe, then \
                C:\\Program Files\\Sub.exe, then C:\\Program Files\\Sub Dir\\Program.exe, then the \
                full name — so a writable directory earlier in that sequence lets a planted \
                binary win without this value ever being modified (T1574.009)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "start_type",
            value_type: ValueType::Integer,
            description: "0=Boot,1=System,2=Automatic,3=On demand (manual),4=Disabled. \
                Do not read 3 as 'never starts on its own': a service carrying a trigger \
                registration is started by the SCM when the trigger event occurs (device \
                arrival, first IP address on the stack, domain join, group-policy change, \
                firewall port, named-pipe/RPC endpoint, or an ETW event) while still \
                showing 3 — enumerate service_trigger_info before classing a service as \
                non-autostart",
            is_uid_component: false,
        },
        FieldSchema {
            name: "service_type",
            value_type: ValueType::Integer,
            description: "Service type bitmask: 0x10=own process, 0x20=shared, 0x100=interactive",
            is_uid_component: false,
        },
        FieldSchema {
            name: "object_name",
            value_type: ValueType::Text,
            description: "For a service, the account the service logs on as (shown as 'Log On As'); \
                for a driver, the NT driver object name used by the I/O Manager. Determines the \
                context a recovery command runs in — see service_failure_actions",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until service key deletion"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "boot_execute",
        "lsa_auth_packages",
        "scheduled_task_registry_cache",
        "service_failure_actions",
        "service_trigger_info",
    ],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/win32/services/services",
        "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
        // Source: documented prefix-probing order when the module name is taken from an
        // unquoted command line, plus the Security Remarks naming the interposition risk.
        "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw",
        // Source: CWE-428 — the weakness class an unquoted ImagePath belongs to.
        "https://cwe.mitre.org/data/definitions/428.html",
        // Source: Start/Type/ErrorControl/ObjectName value semantics and the service key layout.
        "https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Services-and-drivers.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "New service sub-key creation time is definitive; ImagePath outside System32/SysWOW64 is suspicious; correlate with EVTX 7045",
        "An unquoted ImagePath containing spaces is a latent interception path, not proof of interception — the finding is the writable directory earlier in the probe order, not the value itself, and plenty of vendor installers ship unquoted paths",
        "A sweep filtered on Start=2 misses trigger-started services, which carry Start=3; enumerate trigger registrations separately before reporting the set of services that run without operator action",
    ],
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
    artifact_type: ArtifactLocation::RegistryValue,
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
    evidence_tier: None,
    evidence_caveats: &[
        "Reset by Windows Feature Updates — does not reflect original install date",
        "OEM/corporate image deployments inherit the original image build date",
        "After a clean install, artefacts the install creates afresh (event logs, Prefetch, logon history) cannot reach conduct before it, while user files restored or migrated from elsewhere can be older than it; files older than InstallDate are consistent with migration or an upgrade reset and are not, by themselves, a sign of tampering. After a feature update the date moves but earlier artefacts may survive, so read it as the latest install or upgrade, not a floor for every artefact",
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryValue,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryValue,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryValue,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
    evidence_caveats: &[
        "Value is deleted after first execution; key may appear empty on a live system post-execution",
        "Evidence of past execution may survive in prefetch, Amcache, or event logs even after self-deletion",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists while present — self-deletion on execution is captured in retention, not volatility class",
};

/// `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`
///
/// User-scoped one-shot RunServicesOnce. Executes once as the logged-on user.
pub(crate) static RUN_SERVICES_ONCE_HKCU: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_services_once_hkcu",
    name: "RunServicesOnce (HKCU)",
    artifact_type: ArtifactLocation::RegistryKey,
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
        logs, or Amcache to establish execution.",
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
    evidence_tier: None,
    evidence_caveats: &[
        "Value is deleted after first execution; may be absent on a live system post-execution",
        "Evidence of past execution may survive in prefetch, Amcache, or event logs even after self-deletion",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists while present — self-deletion on execution is captured in retention, not volatility class",
};

// ── Windows Firewall Authorized Applications (T1686) ─────────────────────

/// Windows Firewall AuthorizedApplications list.
///
/// Registry values under HKLM and via policy that permit named applications
/// to communicate through the firewall. Emotet and other commodity malware
/// add entries here to ensure C2 channels pass through host-based filtering.
pub(crate) static FIREWALL_AUTHORIZED_APPS: ArtifactDescriptor = ArtifactDescriptor {
    id: "firewall_authorized_apps",
    name: "Windows Firewall Authorized Applications",
    artifact_type: ArtifactLocation::RegistryKey,
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
    mitre_techniques: &["T1686"],
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
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
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_tier: None,
    evidence_caveats: &[
        "Should be empty on clean modern Windows — any CLSID here is anomalous",
        "Resolve CLSID in HKCR\\CLSID to identify the DLL",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicitly deleted",
};

// ── Credential Provider Filters (T1556.001) ───────────────────────────────────

/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters`
///
/// COM objects registered here act as filters that intercept credentials passing
/// through the credential provider pipeline. Unlike credential providers (which
/// supply credentials), filters see every credential *after* collection and can
/// log, modify, or block them before authentication completes.
///
/// Attackers register malicious DLLs as filters to capture plaintext credentials
/// for every Windows logon without needing to replace a full credential provider.
pub(crate) static CREDENTIAL_PROVIDER_FILTERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "credential_provider_filters",
    name: "Credential Provider Filters",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "COM objects registered as credential provider filters intercept all credentials \
        flowing through the Windows authentication pipeline after collection. Unlike credential \
        providers (which supply credentials), filters receive plaintext credentials from every \
        provider — including password, smartcard, and biometric — before authentication \
        completes. A malicious filter DLL captures credentials for every interactive logon, \
        network authentication, and UAC elevation on the machine. Correlate CLSID with \
        HKCR\\CLSID\\{<value>}\\InprocServer32 to identify the DLL.",
    mitre_techniques: &["T1556.001"],
    fields: &[FieldSchema {
        name: "filter_clsid",
        value_type: ValueType::Text,
        description: "CLSID of the registered credential provider filter COM object",
        is_uid_component: true,
    }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["credential_providers", "lsa_auth_pkgs"],
    sources: &[
        "https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows",
        "https://github.com/forensicartifacts/artifacts",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Should contain zero or very few entries on a clean system — any unknown CLSID warrants immediate investigation",
        "Resolve CLSID in HKCR to find the filter DLL; compare DLL hash against known good",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicitly deleted",
};

// ── T1543.003 — Service recovery actions (FailureActions / FailureCommand) ───

/// `HKLM\SYSTEM\CurrentControlSet\Services\<service>\FailureActions` (REG_BINARY)
/// and `...\FailureCommand` (REG_SZ)
///
/// A service may carry optional `FailureActions` and `FailureCommand` entries in
/// its registry sub-key, which the Service Control Manager reads at service
/// startup. The SCM is signalled when a service process exits; when one exits
/// without reporting SERVICE_STOPPED the SCM works out which services ran in that
/// process and performs the recovery steps their entries specify — restart the
/// service, run a program, or restart the computer, each with its own delay, and
/// with a different action selectable for the first, second and subsequent
/// failures.
///
/// `FailureActions` is the serialized form of SERVICE_FAILURE_ACTIONS: a reset
/// period in seconds (INFINITE = never reset), a reboot broadcast message, a
/// command line, and an array of SC_ACTION records, each a type plus a delay in
/// milliseconds. The SC_ACTION types are 0 = SC_ACTION_NONE, 1 = SC_ACTION_RESTART,
/// 2 = SC_ACTION_REBOOT and 3 = SC_ACTION_RUN_COMMAND; only type 3 consumes
/// `FailureCommand`. The command line is handed to CreateProcess and runs under
/// the same account as the service, so the service's `ObjectName` — not the
/// analyst's assumption — determines the context.
///
/// Forensic significance: the recovery command is a code path that executes when
/// the service is made to crash, and it lives nowhere an autostart enumerator
/// looks — not in a Run key, not in `ImagePath`, and not in the scheduled-task
/// store. The failure count is kept since boot and reset after the reset period,
/// so the array index chosen depends on how many times the process has already
/// failed.
///
/// Source: <https://learn.microsoft.com/en-us/archive/technet-wiki/14774.troubleshooting-system-services>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-sc_action>
pub(crate) static SERVICE_FAILURE_ACTIONS: ArtifactDescriptor = ArtifactDescriptor {
    id: "service_failure_actions",
    name: "Service Failure Actions (FailureActions / FailureCommand)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    // Source: https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Services-and-drivers.html
    // (FailureActions listed among the values of a service's Name sub key)
    key_path: r"CurrentControlSet\Services\*",
    value_name: Some("FailureActions"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Recovery configuration the Service Control Manager applies when a service process \
exits without reporting SERVICE_STOPPED. FailureActions is the serialized SERVICE_FAILURE_ACTIONS \
structure — reset period in seconds, reboot broadcast message, command line, then an array of \
SC_ACTION records of {type, delay-in-milliseconds} where type 0 = no action, 1 = restart the \
service, 2 = reboot the computer, 3 = run a command. Type 3 executes the sibling FailureCommand \
(REG_SZ) via CreateProcess, under the same account the service logs on as (the ObjectName value). \
The SCM counts failures since boot, resets the count after the reset period, and takes element \
[N-1] for the Nth failure, repeating the last element beyond the end of the array. This is a \
distinct execution path from ImagePath: a command registered here runs only when the service is \
made to fail, so it does not appear in any Run key, in the service binary path, or in the \
scheduled-task store, and an autostart enumerator will not surface it. Recover both values from an \
offline SYSTEM hive and read FailureCommand alongside the SC_ACTION array — a FailureCommand with \
no type-3 action is inert, and a type-3 action with an empty FailureCommand runs nothing.",
    mitre_techniques: &["T1543.003", "T1543"],
    fields: &[
        FieldSchema {
            name: "failure_command",
            value_type: ValueType::Text,
            description: "FailureCommand (REG_SZ) — the command line executed for an \
                SC_ACTION_RUN_COMMAND (type 3) recovery action, run under the service's own logon \
                account. Highest-signal field: read it verbatim and resolve the binary it names",
            is_uid_component: false,
        },
        FieldSchema {
            name: "reset_period",
            value_type: ValueType::UnsignedInt,
            description: "Seconds without a failure after which the SCM resets the failure count \
                to zero; INFINITE means never reset. A long reset period keeps the actor's later \
                array element reachable indefinitely",
            is_uid_component: false,
        },
        FieldSchema {
            name: "reboot_message",
            value_type: ValueType::Text,
            description: "Broadcast message sent to server users before an SC_ACTION_REBOOT \
                (type 2) action; empty means no message is broadcast",
            is_uid_component: false,
        },
        FieldSchema {
            name: "action_type",
            value_type: ValueType::Integer,
            description: "SC_ACTION Type for each element of the action array: 0=SC_ACTION_NONE, \
                1=SC_ACTION_RESTART, 2=SC_ACTION_REBOOT, 3=SC_ACTION_RUN_COMMAND. Only 3 causes \
                FailureCommand to run; the array index used is (failure count - 1)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "action_delay",
            value_type: ValueType::UnsignedInt,
            description: "SC_ACTION Delay for the same element — milliseconds the SCM waits before \
                performing that action. Bounds how long after the crash the command appears",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until the value or the service key is deleted"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["services_hklm", "services_imagepath", "service_trigger_info"],
    sources: &[
        // Source: Microsoft — names FailureActions and FailureCommand as registry entries in a
        // service's sub key, and describes the SCM's recovery behaviour on unexpected process exit.
        "https://learn.microsoft.com/en-us/archive/technet-wiki/14774.troubleshooting-system-services",
        // Source: SERVICE_FAILURE_ACTIONSW — dwResetPeriod / lpRebootMsg / lpCommand / cActions /
        // lpsaActions, the [N-1] selection rule, and "runs under the same account as the service".
        "https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw",
        // Source: SC_ACTION — the numeric SC_ACTION_TYPE values and the millisecond Delay.
        "https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-sc_action",
        // Source: sc failure — the reset=/reboot=/command=/actions= surface that writes these values.
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742019(v=ws.11)",
        // Source: winreg-kb — FailureActions listed among the values of a service's Name sub key.
        "https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Services-and-drivers.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Legitimate services and installers configure recovery actions routinely — restart-only configurations (type 1) are the common case and are not evidence of anything",
        "A FailureCommand is inert unless some element of the action array is type 3; conversely a type-3 action with an empty FailureCommand runs no program",
        "The command runs as the service's logon account (ObjectName), which may be LocalService or NetworkService rather than LocalSystem — read ObjectName before characterising the privilege obtained",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry values under the service key; persist until explicitly removed",
};

// ── T1543.003 — Trigger-start service registration ───────────────────────────

/// Service trigger registration — `TriggerInfo` in a service's registry subtree.
///
/// A service can register trigger events with the SCM, so it starts (or stops)
/// when a specified event occurs rather than at boot or on operator demand. The
/// registration is a SERVICE_TRIGGER_INFO block of SERVICE_TRIGGER records, each
/// carrying a trigger type, an action, a subtype GUID and optional trigger-specific
/// data items; it is queried live through QueryServiceConfig2 with
/// SERVICE_CONFIG_TRIGGER_INFO, and stored in the service's registry subtree in a
/// `TriggerInfo` sub key (libyal's winreg-kb records `TriggerInfo` beneath the
/// service's `Parameters` key, so search the whole service subtree rather than one
/// fixed path).
///
/// Why it matters for triage: a trigger-registered service keeps
/// `Start` = 3 (on demand). A hunt that treats `Start` = 2 as "starts by itself"
/// therefore classifies it as operator-driven and never looks at it, while in
/// practice the SCM starts it the moment the first IP address appears on the
/// stack, a matching device arrives, the machine joins a domain, a group-policy
/// change lands, a firewall port opens, a named pipe or RPC endpoint is
/// addressed, or a chosen ETW provider emits an event.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_trigger>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_trigger_info>
pub(crate) static SERVICE_TRIGGER_INFO: ArtifactDescriptor = ArtifactDescriptor {
    id: "service_trigger_info",
    name: "Service Trigger-Start Registration (TriggerInfo)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    // Source: https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Services-and-drivers.html
    // (TriggerInfo documented as a sub key inside a service's subtree)
    key_path: r"CurrentControlSet\Services",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    // Source: SERVICE_TRIGGER — minimum supported client Windows 7.
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Trigger-event registration for a Windows service, held in a TriggerInfo sub key \
within the service's registry subtree and expressed live as SERVICE_TRIGGER_INFO / \
SERVICE_TRIGGER (QueryServiceConfig2 with SERVICE_CONFIG_TRIGGER_INFO). Each trigger carries a \
type — 1 device interface arrival, 2 first/last IP address on the TCP/IP stack, 3 domain \
join/leave, 4 firewall port open/close, 5 machine or user policy change, 6 network endpoint \
(RPC interface or named pipe), 20 custom ETW provider event — an action (1 start the service, \
2 stop it), a subtype GUID identifying the specific event, and optional Unicode data items \
narrowing the match (hardware IDs, port/protocol/executable/user, endpoint or interface GUID). \
The triage consequence is the one to carry: a trigger-registered service still reads Start=3 \
(on demand), so any sweep that equates autostart with Start=2 misses it entirely even though the \
SCM starts it without operator action. Enumerate the trigger registration for every service \
before reporting what runs on a host, and read the subtype GUID and data items — they name the \
condition, and a custom (type 20) trigger points at an ETW provider GUID rather than a \
system event.",
    mitre_techniques: &["T1543.003", "T1543"],
    fields: &[
        FieldSchema {
            name: "trigger_type",
            value_type: ValueType::Integer,
            description: "SERVICE_TRIGGER dwTriggerType: 1=device interface arrival, \
                2=IP address availability, 3=domain join/leave, 4=firewall port event, \
                5=group policy change, 6=network endpoint (RPC interface or named pipe), \
                20=custom ETW provider event. Names the condition that starts the service",
            is_uid_component: false,
        },
        FieldSchema {
            name: "trigger_action",
            value_type: ValueType::Integer,
            description: "SERVICE_TRIGGER dwAction: 1=SERVICE_TRIGGER_ACTION_SERVICE_START, \
                2=SERVICE_TRIGGER_ACTION_SERVICE_STOP. Network-endpoint triggers (type 6) must \
                be start-only",
            is_uid_component: false,
        },
        FieldSchema {
            name: "trigger_subtype_guid",
            value_type: ValueType::Guid,
            description: "SERVICE_TRIGGER pTriggerSubtype — the specific event. For type 20 it is \
                the ETW provider GUID; for type 1 the device interface class GUID; otherwise one \
                of the documented constants, e.g. DOMAIN_JOIN_GUID \
                {1ce20aba-9851-4421-9430-1ddeb766e809}, \
                NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID \
                {4f27f2de-14e2-430b-a549-7cd48cbc8245}, NAMED_PIPE_EVENT_GUID \
                {1F81D131-3FAC-4537-9E0C-7E7B0C2F4B55}, RPC_INTERFACE_EVENT_GUID \
                {BC90D167-9470-4139-A9BA-BE0BBBF5B74D}",
            is_uid_component: false,
        },
        FieldSchema {
            name: "trigger_data",
            value_type: ValueType::Text,
            description: "SERVICE_TRIGGER_SPECIFIC_DATA_ITEM contents narrowing the match — \
                hardware/compatible ID strings for a device trigger, the NUL-separated \
                port/protocol/executable-path/user tuple for a firewall-port trigger, or the \
                endpoint/interface GUID for a network-endpoint trigger. Every string must match \
                for a firewall-port trigger to fire",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until the trigger registration or the service key is removed"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["services_hklm", "service_failure_actions", "services_imagepath"],
    sources: &[
        // Source: SERVICE_TRIGGER — the numeric trigger types, the two actions, the subtype GUID
        // constants, and what pDataItems carries per type.
        "https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_trigger",
        // Source: SERVICE_TRIGGER_INFO — the containing structure used with
        // ChangeServiceConfig2 / QueryServiceConfig2 (SERVICE_CONFIG_TRIGGER_INFO).
        "https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_trigger_info",
        // Source: winreg-kb — TriggerInfo documented as a sub key inside a service's subtree,
        // alongside the Start value enumeration that makes a trigger-started service read as 3.
        "https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Services-and-drivers.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Trigger-start is ordinary Windows design — many in-box services are registered this way; the registration is context for when a service runs, not an indicator by itself",
        "winreg-kb records TriggerInfo beneath the service's Parameters key; search the whole service subtree rather than assuming one fixed path, and confirm against QueryServiceConfig2 output on a live host",
        "Absence of a trigger registration does not mean the service never starts unattended — Start and service dependencies still apply",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry sub key under the service key; persists until the registration is removed",
};

// ── System Restore snapshot scoping ──────────────────────────────────────────

/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore`
///
/// Two DWORD values under this key decide what a shadow copy of the boot volume
/// is worth as evidence and how often one exists at all. Neither is present on a
/// default install — applications are expected to create them.
///
/// `ScopeSnapshots`: from Windows 8, System Restore monitors only those boot-volume
/// files that are relevant to system restore. Setting the value to 0 makes System
/// Restore create boot-volume snapshots the way earlier Windows versions did.
/// **Deleting the value does not undo the setting — it restores the scoped
/// behaviour**, which is the opposite of the intuitive reading and is the reason
/// this value is worth recording verbatim rather than as present/absent.
///
/// `SystemRestorePointCreationFrequency`: when an application calls
/// SRSetRestorePoint, Windows skips creating a restore point if one was created in
/// the previous N minutes, N being this value; 0 disables the skip. With the value
/// absent the default applies — a restore point requested within 24 hours of the
/// last one is skipped and the earlier sequence number is returned with
/// ERROR_SUCCESS, so the call *looks* successful and no new snapshot exists.
///
/// Microsoft also documents an evidence-destruction hazard on the same page: a
/// boot-volume snapshot created by System Restore on Windows 8 may be deleted if
/// that snapshot is subsequently exposed by an earlier version of Windows.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/srrestoreptapi/nf-srrestoreptapi-srsetrestorepointa>
pub(crate) static SYSTEM_RESTORE_SCOPE_SNAPSHOTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "system_restore_scope_snapshots",
    name: "System Restore Snapshot Scoping (ScopeSnapshots)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    // Source: https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/System-restore.html
    key_path: r"Microsoft\Windows NT\CurrentVersion\SystemRestore",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win8Plus,
    decoder: Decoder::DwordLe,
    meaning: "Configuration that governs what a System Restore snapshot of the boot volume \
contains and how often one is created. From Windows 8, System Restore monitors only the \
boot-volume files relevant to system restore; the ScopeSnapshots DWORD set to 0 returns it to the \
earlier behaviour of snapshotting the boot volume as previous Windows versions did. Deleting the \
value RESUMES the scoped behaviour rather than undoing it — the inverse of the intuitive reading, \
and the reason to record the value as present-and-0, present-and-nonzero, or absent rather than as \
a boolean. SystemRestorePointCreationFrequency (DWORD, minutes) makes SRSetRestorePoint skip \
creating a restore point when one was created within the previous N minutes; 0 disables the skip, \
and with the value absent the default 24-hour skip applies — the call returns TRUE with the \
earlier restore point's sequence number, so a scheduled job that drives System Restore can appear \
to succeed while producing no new snapshot. Examiner consequence: on a Win8+ host with \
ScopeSnapshots absent or non-zero, treat a boot-volume shadow copy as a System-Restore-scoped \
view, not a full point-in-time image of user data, and establish recoverability per file rather \
than assuming it. Microsoft additionally documents that a Windows 8 boot-volume snapshot may be \
DELETED if it is subsequently exposed by an earlier version of Windows — an evidence-destruction \
hazard when a subject image is mounted on an older analysis host.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema {
            name: "scope_snapshots",
            value_type: ValueType::UnsignedInt,
            description: "ScopeSnapshots DWORD. 0 = System Restore snapshots the boot volume as \
                earlier Windows versions did. Absent (the default — the value does not preexist) \
                or deleted = scoped snapshots that monitor only files relevant to system restore. \
                Record which of the three states applies; deleting the value re-enables scoping \
                rather than reverting it",
            is_uid_component: false,
        },
        FieldSchema {
            name: "system_restore_point_creation_frequency",
            value_type: ValueType::UnsignedInt,
            description: "SystemRestorePointCreationFrequency DWORD, in minutes. N = a requested \
                restore point is skipped if one was created in the previous N minutes; 0 = never \
                skip. Absent = default 24-hour skip, in which case SRSetRestorePoint returns TRUE \
                and the PREVIOUS sequence number with ERROR_SUCCESS — governs how dense the \
                restore-point timeline can be",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until the value is modified or deleted"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["vss_snapshot_analysis", "vss_files_not_to_snapshot", "vss_files_not_to_backup"],
    sources: &[
        // Source: SRSetRestorePoint Remarks — documents the ScopeSnapshots DWORD, its location,
        // the 0 semantics, the delete-resumes-scoping behaviour,
        // SystemRestorePointCreationFrequency, and the older-Windows snapshot-deletion hazard.
        "https://learn.microsoft.com/en-us/windows/win32/api/srrestoreptapi/nf-srrestoreptapi-srsetrestorepointa",
        // Source: winreg-kb — the SystemRestore key location.
        "https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/System-restore.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Neither value exists on a default installation, so absence is the normal state and carries the scoped-snapshot default — it is not evidence of tampering",
        "The value describes snapshot SCOPE, not whether a given file is recoverable; confirm recoverability against the snapshot itself rather than inferring it from the setting",
        "Exposing a Windows 8 boot-volume snapshot from an earlier Windows version may delete it — treat an older analysis host as a destructive environment for such snapshots",
        "Backup and imaging products legitimately create the value; an explicit 0 shows coverage was widened, not who widened it or why",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry values; persist until explicitly modified or deleted",
};

// ── T1112 / T1021.002 — UAC remote restriction ───────────────────────────────

/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`
///
/// UAC applies restrictions over the network to members of the local
/// Administrators group. A user holding a local (SAM) account that is a member of
/// the local Administrators group on the target does not connect as a full
/// administrator over a remote administrative connection — the token is filtered
/// and the account has no elevation potential remotely. Domain accounts in the
/// Administrators group are not filtered this way.
///
/// `LocalAccountTokenFilterPolicy` (REG_DWORD) selects between the two: 0 — the
/// default — builds a filtered token with the administrator credentials removed;
/// 1 builds an elevated token, disabling UAC remote restrictions.
///
/// Read from an offline SOFTWARE hive the value is two things at once: a
/// capability fact (whether a non-domain local admin account could be used
/// remotely at all on this host), and a configuration-change indicator worth
/// dating against the key's last-write time. The value does not exist on a
/// default install.
///
/// Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction>
pub(crate) static UAC_REMOTE_RESTRICTION_POLICY: ArtifactDescriptor = ArtifactDescriptor {
    id: "uac_remote_restriction_policy",
    name: "UAC Remote Restriction (LocalAccountTokenFilterPolicy)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    // Source: KB951016 — the exact subkey named in the procedure.
    key_path: r"Microsoft\Windows\CurrentVersion\Policies\System",
    value_name: Some("LocalAccountTokenFilterPolicy"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::DwordLe,
    meaning: "REG_DWORD that turns UAC remote restrictions off. With the default behaviour (value \
0 or absent), a member of the local Administrators group connecting remotely with a local SAM \
account receives a FILTERED token: the administrator credentials are removed, the account has no \
elevation potential on the remote computer, and administrative tasks over that connection fail — \
administering the machine with a SAM account requires an interactive logon such as Remote Desktop \
or Remote Assistance instead. Setting the value to 1 builds an ELEVATED token, and local \
administrator accounts become usable for remote administration. Domain accounts in the \
Administrators group are unaffected: they already run with a full administrator token remotely. \
Because the value is read straight out of an offline SOFTWARE hive it is a checkable host fact, \
not a live-only setting — it answers 'could a non-domain local admin account have been used \
against this host remotely', and its presence on a host where no administrator set it is a \
configuration change to date against the Policies\\System key last-write time. The built-in \
(RID 500) Administrator account is governed separately by the Admin Approval Mode policy for that \
account, which is Disabled by default.",
    mitre_techniques: &["T1112", "T1021.002"],
    fields: &[FieldSchema {
        name: "local_account_token_filter_policy",
        value_type: ValueType::UnsignedInt,
        description: "0 (default) = filtered token — local-account administrator credentials are \
            removed on a remote administrative connection; 1 = elevated token — UAC remote \
            restrictions disabled and local admin accounts usable remotely. Absent means the \
            default applies; record absent and 0 distinctly, since only an explicit write leaves \
            a key last-write timestamp to date",
        is_uid_component: false,
    }],
    retention: Some("Persistent until the value is modified or deleted"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["rdp_enable_registry", "special_accounts_userlist", "nirsoft_sam_hive_reg"],
    sources: &[
        // Source: KB951016 — how UAC remote restrictions work for SAM vs domain accounts, the
        // exact subkey and value name, and the 0/1 value table.
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction",
        // Source: the separate policy governing the built-in Administrator account's
        // Admin Approval Mode, including its Disabled default.
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-account-control-admin-approval-mode-for-the-built-in-administrator-account",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Management tooling and remote-administration setup legitimately set this value — the value alone establishes capability, not intent; date it against the key last-write time and corroborate with logon records",
        "Absence is the default and is not the same as an explicit 0: only an explicit write moves the Policies\\System key last-write timestamp",
        "It does not govern domain accounts, which already receive a full administrator token remotely — a 0 here does not mean the host was unreachable for administration",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicitly modified or deleted",
};

// ── T1557.001 / T1110.002 — LAN Manager authentication level ─────────────────

/// `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel`
///
/// The registry value behind the "Network security: LAN Manager authentication
/// level" policy. It decides which challenge/response protocol is used for
/// network logons — which variants the client sends, the session security
/// negotiated, and which variants a server or domain controller will accept.
///
/// Levels 0–5 run from "send LM & NTLM responses, accept all three" through to
/// "send NTLMv2 only, refuse LM and NTLM". The value is the precondition an
/// examiner needs when reasoning about a captured or relayed authentication: a
/// host configured below level 3 still sends NTLMv1, and an authentication a host
/// will not send cannot have been captured from it.
///
/// It reads directly from an offline SYSTEM hive, so it is a checkable
/// configuration fact rather than a live-only setting. Where no value is written,
/// the effective default applies (stand-alone servers, domain controllers and
/// member servers default to "send NTLMv2 response only"; on client computers the
/// policy is not defined).
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level>
pub(crate) static LSA_LM_COMPATIBILITY_LEVEL: ArtifactDescriptor = ArtifactDescriptor {
    id: "lsa_lm_compatibility_level",
    name: "LAN Manager Authentication Level (LmCompatibilityLevel)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Lsa",
    value_name: Some("LmCompatibilityLevel"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::DwordLe,
    meaning: "REG_DWORD (0-5) selecting the challenge/response authentication protocol used for \
network logons: which variant client devices send, the session security they negotiate, and which \
variants domain controllers accept. 0 = send LM & NTLM, never NTLMv2 session security, accept LM, \
NTLM and NTLMv2. 1 = send LM & NTLM, use NTLMv2 session security when negotiated, accept all \
three. 2 = send NTLM response only (NTLMv1 authentication), accept all three. 3 = send NTLMv2 \
response only, accept all three. 4 = send NTLMv2 only, refuse LM. 5 = send NTLMv2 only, refuse LM \
and NTLM. Forensic use: it is the host-side precondition for any claim about a captured or relayed \
authentication — a host at level 3 or above does not emit an NTLMv1 response, so an NTLMv1 \
exchange attributed to it needs another explanation, while a host at 0-2 does emit one. Read \
straight from an offline SYSTEM hive alongside the Lsa provider lists (Authentication Packages, \
Security Packages, Notification Packages). Where the value is absent the effective default \
applies: stand-alone servers, domain controllers and member servers default to send-NTLMv2-only, \
and on client computers the policy is not defined. Changes take effect without a restart, so the \
value at acquisition time may post-date the activity under examination. A companion policy \
governs whether the weaker LM hash is stored at the next password change.",
    mitre_techniques: &["T1557.001", "T1110.002"],
    fields: &[FieldSchema {
        name: "lm_compatibility_level",
        value_type: ValueType::UnsignedInt,
        description: "0=send LM & NTLM; 1=send LM & NTLM, NTLMv2 session security if negotiated; \
            2=send NTLM response only; 3=send NTLMv2 response only; 4=send NTLMv2 only, DC refuses \
            LM; 5=send NTLMv2 only, DC refuses LM and NTLM. Below 3 the host still sends NTLMv1; \
            at 3 and above it does not. Absent = effective default (send NTLMv2 only on \
            stand-alone servers, DCs and member servers; not defined on client computers)",
        is_uid_component: false,
    }],
    retention: Some("Persistent until the value is modified; takes effect without a restart"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[
        "lsa_auth_packages",
        "lsa_security_packages",
        "lsa_notification_packages",
        "velociraptor_securityproviders_wdigest",
    ],
    sources: &[
        // Source: the policy reference — the 0-5 registry security levels with per-level client
        // and domain-controller behaviour, the HKLM\System\CurrentControlSet\Control\Lsa
        // \LmCompatibilityLevel location, the default table, and the no-restart note.
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level",
        // Source: the companion policy on storing the LAN Manager hash at the next password change.
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Changes take effect without a restart, so the acquired value describes the host at acquisition time, not necessarily at the time of the authentication being examined",
        "Absence is common and means the effective default applies — which differs between client computers and servers; do not report absence as level 0",
        "The value constrains what the host sends and accepts; it does not evidence that any particular authentication occurred",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicitly modified",
};

// ── Crash dump configuration ─────────────────────────────────────────────────

/// `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl`
///
/// The key that says whether a memory dump should exist at all, which type was
/// configured, and where it was redirected. Without it, the absence of
/// `%SystemRoot%\MEMORY.DMP` is ambiguous between "the machine never crashed",
/// "dumps were disabled" and "the dump went somewhere else" — and there is no way
/// to tell from the hive whether a full-RAM dump was ever obtainable.
///
/// `CrashDumpEnabled` (REG_DWORD): 0 none, 1 complete memory dump, 2 kernel
/// memory dump, 3 small memory dump (64 KB), 7 automatic memory dump. An active
/// memory dump is `CrashDumpEnabled` = 1 together with `FilterPages` = 1.
/// `DumpFile` and `MinidumpDir` (both REG_EXPAND_SZ) hold the destinations,
/// defaulting to `%SystemRoot%\Memory.dmp` and `%SystemRoot%\Minidump`;
/// `Overwrite`, `AutoReboot`, `LogEvent` and `SendAlert` are DWORDs.
///
/// Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options>
/// Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/configure-system-failure-and-recovery-options>
pub(crate) static CRASH_CONTROL: ArtifactDescriptor = ArtifactDescriptor {
    id: "crash_control",
    name: "Crash Dump Configuration (Control\\CrashControl)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\CrashControl",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Startup-and-recovery configuration governing memory dump creation on a bug check. \
CrashDumpEnabled (REG_DWORD) selects the dump type: 0 = none, 1 = complete memory dump (all of \
physical memory, and it may contain data from processes that were running), 2 = kernel memory \
dump, 3 = small memory dump (64 KB), 7 = automatic memory dump; an active memory dump is \
CrashDumpEnabled=1 with FilterPages=1. DumpFile (REG_EXPAND_SZ, default \
%SystemRoot%\\Memory.dmp) and MinidumpDir (REG_EXPAND_SZ, default %SystemRoot%\\Minidump) hold \
the destinations, and Overwrite, AutoReboot, LogEvent and SendAlert are DWORDs. Read this key \
BEFORE concluding anything from the presence or absence of a dump file: a missing MEMORY.DMP \
means 'no crash' only if dumps were enabled and not redirected, and the key is also how an \
examiner establishes, from the hive alone, whether a full-RAM capture was ever obtainable from \
this host — CrashDumpEnabled=1 is the only setting that would have produced one. Small dumps \
accumulate under MinidumpDir with the date encoded in each filename (e.g. Mini022900-01.dmp) \
while kernel and complete dumps overwrite a single file when Overwrite is set, so the dump type \
also determines whether a history or a single latest artifact is expected on disk. Pair with \
windows_crash_dump and windows_minidump, which describe the files themselves.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema {
            name: "crash_dump_enabled",
            value_type: ValueType::UnsignedInt,
            description: "CrashDumpEnabled REG_DWORD: 0=none, 1=complete memory dump, 2=kernel \
                memory dump, 3=small memory dump (64 KB), 7=automatic memory dump. Only 1 (with \
                FilterPages unset) would have captured all of physical memory",
            is_uid_component: false,
        },
        FieldSchema {
            name: "filter_pages",
            value_type: ValueType::UnsignedInt,
            description: "FilterPages REG_DWORD. With CrashDumpEnabled=1, a value of 1 selects an \
                ACTIVE memory dump rather than a complete one — pages judged irrelevant to \
                troubleshooting are filtered out, so it is not a full image of physical memory",
            is_uid_component: false,
        },
        FieldSchema {
            name: "dump_file",
            value_type: ValueType::Text,
            description: "DumpFile REG_EXPAND_SZ — path for the kernel/complete/automatic/active \
                dump, default %SystemRoot%\\Memory.dmp. A redirected path is where to look before \
                reporting that no dump exists",
            is_uid_component: false,
        },
        FieldSchema {
            name: "minidump_dir",
            value_type: ValueType::Text,
            description: "MinidumpDir REG_EXPAND_SZ — directory holding small memory dumps, \
                default %SystemRoot%\\Minidump. Each small dump is a new file with the date in \
                its name, so this directory carries a crash history",
            is_uid_component: false,
        },
        FieldSchema {
            name: "overwrite",
            value_type: ValueType::UnsignedInt,
            description: "Overwrite REG_DWORD. 1 = a later kernel or complete dump overwrites the \
                previous file at the same path; 0 = the previous file is kept. Decides whether \
                the dump on disk is the latest crash or the first",
            is_uid_component: false,
        },
        FieldSchema {
            name: "auto_reboot",
            value_type: ValueType::UnsignedInt,
            description: "AutoReboot REG_DWORD — 1 restarts the computer automatically after the \
                bug check. Explains an unattended reboot in the timeline that has no operator \
                behind it",
            is_uid_component: false,
        },
        FieldSchema {
            name: "log_event",
            value_type: ValueType::UnsignedInt,
            description: "LogEvent REG_DWORD — 1 records the system error in the System event log. \
                When 0, a crash may leave no event-log trace to correlate the dump against",
            is_uid_component: false,
        },
        FieldSchema {
            name: "send_alert",
            value_type: ValueType::UnsignedInt,
            description: "SendAlert REG_DWORD — 1 notifies administrators of the system error \
                where administrative alerts are configured",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until modified; changes take effect after a restart"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["windows_crash_dump", "windows_minidump"],
    sources: &[
        // Source: the CrashControl value list — CrashDumpEnabled 0/1/2/3/7, the
        // CrashDumpEnabled=1 + FilterPages=1 active-dump combination, and the
        // AutoReboot / DumpFile / LogEvent / MinidumpDir / Overwrite / SendAlert defaults.
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options",
        // Source: each Startup-and-Recovery option mapped to its CrashControl value.
        "https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/configure-system-failure-and-recovery-options",
        // Source: what each dump variety does and does not contain.
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Changes require a restart to take effect, so the configured value may not be the one that applied to an existing dump file — date the dump against the key last-write time",
        "A dump is also gated by paging-file size and free space on the destination volume; a correct CrashDumpEnabled does not guarantee a dump was written",
        "Enterprise build images and OEM configurations routinely disable or redirect dumps — a 0 here is a configuration fact, not an anti-forensic finding",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry values; persist until explicitly modified",
};

// ── Windows build identification ─────────────────────────────────────────────

/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` — build identification.
///
/// The value set that answers "which Windows build produced this image", read
/// from the SOFTWARE hive rather than from a running system. The catalog already
/// carries `InstallDate` on this key (`windows_install_date`); this entry covers
/// the identification values beside it.
///
/// Three of them are routinely conflated, and the distinction is the reason this
/// descriptor exists:
///
/// - `CurrentBuild` / `CurrentBuildNumber` — the base build of the release
///   (e.g. `19041`). This is what a memory-analysis profile keyed on a build
///   number matches.
/// - `UBR` — the update build revision, the component after the dot in an OS
///   build such as `19041.1237`. It moves with the cumulative update, which is
///   what a Settings panel reports and what the base build alone cannot tell you.
/// - `BuildLab` — the build-lab stamp of the base build. It identifies the build
///   and branch, not the cumulative-update level.
///
/// `CurrentVersion` is a further trap: Microsoft's own `Get-ComputerInfo` example
/// shows `WindowsCurrentVersion : 6.3` on a host whose `OsVersion` is
/// `10.0.19043`, so the major/minor pair is not the OS generation. Read the
/// generation from the build number and map it with the release-information
/// table.
///
/// Source: <https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Windows-product-information.html>
/// Source: <https://learn.microsoft.com/en-us/windows/release-health/release-information>
pub(crate) static WINDOWS_BUILD_IDENTIFICATION: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_build_identification",
    name: "Windows Build Identification (Windows NT\\CurrentVersion)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "The product and build values an examiner needs to state which Windows build produced \
an image, read from an offline SOFTWARE hive: ProductName, CurrentVersion (major.minor), \
CurrentBuild and CurrentBuildNumber, UBR, BuildLab, ProductId, RegisteredOwner and \
RegisteredOrganization. The load-bearing distinction is between the three build-ish values. \
CurrentBuild/CurrentBuildNumber is the BASE build of the release and is what a build-keyed memory \
profile matches. UBR is the update build revision — the component after the dot in an OS build \
such as 19041.1237 — and it tracks the monthly cumulative rollup, so it is the value that moves \
when the base build does not. BuildLab stamps the build and branch of the base build and likewise \
does not track cumulative updates. Consequently a Settings panel reporting build.revision, a \
kernel build-lab string, and a memory profile keyed on the base build alone are three \
non-contradictory readings of the same host, and reconciling them needs all three values rather \
than one. CurrentVersion is a separate trap: Microsoft's own Get-ComputerInfo example shows \
WindowsCurrentVersion 6.3 on a host whose OsVersion is 10.0.19043, so the major/minor pair is not \
the OS generation — derive the generation from the build number and map it through the release \
information table. Pair with windows_install_date on the same key, bearing its Feature-Update \
reset caveat in mind.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema {
            name: "product_name",
            value_type: ValueType::Text,
            description: "ProductName REG_SZ — the product name, e.g. 'Microsoft Windows XP'. \
                A marketing label: establish the OS generation from the build number, not from \
                this string",
            is_uid_component: true,
        },
        FieldSchema {
            name: "current_build_number",
            value_type: ValueType::Text,
            description: "CurrentBuildNumber REG_SZ — the base build number of the release \
                (e.g. 2600, 19041). The value a build-keyed memory profile or symbol lookup \
                matches; it does not move with cumulative updates",
            is_uid_component: true,
        },
        FieldSchema {
            name: "current_build",
            value_type: ValueType::Text,
            description: "CurrentBuild REG_SZ — historically an obsolete form (e.g. 1.511.1); on \
                modern releases it carries the same base build as CurrentBuildNumber. Record both \
                and note any disagreement rather than picking one",
            is_uid_component: false,
        },
        FieldSchema {
            name: "ubr",
            value_type: ValueType::UnsignedInt,
            description: "UBR (update build revision) REG_DWORD — the revision component after the \
                dot in an OS build such as 19041.1237, reflecting the current monthly rollup. \
                Combine as CurrentBuild + '.' + UBR to state the full build an examiner can match \
                against the published release-information table",
            is_uid_component: false,
        },
        FieldSchema {
            name: "build_lab",
            value_type: ValueType::Text,
            description: "BuildLab REG_SZ — the build-lab/branch stamp of the base build. It \
                identifies which build was installed, NOT the cumulative-update level; a BuildLab \
                that disagrees with an expected patch level is the expected behaviour, not a \
                discrepancy",
            is_uid_component: false,
        },
        FieldSchema {
            name: "current_version",
            value_type: ValueType::Text,
            description: "CurrentVersion REG_SZ — major and minor version (e.g. 5.1). Frozen \
                relative to the OS generation on modern releases: Microsoft's Get-ComputerInfo \
                example shows 6.3 on a host whose OS version is 10.0.19043. Never derive the OS \
                generation from this value",
            is_uid_component: false,
        },
        FieldSchema {
            name: "product_id",
            value_type: ValueType::Text,
            description: "ProductId REG_SZ — the installation's product identifier. Useful for \
                tying an image to a specific installation, and for matching against other hosts \
                built from the same media",
            is_uid_component: false,
        },
        FieldSchema {
            name: "registered_owner",
            value_type: ValueType::Text,
            description: "RegisteredOwner REG_SZ (with RegisteredOrganization) — the name supplied \
                at installation. Attribution-adjacent and freely chosen, so it names whoever set \
                up the install or the image it was cloned from, not necessarily the user",
            is_uid_component: false,
        },
        FieldSchema {
            name: "csd_version",
            value_type: ValueType::Text,
            description: "CSDVersion REG_SZ — service pack level on releases that used service \
                packs; absent on releases that ship cumulative updates instead",
            is_uid_component: false,
        },
        FieldSchema {
            name: "system_root",
            value_type: ValueType::Text,
            description: "SystemRoot REG_SZ (and PathName) — the Windows directory, the value \
                behind %SystemRoot%. Needed to resolve the REG_EXPAND_SZ paths in other \
                descriptors against an offline image",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent; build values are rewritten by upgrades and feature updates"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["windows_install_date", "cbs_log", "setupapi_upgrade_log"],
    sources: &[
        // Source: winreg-kb — the CurrentVersion key value table (BuildLab, CSDVersion,
        // CurrentBuild, CurrentBuildNumber, CurrentVersion, ProductId, ProductName,
        // RegisteredOwner/Organization, SystemRoot, PathName) with types and meanings.
        "https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Windows-product-information.html",
        // Source: the published version-to-OS-build table, where builds are given in the
        // base-build.revision form that CurrentBuild and UBR reconstruct.
        "https://learn.microsoft.com/en-us/windows/release-health/release-information",
        // Source: Microsoft support answer describing UBR as the current monthly rollup revision.
        "https://learn.microsoft.com/en-us/archive/msdn-technet-forums/cadee4de-24d0-403e-9f3e-75868abf8f34",
        // Source: Get-ComputerInfo sample output showing WindowsCurrentVersion 6.3 alongside
        // OsVersion 10.0.19043 — the major/minor-is-not-the-generation trap.
        "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-computerinfo",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Upgrades and feature updates rewrite these values, so they describe the build at acquisition, not the build in place at the time of the activity under examination",
        "CurrentVersion (major.minor) does not track the OS generation on modern releases — reading it as the version is a documented trap, not an edge case",
        "BuildLab identifies the base build and branch and does not move with monthly cumulative updates; only UBR does, so the two disagreeing is normal",
        "Cloned or imaged deployments share ProductId, RegisteredOwner and RegisteredOrganization across every host built from the same media",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry values; persist until an upgrade or feature update rewrites them",
};

// ── T1125 / T1123 — Capability Access Manager ConsentStore ───────────────────

/// `…\CurrentVersion\CapabilityAccessManager\ConsentStore\<capability>\…`
///
/// Windows records, per privacy-protected capability (webcam, microphone,
/// location and others), the most recent access by each application: a
/// `LastUsedTimeStart` and a `LastUsedTimeStop`, both FILETIME. Packaged
/// applications appear as child keys named by package family; everything else —
/// which is usually what an investigation cares about — appears under a
/// `NonPackaged` child key, named by the executable's full path with `#`
/// substituted for each `\`.
///
/// The key exists in both the SOFTWARE hive and per-user (NTUSER.DAT /
/// `HKEY_USERS\<SID>`); collection tooling globs both, and an entry present in one
/// is not necessarily present in the other. It appears from Windows 10 1903
/// onward.
///
/// Forensic value: it ties a named binary to camera or microphone use and gives
/// the session duration as stop minus start — including for a binary that reached
/// the device through an implant rather than a UI. Only the LAST session per
/// application is retained; a history requires separate monitoring of writes to
/// these keys.
///
/// Source: <https://dfir.pubpub.org/pub/nm5b39ae>
/// Source: <https://docs.velociraptor.app/exchange/artifacts/pages/windows.registry.capabilityaccessmanager/>
pub(crate) static CAPABILITY_ACCESS_MANAGER_CONSENT_STORE: ArtifactDescriptor = ArtifactDescriptor {
    id: "capability_access_manager_consent_store",
    name: "Capability Access Manager ConsentStore (Webcam / Microphone / Location Use)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore",
    value_name: None,
    file_path: None,
    // Present in both the SOFTWARE hive and per-user NTUSER.DAT / HKEY_USERS\<SID>.
    scope: DataScope::Mixed,
    // Source: DFIR Review article — observed in Windows 10 1903 and later.
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Per-capability record of the most recent access to a privacy-protected resource — \
webcam, microphone, location and others — by each application. Under \
ConsentStore\\<capability>, packaged applications are child keys named by package family and \
everything else lives under a NonPackaged child key whose key names are executable full paths \
with '#' substituted for each backslash. Each entry carries LastUsedTimeStart and \
LastUsedTimeStop as FILETIME values, so the session duration is stop minus start; that is how an \
examiner establishes that a specific binary held the camera or microphone and for how long. The \
mechanism is agnostic to how the device was reached: a post-exploitation module that records \
audio or grabs the camera populates an entry from the path it ran as, exactly like a chat \
client. Collect BOTH locations — the SOFTWARE hive and the per-user NTUSER.DAT / \
HKEY_USERS\\<SID> copy — since an application may be recorded in one and not the other. Present \
from Windows 10 1903 onward. Only the LAST session per application is retained; building a \
history of every session requires separate monitoring of writes to these keys (registry-modify \
telemetry), not the hive alone. A path recorded as a generic host process (rundll32 and the like) \
identifies the loader, not the payload — treat it as a lead and resolve what it loaded.",
    mitre_techniques: &["T1125", "T1123"],
    fields: &[
        FieldSchema {
            name: "capability",
            value_type: ValueType::Text,
            description: "The ConsentStore child key naming the protected resource — webcam, \
                microphone, location and others. Determines which device the entry is about",
            is_uid_component: true,
        },
        FieldSchema {
            name: "application",
            value_type: ValueType::Text,
            description: "The entry key name: a package family name for packaged applications, or \
                — under NonPackaged — the executable's full path with '#' in place of each \
                backslash. Reverse the substitution before matching against the file system",
            is_uid_component: true,
        },
        FieldSchema {
            name: "last_used_time_start",
            value_type: ValueType::Timestamp,
            description: "LastUsedTimeStart FILETIME — when this application most recently began \
                using the capability. Only the latest session survives; an earlier access by the \
                same application is gone",
            is_uid_component: false,
        },
        FieldSchema {
            name: "last_used_time_stop",
            value_type: ValueType::Timestamp,
            description: "LastUsedTimeStop FILETIME — when that session ended. Stop minus start is \
                the session duration, which is the figure that answers 'how long was the camera or \
                microphone live'",
            is_uid_component: false,
        },
    ],
    retention: Some("Only the most recent session per application per capability is retained; overwritten on next use"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "kape_file_capabilityaccessmanager_capabilityaccessmanager_db",
        "userassist_exe",
        "windows_timeline",
    ],
    sources: &[
        // Source: peer-reviewed DFIR Review article — the ConsentStore\webcam and
        // ConsentStore\microphone key paths, the NonPackaged child key with '#' substituted for
        // '\', the LastUsedTimeStart/LastUsedTimeStop FILETIME pair, the 1903-and-later
        // observation, and that only the last session is retained without extra monitoring.
        "https://dfir.pubpub.org/pub/nm5b39ae",
        // Source: Velociraptor artifact — the HKLM and HKEY_USERS globs, the NonPackaged scope,
        // and the FILETIME decoding of both values.
        "https://docs.velociraptor.app/exchange/artifacts/pages/windows.registry.capabilityaccessmanager/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Only the most recent session per application is kept — an absent entry means no retained record, never that the application did not use the device",
        "An entry evidences that the named binary held the capability, not what was captured or whether anything was recorded to disk",
        "Entries appear in the SOFTWARE hive, the per-user hive, or both; collecting only one location under-reports the set of applications",
        "A generic host process path (e.g. rundll32) names the loader rather than the code that ran — resolve what it loaded before attributing the access",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Each new access overwrites that application's timestamps; the retained record degrades with ordinary use",
};

// ── Explorer Programs Cache ──────────────────────────────────────────────────

/// `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2` (and
/// `…\StartPage` on older releases)
///
/// `ProgramsCache` is a REG_BINARY value holding a versioned list of entries,
/// each of which is a shell item list — the same format family as the shell items
/// in BagMRU/ShellBags, so an existing shell-item decoder reads it. On Windows 7
/// the `StartPage2` key adds two siblings: `ProgramsCacheSMP` for applications
/// pinned to the Start Menu and `ProgramsCacheTBP` for applications pinned to the
/// Taskband, whose data format differs slightly from `ProgramsCache`.
///
/// The value data begins with a format version — 0x09 on Windows XP/2003, 0x0c on
/// Vista, 0x13 on Windows 7/2008 — with the Vista and Windows 7 headers followed
/// by the FOLDERID_StartMenu known-folder GUID
/// {c3535b62-48ab-c14e-ba1f-a1ef4146fc19}. Entries then follow as a size plus a
/// shell item list plus a sentinel byte.
///
/// Forensic value: a per-user record of Start Menu and taskbar program entries,
/// carrying the shell-item metadata (names, MFT entry references and timestamps
/// where the shell items hold them) rather than a bare path list, which makes it a
/// cross-check on UserAssist and FeatureUsage for programs that a taskbar-centric
/// artifact would otherwise miss.
///
/// Source: <https://winreg-kb.readthedocs.io/en/latest/sources/explorer-keys/Program-cache.html>
/// Source: <https://github.com/libyal/libfwsi>
pub(crate) static EXPLORER_PROGRAMS_CACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "explorer_programs_cache",
    name: "Explorer Programs Cache (StartPage / StartPage2)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    // Source: winreg-kb — StartPage seen on XP/2003/Vista, StartPage2 on Windows 7.
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Per-user binary cache of Start Menu and taskbar program entries. ProgramsCache \
(REG_BINARY) lives under Explorer\\StartPage on Windows XP, 2003 and Vista and under \
Explorer\\StartPage2 on Windows 7; on StartPage2 it is joined by ProgramsCacheSMP (applications \
pinned to the Start Menu) and ProgramsCacheTBP (applications pinned to the Taskband), whose data \
format differs slightly from ProgramsCache. The value data opens with a format version — 0x09 on \
XP/2003, 0x0c on Vista, 0x13 on Windows 7/2008 — the Vista and Windows 7 headers carrying the \
FOLDERID_StartMenu known-folder GUID {c3535b62-48ab-c14e-ba1f-a1ef4146fc19}, followed by entries \
of {entry data size, shell item list, sentinel byte}. Because the entries are SHELL ITEM LISTS, \
the same decoder used for BagMRU/ShellBags parses them, and the recovered entries carry shell-item \
metadata rather than bare strings. Analyst use: it is a per-user view of which programs the Start \
Menu and taskband referenced, which makes it a cross-check on UserAssist (desktop and Start Menu \
launches) and FeatureUsage (taskbar interaction counters) — three independently maintained \
records of program presence that can be compared rather than one relied upon. Parse all three \
values where present; ProgramsCacheSMP and ProgramsCacheTBP name what the user deliberately \
pinned, which is a different claim from what was merely run.",
    mitre_techniques: &["T1204.002"],
    fields: &[
        FieldSchema {
            name: "format_version",
            value_type: ValueType::UnsignedInt,
            description: "First 4 bytes of the value data: 0x09 = Windows XP/2003, 0x0c = Vista, \
                0x13 = Windows 7/2008 for ProgramsCache; 0x01 for ProgramsCacheSMP and \
                ProgramsCacheTBP. Selects the header layout — parse it before anything else",
            is_uid_component: false,
        },
        FieldSchema {
            name: "known_folder_identifier",
            value_type: ValueType::Guid,
            description: "GUID at offset 4 of the Vista and Windows 7 ProgramsCache headers — \
                FOLDERID_StartMenu {c3535b62-48ab-c14e-ba1f-a1ef4146fc19}. Confirms which folder \
                the cached entries belong to",
            is_uid_component: false,
        },
        FieldSchema {
            name: "programs_cache",
            value_type: ValueType::Bytes,
            description: "ProgramsCache REG_BINARY — the entry list for started programs. Each \
                entry is {data size, shell item list, sentinel}; decode the shell item lists with \
                the shell-item parser rather than string-scanning the blob",
            is_uid_component: true,
        },
        FieldSchema {
            name: "programs_cache_smp",
            value_type: ValueType::Bytes,
            description: "ProgramsCacheSMP REG_BINARY (StartPage2, Windows 7) — applications \
                pinned to the Start Menu. Evidences a deliberate pin, which is a stronger claim \
                about user intent than mere execution",
            is_uid_component: false,
        },
        FieldSchema {
            name: "programs_cache_tbp",
            value_type: ValueType::Bytes,
            description: "ProgramsCacheTBP REG_BINARY (StartPage2, Windows 7) — applications \
                pinned to the Taskband. Same intent signal as SMP, for the taskbar",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent in the user hive until Explorer rewrites the value"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["userassist_exe", "registry_featureusage", "shellbags_user"],
    sources: &[
        // Source: winreg-kb — StartPage vs StartPage2, the ProgramsCache / ProgramsCacheSMP /
        // ProgramsCacheTBP values and their meanings, the per-version format versions, the
        // FOLDERID_StartMenu header GUID, and the entry {size, shell item list, sentinel} layout.
        "https://winreg-kb.readthedocs.io/en/latest/sources/explorer-keys/Program-cache.html",
        // Source: libfwsi — the Windows Shell Item format the entries are built from.
        "https://github.com/libyal/libfwsi",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Explorer rewrites the value, so it reflects a state of the Start Menu and taskband rather than an append-only history — absence of an entry is not evidence a program was never present",
        "ProgramsCacheSMP and ProgramsCacheTBP evidence pinning, not execution; do not report a pinned application as a run program without an execution artifact",
        "The entries are shell item lists whose embedded metadata is only as reliable as the shell items themselves — parse with a shell-item decoder and carry its caveats, rather than treating recovered strings as verified paths",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Rewritten by Explorer as Start Menu and taskband contents change",
};

// ── Assessed artifacts (moved out of descriptors/generated/) ──────────────────
//
// Each of these carries a curated evidence strength and volatility class. No
// upstream corpus supplies that judgement, so it used to be written into the
// generated module by hand after every run — which a full-corpus regeneration
// erased. Here the ingest pipeline sees the id is already catalogued and skips
// its own record, so the judgement survives, and the triage priority is the
// artifact's own rather than the generator's High ceiling.

pub(crate) static NIRSOFT_SAM_HIVE_REG: ArtifactDescriptor = ArtifactDescriptor {
    id: "nirsoft_sam_hive_reg",
    name: "SAM Hive — Account Database",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSam),
    key_path: "SAM\\Domains\\Account\\Users",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "SAM hive users sub-key contains NT/LM password hashes for local accounts. Relevant to NirSoft's password recovery tools.",
    mitre_techniques: &["T1003.002"],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://www.nirsoft.net/utils/sam_password_recovery.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SAM hive persists across reboots; protected in-use by Windows",
};

pub(crate) static REGEDIT_DOMAINS_ACCOUNT_USERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "regedit_domains_account_users",
    name: "SAM Users",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSam),
    key_path: "SAM\\Domains\\Account\\Users",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "User accounts in SAM file",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://raw.githubusercontent.com/EricZimmerman/RECmd/master/BatchExamples/RECmd_Batch_MC.reb"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Local account enumeration via registry; compare against expected user list"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SAM account registry persists until account deletion",
};

pub(crate) static VELOCIRAPTOR_CURRENTVERSION_IMAGE_FILE_EXECUTION_OPTIONS: ArtifactDescriptor =
    ArtifactDescriptor {
        id: "velociraptor_currentversion_image_file_execution_options",
        name: "Windows.Persistence.Debug",
        artifact_type: ArtifactLocation::RegistryKey,
        hive: Some(HiveTarget::HklmSoftware),
        key_path:
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*",
        value_name: None,
        file_path: None,
        scope: DataScope::System,
        os_scope: OsScope::Win7Plus,
        decoder: Decoder::Identity,
        meaning: "Windows allows specific configuration of various executables via a
registry key. Some keys allow defining a debugger to attach to a
program as it is run. If this debugger is launched for commonly used
programs (e.g. notepad) then another program can be launched at the
same time (with the same privileges).

There is an additional key for x86 executables `HKEY_LOCAL_MACHINE\\
SOFTWARE\\wow6432node\\Microsoft\\Windows NT\\CurrentVersion\\Image File
Execution Options\\*` however this is kept inline with the x64 key and
therefore does not need to be processed.

Limitations: This queries the live registry and therefore does not
parse data in Windows.old or Regback folders, or VSS.",
        mitre_techniques: &[],
        fields: &[],
        retention: None,
        triage_priority: TriagePriority::Critical,
        related_artifacts: &[],
        sources: &["https://github.com/Velocidex/velociraptor"],
        evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
        evidence_tier: None,
        evidence_caveats: &[
            "Non-zero GlobalFlag with Debugger value indicates silent process exit / hijack",
        ],
        volatility: Some(crate::volatility::VolatilityClass::Persistent),
        volatility_rationale: "IFEO GlobalFlag registry persists until key deletion",
    };

pub(crate) static VELOCIRAPTOR_SECURITYPROVIDERS_WDIGEST: ArtifactDescriptor = ArtifactDescriptor {
    id: "velociraptor_securityproviders_wdigest",
    name: "Windows.Registry.WDigest",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: "SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\**",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Find WDigest registry values on the filesystem. The artifact will also use
GROUP BY to limit all ControlSet output to a single row.

To prevent a clear-text password from being placed in
LSASS, the following registry key needs to be set to “0” (Digest
Disabled):

 - HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest
    “UseLogonCredential”(DWORD)
    “Negotiate”(DWORD)

These registry keys are worth monitoring in an environment as an
attacker may wish to set it to 1 to enable Digest password support
which forces “clear-text” passwords to be placed in LSASS on any
version of Windows from Windows 7 / 2008R2 up to Windows 10 /
2012R2. Furthermore, Windows 8.1 / 2012 R2 and newer do not have a
“UseLogonCredential” DWORD value, so the key needs to be
added. The existence of the key is suspicious, if not expected.

* ATT&CK tactic: Defense Evasion, Credential Access
* ATT&CK technique: T1112, T1003.001",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/Velocidex/velociraptor"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "UseLogonCredential=1 enables plaintext credential caching in LSASS — critical IOC",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "WDigest registry value persists across reboots",
};

pub(crate) static VELOCIRAPTOR_CURRENTVERSION_PROFILELIST: ArtifactDescriptor =
    ArtifactDescriptor {
        id: "velociraptor_currentversion_profilelist",
        name: "Windows.Sys.AllUsers",
        artifact_type: ArtifactLocation::RegistryKey,
        hive: Some(HiveTarget::HklmSoftware),
        key_path: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\*",
        value_name: None,
        file_path: None,
        scope: DataScope::System,
        os_scope: OsScope::Win7Plus,
        decoder: Decoder::Identity,
        meaning: "List User accounts. We combine two data sources - the output from
the `NetUserEnum` API (termed `local` users) and the list of SIDs in
the registry (termed `remote` users).

In this artifact, 'remote' means that user profile was cached in the
registry, but the user does not appear in the output of the
`NetUserEnum` API - this normally happens for users remotely logging
into the system using domain credentials.

On Domain Controllers the `NetUserEnum` API will return the contents
of the entire ActiveDirectory as a list of 'local' users, however
this does not mean that the users have logged into the DC
locally. In this artifact we limit the number of users to 1000. If
you need to obtain the full list from the AD, customize this
artifact.",
        mitre_techniques: &[],
        fields: &[],
        retention: None,
        triage_priority: TriagePriority::Critical,
        related_artifacts: &[],
        sources: &["https://github.com/Velocidex/velociraptor"],
        evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
        evidence_tier: None,
        evidence_caveats: &[
            "User SID enumeration; compare against expected user base for rogue accounts",
        ],
        volatility: Some(crate::volatility::VolatilityClass::Persistent),
        volatility_rationale: "ProfileList registry persists until profile deletion",
    };
