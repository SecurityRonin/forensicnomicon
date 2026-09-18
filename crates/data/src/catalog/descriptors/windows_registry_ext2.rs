//! Extended Windows registry threat-hunting artifact descriptors — Phase 2.
//!
//! Sources: RECmd Kroll_Batch.reb, RECmd_Batch_MC.reb (EricZimmerman), SigmaHQ,
//! MITRE ATT&CK, Elastic Detection Rules, CrowdStrike threat intelligence.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, HiveTarget, OsScope,
    TriagePriority, ValueType,
};

// ── WinLogon credential exposure ─────────────────────────────────────────────

pub(crate) static WINLOGON_AUTOADMIN_LOGON: ArtifactDescriptor = ArtifactDescriptor {
    id: "winlogon_autoadmin_logon",
    name: "WinLogon AutoAdminLogon",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Winlogon",
    value_name: Some("AutoAdminLogon"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "AutoAdminLogon=1 enables passwordless automatic logon at boot. An attacker who enables this setting (or finds it pre-enabled on kiosk/server builds) can reboot to gain access without credentials, or retrieve the plaintext password from DefaultPassword.",
    mitre_techniques: &["T1547.001"],
    fields: &[FieldSchema {
        name: "auto_admin_logon",
        value_type: ValueType::Text,
        description: "1 = auto logon enabled; 0 or absent = disabled",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["winlogon_default_password", "winlogon_default_username"],
    sources: &[
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Legitimate on unattended kiosk/server builds; verify DefaultPassword also present"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persistent until modification",
};

pub(crate) static WINLOGON_DEFAULT_PASSWORD: ArtifactDescriptor = ArtifactDescriptor {
    id: "winlogon_default_password",
    name: "WinLogon DefaultPassword",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Winlogon",
    value_name: Some("DefaultPassword"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Stores the plaintext password used for automatic logon. This is a critical credential exposure: any user or process able to read HKLM SOFTWARE obtains the account password in cleartext. Attackers read this value for lateral movement.",
    mitre_techniques: &["T1552.002"],
    fields: &[FieldSchema {
        name: "default_password",
        value_type: ValueType::Text,
        description: "Plaintext password for automatic logon account",
        is_uid_component: false,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["winlogon_autoadmin_logon", "winlogon_default_username"],
    sources: &[
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Presence proves plaintext credential stored; must confirm AutoAdminLogon=1 for context"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persistent until modification",
};

pub(crate) static WINLOGON_DEFAULT_USERNAME: ArtifactDescriptor = ArtifactDescriptor {
    id: "winlogon_default_username",
    name: "WinLogon DefaultUserName",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Winlogon",
    value_name: Some("DefaultUserName"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Stores the username used for automatic logon. Combined with DefaultPassword, reveals the target account for credential harvesting.",
    mitre_techniques: &["T1552.002"],
    fields: &[FieldSchema {
        name: "default_username",
        value_type: ValueType::Text,
        description: "Username for automatic logon (SAM account name or UPN)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["winlogon_autoadmin_logon", "winlogon_default_password"],
    sources: &[
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Legitimately set when Autologon is configured intentionally"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicit deletion",
};

// ── LogonUI last logged-on user ───────────────────────────────────────────────

pub(crate) static LOGONUI_LAST_LOGGEDON_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "logonui_last_loggedon_user",
    name: "LogonUI LastLoggedOnUser",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
    value_name: Some("LastLoggedOnUser"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Records the UPN or SAM name of the last user who logged on interactively. Useful for establishing which account was active before an incident, or identifying compromised accounts used for initial access.",
    mitre_techniques: &["T1078"],
    fields: &[FieldSchema {
        name: "last_logged_on_user",
        value_type: ValueType::Text,
        description: "UPN or domain\\user of the last interactive logon",
        is_uid_component: true,
    }],
    retention: Some("Overwritten on each new interactive logon"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["winlogon_default_username", "profile_list_users"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Only reflects the most recent interactive logon, not full logon history"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Overwritten on each interactive logon",
};

// ── PortProxy (netsh port forwarding) ────────────────────────────────────────

pub(crate) static PORTPROXY_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "portproxy_config",
    name: "PortProxy v4tov4 TCP",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\PortProxy\v4tov4\tcp",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Records netsh portproxy IPv4-to-IPv4 TCP forwarding rules. Attackers use port forwarding to tunnel C2 traffic, relay RDP through a compromised pivot host, or expose internal services externally. Each value name is listenaddress/port; each value data is connectaddress/port.",
    mitre_techniques: &["T1572"],
    fields: &[FieldSchema {
        name: "proxy_rule",
        value_type: ValueType::Text,
        description: "connectaddress/port for the forwarded listener (value name = listenaddress/port)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until netsh portproxy delete or registry modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["network_shares_server", "rdp_shadow_sessions"],
    sources: &[
        "https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Legitimate uses exist (e.g., WSL2 port forwarding); verify rule targets are suspicious"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persistent until netsh portproxy delete",
};

// ── Windows Defender tampering ────────────────────────────────────────────────

pub(crate) static WINDOWS_DEFENDER_EXCLUSIONS_LOCAL: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_defender_exclusions_local",
    name: "Windows Defender Exclusions",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows Defender\Exclusions",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Stores Defender exclusion paths, extensions, processes, and IP ranges. Attackers add exclusions to hide malware payloads and C2 tools from real-time scanning. Presence of attacker-controlled paths, temp directories, or suspicious tool names is a strong IOC.",
    mitre_techniques: &["T1562.001"],
    fields: &[FieldSchema {
        name: "exclusion_entry",
        value_type: ValueType::Text,
        description: "Excluded path, extension, process, or IP (subkey name encodes type)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until removed by admin or AV policy"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["windows_defender_disabled_av", "windows_defender_realtime"],
    sources: &[
        "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_windows_defender_exclusion_added.yml",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Legitimate AV exclusions common; suspicious if path matches known attacker staging directories"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persistent until Defender policy change",
};

pub(crate) static WINDOWS_DEFENDER_DISABLED_AV: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_defender_disabled_av",
    name: "Windows Defender DisableAntiVirus",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Policies\Microsoft\Windows Defender",
    value_name: Some("DisableAntiVirus"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "DisableAntiVirus=1 via Group Policy disables Windows Defender completely. Attackers set this via policy key (not the service key) to bypass Tamper Protection. A value of 1 in this location is a near-certain indicator of deliberate AV disabling.",
    mitre_techniques: &["T1562.001"],
    fields: &[FieldSchema {
        name: "disable_anti_virus",
        value_type: ValueType::Integer,
        description: "1 = Defender disabled via policy; 0 = enabled",
        is_uid_component: true,
    }],
    retention: Some("Persistent until policy GPO refresh or manual deletion"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["windows_defender_exclusions_local", "windows_defender_realtime"],
    sources: &[
        "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_windows_defender_disabled.yml",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Via policy key — Tamper Protection bypass required; near-certain indicator of deliberate disabling"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persistent until GPO refresh",
};

pub(crate) static WINDOWS_DEFENDER_REALTIME: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_defender_realtime",
    name: "Windows Defender Real-Time Protection",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows Defender\Real-Time Protection",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Contains individual real-time protection component disable flags (DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection, etc.). Attackers disable individual components to evade detection while leaving the service nominally running.",
    mitre_techniques: &["T1562.001"],
    fields: &[FieldSchema {
        name: "protection_flag",
        value_type: ValueType::Integer,
        description: "Component disable flag: 1 = disabled (value name identifies component)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until Defender policy reset"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["windows_defender_disabled_av", "windows_defender_exclusions_local"],
    sources: &[
        "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_windows_defender_realtime_protection_disabled.yml",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Individual component flags may be legitimately set by MDM; check for combination of multiple disabled components"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persistent until Defender reset",
};

// ── Office macro trust records ────────────────────────────────────────────────

pub(crate) static MS_OFFICE_TRUSTED_DOCS: ArtifactDescriptor = ArtifactDescriptor {
    id: "ms_office_trusted_docs",
    name: "MS Office Trusted Documents (TrustRecords)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Office\{version}\{app}\Security\Trusted Documents\TrustRecords",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Records Office documents for which the user clicked 'Enable Content' or 'Enable Editing'. Each value name is the document path; binary data encodes trust decision and timestamp. Attackers delivering macro-enabled documents (T1566.001) leave traces here — the file path reveals the lure document name and delivery location.",
    mitre_techniques: &["T1566.001"],
    fields: &[FieldSchema {
        name: "trusted_doc_path",
        value_type: ValueType::Text,
        description: "Full path to the document the user trusted for macro execution",
        is_uid_component: true,
    }],
    retention: Some("Persistent in NTUSER.DAT until user profile is deleted"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["ms_office_server_cache"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://docs.microsoft.com/en-us/deployoffice/security/trusted-documents",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Legitimate macros also create entries; suspicious if document path is temp folder or remote share"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Updated when user enables Office document macros",
};

// ── VSS / shadow copy evasion ─────────────────────────────────────────────────

pub(crate) static VSS_FILES_NOT_TO_SNAPSHOT: ArtifactDescriptor = ArtifactDescriptor {
    id: "vss_files_not_to_snapshot",
    name: "VSS FilesNotToSnapshot",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Lists file path patterns excluded from Volume Shadow Copy snapshots. Ransomware families (e.g., REvil, Conti, BlackMatter) add malware payload paths here to prevent recovery via VSS. Presence of attacker-controlled paths is a near-certain ransomware IOC.",
    mitre_techniques: &["T1490"],
    fields: &[FieldSchema {
        name: "excluded_path_pattern",
        value_type: ValueType::Text,
        description: "File path or glob pattern excluded from VSS snapshots",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["vss_files_not_to_backup"],
    sources: &[
        "https://www.bleepingcomputer.com/news/security/revil-ransomware-has-a-secret-backdoor-and-its-been-used/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Non-Microsoft entries in this key are highly suspicious; verify against known software"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persistent until registry modification",
};

pub(crate) static VSS_FILES_NOT_TO_BACKUP: ArtifactDescriptor = ArtifactDescriptor {
    id: "vss_files_not_to_backup",
    name: "VSS FilesNotToBackup",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\BackupRestore\FilesNotToBackup",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Lists file path patterns excluded from Windows Backup. Ransomware and wipers add malware paths here to prevent backup-based recovery. Analogous to FilesNotToSnapshot but for the Windows Backup service.",
    mitre_techniques: &["T1490"],
    fields: &[FieldSchema {
        name: "excluded_path_pattern",
        value_type: ValueType::Text,
        description: "File path or glob pattern excluded from Windows Backup",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["vss_files_not_to_snapshot"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Non-Microsoft entries in this key are highly suspicious; verify against known software"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persistent until registry modification",
};

// ── IFEO SilentProcessExit (T1546.012) ───────────────────────────────────────

pub(crate) static IFEO_SILENT_EXIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "ifeo_silent_exit",
    name: "IFEO SilentProcessExit",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "SilentProcessExit subkeys specify a monitoring process launched when a target process exits. Attackers register this to re-spawn a payload or spawn a backdoor whenever a monitored process (e.g., svchost.exe, lsass.exe) exits — a stealthy persistence mechanism.",
    mitre_techniques: &["T1546.012"],
    fields: &[FieldSchema {
        name: "monitored_process",
        value_type: ValueType::Text,
        description: "Name of the process whose exit triggers the payload (subkey name)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["taskcache_tasks_path", "startup_approved_run_system"],
    sources: &[
        "https://www.deepinstinct.com/blog/ifeo-injections",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Legitimate uses exist (WER config); suspicious if MonitorProcess points to unknown binary"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persistent until modification",
};

// ── .exe handler hijack ───────────────────────────────────────────────────────

pub(crate) static EXEFILE_SHELL_OPEN_SOFTWARE: ArtifactDescriptor = ArtifactDescriptor {
    id: "exefile_shell_open_software",
    name: "Exefile Shell Open Command (HKLM SOFTWARE)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Classes\Exefile\Shell\Open\Command",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Defines the system-wide handler invoked when any .exe file is executed. Hijacking this key (e.g., to prefix a loader or logger) causes every program launch to run the attacker's payload first. This is a high-impact persistence and execution mechanism.",
    mitre_techniques: &["T1546.001"],
    fields: &[FieldSchema {
        name: "shell_open_command",
        value_type: ValueType::Text,
        description: "Command template invoked on .exe execution (system-wide)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["exefile_shell_open_usrclass"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Any deviation from default (%1 %*) is extremely suspicious; near-certain compromise indicator"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persistent until explicit deletion",
};

pub(crate) static EXEFILE_SHELL_OPEN_USRCLASS: ArtifactDescriptor = ArtifactDescriptor {
    id: "exefile_shell_open_usrclass",
    name: "Exefile Shell Open Command (UsrClass.dat)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::UsrClass),
    key_path: r"Exefile\Shell\Open\Command",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Per-user .exe handler in UsrClass.dat. Takes precedence over the HKLM SOFTWARE equivalent for the affected user. Non-admin attackers can set this without elevated privileges, hijacking all .exe execution for the user.",
    mitre_techniques: &["T1546.001"],
    fields: &[FieldSchema {
        name: "shell_open_command",
        value_type: ValueType::Text,
        description: "Command template invoked on .exe execution (per-user)",
        is_uid_component: true,
    }],
    retention: Some("Persistent in UsrClass.dat until profile deletion"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["exefile_shell_open_software"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Any presence of this key is suspicious; no legitimate software sets per-user .exe handler"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "UsrClass.dat value; persistent until profile deletion",
};

// ── RDP shadow sessions / credential abuse ────────────────────────────────────

pub(crate) static RDP_SHADOW_SESSIONS: ArtifactDescriptor = ArtifactDescriptor {
    id: "rdp_shadow_sessions",
    name: "RDP Shadow Session Policy",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Policies\Microsoft\Windows NT\Terminal Services",
    value_name: Some("Shadow"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Shadow value controls whether an admin can covertly view or interact with another user's RDP session. Values 2 or 4 (no user consent) allow silent takeover of active RDP sessions — used for insider threat and post-compromise lateral movement.",
    mitre_techniques: &["T1021.001", "T1563.002"],
    fields: &[FieldSchema {
        name: "shadow_mode",
        value_type: ValueType::Integer,
        description: "0=disabled, 1=full control+consent, 2=full control no consent, 3=view+consent, 4=view no consent",
        is_uid_component: true,
    }],
    retention: Some("Persistent until policy modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["portproxy_config", "restricted_admin_rdp"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Shadow=2 or 4 (no consent) is particularly suspicious; verify against admin policy"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persistent until policy modification",
};

pub(crate) static RESTRICTED_ADMIN_RDP: ArtifactDescriptor = ArtifactDescriptor {
    id: "restricted_admin_rdp",
    name: "Restricted Admin RDP (DisableRestrictedAdmin)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Lsa",
    value_name: Some("DisableRestrictedAdmin"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "DisableRestrictedAdmin=0 enables Restricted Admin mode for RDP, which allows Pass-the-Hash (PtH) authentication over RDP. Attackers set this to 0 to enable RDP PtH from a host where they hold NTLM hashes without knowing plaintext passwords.",
    mitre_techniques: &["T1550.002"],
    fields: &[FieldSchema {
        name: "disable_restricted_admin",
        value_type: ValueType::Integer,
        description: "0 = Restricted Admin enabled (PtH possible); 1 = disabled",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["rdp_shadow_sessions"],
    sources: &[
        "https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["May be legitimately enabled for privileged access workstations; context required"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persistent until explicit change",
};

// ── Network shares ────────────────────────────────────────────────────────────

pub(crate) static NETWORK_SHARES_SERVER: ArtifactDescriptor = ArtifactDescriptor {
    id: "network_shares_server",
    name: "LanmanServer Shares",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\LanmanServer\Shares",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Stores all Windows SMB shares hosted by this system. Attackers create shares to stage exfiltration data, enable lateral movement to/from this host, or expose sensitive directories. Share path and permissions reveal the scope of data access.",
    mitre_techniques: &["T1021.002"],
    fields: &[FieldSchema {
        name: "share_config",
        value_type: ValueType::Text,
        description: "Multi-string share configuration (path, permissions, description)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until share removal"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["portproxy_config"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Legitimate shares common; suspicious if share path is attacker staging directory or C: root"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persistent until share removal",
};

// ── Sysinternals EULA (tool execution indicator) ──────────────────────────────

pub(crate) static SYSINTERNALS_EULA: ArtifactDescriptor = ArtifactDescriptor {
    id: "sysinternals_eula",
    name: "Sysinternals EulaAccepted",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Sysinternals",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Sysinternals tools write EulaAccepted=1 to per-tool subkeys on first launch. Presence of subkeys for PsExec, ProcDump, Procdump64, Handle, or Strings under this path indicates a user ran those tools — common attacker-used utilities for lateral movement, credential dumping, and reconnaissance.",
    mitre_techniques: &["T1012"],
    fields: &[FieldSchema {
        name: "tool_name",
        value_type: ValueType::Text,
        description: "Sysinternals tool name (subkey name, e.g. PsExec, ProcDump)",
        is_uid_component: true,
    }],
    retention: Some("Persistent in NTUSER.DAT until profile deletion"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["registrar_favorites"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://learn.microsoft.com/en-us/sysinternals/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Sysadmins legitimately use these tools — context required to distinguish admin from attacker activity",
        "EulaAccepted bit can be pre-seeded in registry without running the tool",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

// ── MS Office Server Cache (Follina IOC) ──────────────────────────────────────

pub(crate) static MS_OFFICE_SERVER_CACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "ms_office_server_cache",
    name: "MS Office Server Cache",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Office\{version}\Common\Internet\Server Cache",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Caches Office server connections for online template and document fetching. CVE-2022-30190 (Follina) exploits MSDT via specially crafted Office documents that trigger remote template fetching; the attacker-controlled URL may appear in this cache as a post-exploitation IOC.",
    mitre_techniques: &["T1566.001"],
    fields: &[FieldSchema {
        name: "server_url",
        value_type: ValueType::Text,
        description: "Cached server URL accessed by Office (may contain C2 URL for Follina)",
        is_uid_component: true,
    }],
    retention: Some("Persistent in NTUSER.DAT"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["ms_office_trusted_docs"],
    sources: &[
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &["URL presence requires correlation with known C2 domains; many legitimate Office URLs expected"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Updated on Office server connections; persists in NTUSER.DAT",
};

// ── Cobalt Strike PowerShell IOC ──────────────────────────────────────────────

pub(crate) static POWERSHELL_COBALT_INFO: ArtifactDescriptor = ArtifactDescriptor {
    id: "powershell_cobalt_info",
    name: "PowerShell Cobalt Strike Info Key",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\PowerShell\info",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "This registry key is created by Cobalt Strike's PowerShell reflective injection staging mechanism. Presence of HKLM\\SOFTWARE\\Microsoft\\PowerShell\\info (not the standard PowerShell paths) is a near-certain Cobalt Strike beacon IOC and should be treated as definitive evidence of compromise.",
    mitre_techniques: &["T1059.001"],
    fields: &[FieldSchema {
        name: "cs_info_value",
        value_type: ValueType::Bytes,
        description: "Cobalt Strike staging data stored in this key",
        is_uid_component: false,
    }],
    retention: Some("Persistent until Cobalt Strike cleanup or registry modification"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["ifeo_silent_exit", "taskcache_tasks_path"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/RECmd_Batch_MC.reb",
        "https://www.crowdstrike.com/blog/registry-analysis-with-crowdresponse/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Key is not created by legitimate software; presence is near-certain Cobalt Strike IOC"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key created by Cobalt Strike; persistent until cleanup",
};

// ── StartupApproved Run keys ──────────────────────────────────────────────────

pub(crate) static STARTUP_APPROVED_RUN_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "startup_approved_run_system",
    name: "StartupApproved Run (HKLM)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Binary flags indicating which HKLM Run key entries are enabled vs disabled by the user (via Task Manager Startup tab). Attackers may re-enable previously disabled run entries, or add new entries here that won't appear as disabled. Correlate with run_key_hklm.",
    mitre_techniques: &["T1547.001"],
    fields: &[FieldSchema {
        name: "startup_entry_status",
        value_type: ValueType::Bytes,
        description: "8-byte binary: bytes 0-1 = status (03 00 00 00 = enabled, 01 00 00 00 = disabled)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until user modification"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["startup_approved_run_user"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit modification",
};

pub(crate) static STARTUP_APPROVED_RUN_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "startup_approved_run_user",
    name: "StartupApproved Run (HKCU)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Per-user equivalent of the HKLM StartupApproved\\Run key. Controls enabled/disabled state of HKCU Run key entries. Useful for detecting re-enabled or attacker-added startup entries at user scope.",
    mitre_techniques: &["T1547.001"],
    fields: &[FieldSchema {
        name: "startup_entry_status",
        value_type: ValueType::Bytes,
        description: "8-byte binary: bytes 0-1 = status (03 00 00 00 = enabled, 01 00 00 00 = disabled)",
        is_uid_component: true,
    }],
    retention: Some("Persistent in NTUSER.DAT"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["startup_approved_run_system"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit modification",
};

// ── Task Scheduler cache ──────────────────────────────────────────────────────

pub(crate) static TASKCACHE_TASKS_PATH: ArtifactDescriptor = ArtifactDescriptor {
    id: "taskcache_tasks_path",
    name: "TaskCache Tree (Scheduled Task Paths)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Registry tree mirroring the Task Scheduler folder hierarchy. Each subkey is a task path with an Id GUID and SD (security descriptor). Attackers create scheduled tasks here for persistence; the registry copy survives deletion of the XML task file and is faster to parse than the XML store. Microsoft reported intrusions in which the actor deleted the SD value from a task's Tree subkey: the task then stops appearing in `schtasks /query` and in the Task Scheduler UI while continuing to run on its schedule, so enumerating tasks through those tools cannot support a negative finding. Read the Tree subkeys directly and treat a task subkey that carries an Id but no SD as hidden rather than absent.",
    mitre_techniques: &["T1053.005", "T1564"],
    fields: &[
        FieldSchema {
            name: "task_path",
            value_type: ValueType::Text,
            description: "Full scheduled task path (subkey hierarchy relative to Tree)",
            is_uid_component: true,
        },
        // Source: https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/
        FieldSchema {
            name: "task_id",
            value_type: ValueType::Guid,
            description: "Id value on the task's Tree subkey — the GUID naming the matching TaskCache\\Tasks subkey that holds the task's actions, path and triggers. Use it to join a Tree entry to the definition that says what the task actually runs",
            is_uid_component: false,
        },
        // Source: https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/
        FieldSchema {
            name: "task_sd",
            value_type: ValueType::Bytes,
            description: "SD value — the task's security descriptor, controlling who may run it. Deleting this value hides the task from schtasks and the Task Scheduler UI while it keeps running, so an Id present with SD missing is the hiding pattern: enumerate the Tree subkeys and flag every task subkey with no SD",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until task deletion"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["ifeo_silent_exit", "startup_approved_run_system"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://nasbench.medium.com/a-deep-dive-into-windows-scheduled-tasks-and-the-processes-running-them-218d1eed4cce",
        // Deleting the SD value under TaskCache\Tree\<task> removes the task from
        // `schtasks /query` and Task Scheduler while the task still runs.
        "https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Many legitimate tasks present; suspicious tasks have random names or reside outside \\Microsoft\\",
        "A task-enumeration tool that returns nothing does not establish that no task is scheduled — a task whose Tree subkey lost its SD value keeps running but is not listed by schtasks or the Task Scheduler UI; compare the Tree subkeys, the Tasks GUID subkeys and the on-disk XML store against each other",
        "Deleting the SD value requires SYSTEM-level access, so the hiding pattern also implies the actor already held or stole that privilege",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persistent until task deletion",
};

// ── User profile list ─────────────────────────────────────────────────────────

pub(crate) static PROFILE_LIST_USERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "profile_list_users",
    name: "ProfileList (User SIDs and Profile Paths)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\ProfileList",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Lists every user who has logged on to this system, keyed by SID. Each subkey contains ProfileImagePath (profile folder), ProfileLoadTime, and other metadata. Useful for enumerating all accounts (including service and temporary accounts) and correlating SIDs to usernames across the investigation.",
    mitre_techniques: &["T1087.001"],
    fields: &[FieldSchema {
        name: "profile_image_path",
        value_type: ValueType::Text,
        description: "Full path to the user's profile directory",
        is_uid_component: false,
    }],
    retention: Some("Persistent; survives user account deletion in some configurations"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["logonui_last_loggedon_user", "winlogon_default_username"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://learn.microsoft.com/en-us/windows/win32/sysinfo/profilelist",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Subkeys may survive account deletion if the profile directory was not cleaned up; absence of a SID does not guarantee the account never existed on this machine"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until profile is deleted",
};

// ── Registrar favorites ───────────────────────────────────────────────────────

pub(crate) static REGISTRAR_FAVORITES: ArtifactDescriptor = ArtifactDescriptor {
    id: "registrar_favorites",
    name: "Registrar Registry Editor Favorites",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Resplendence\Registrar\Favorites",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Bookmarks saved in the Registrar registry editor. Presence of bookmarks to sensitive keys (SAM, LSA Secrets, credential providers, run keys) indicates an attacker used Registrar to navigate and potentially modify those keys during the intrusion.",
    mitre_techniques: &["T1012"],
    fields: &[FieldSchema {
        name: "favorite_key_path",
        value_type: ValueType::Text,
        description: "Registry path bookmarked by the user in Registrar",
        is_uid_component: true,
    }],
    retention: Some("Persistent in NTUSER.DAT"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["sysinternals_eula"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Sysadmins and forensic analysts legitimately use Registrar with sensitive bookmarks"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

// ── DHCP interface configuration ──────────────────────────────────────────────

pub(crate) static DHCP_IPV4_INTERFACE: ArtifactDescriptor = ArtifactDescriptor {
    id: "dhcp_ipv4_interface",
    name: "DHCP Interface IPv4 Configuration",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Per-interface subkeys record DHCP-assigned IP address, subnet mask, gateway, lease times, and DNS servers. Useful for network reconstruction: DhcpIPAddress + LeaseObtainedTime establish which IP a host held at a given point in time — critical for correlating log events to host identity.",
    mitre_techniques: &["T1016"],
    fields: &[FieldSchema {
        name: "dhcp_ip_address",
        value_type: ValueType::Text,
        description: "DHCP-assigned IPv4 address for this interface",
        is_uid_component: true,
    }],
    retention: Some("Overwritten on each DHCP renewal; last lease persists"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["portproxy_config", "firewall_rules"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Only reflects current/most-recent DHCP lease, not full historical IP assignment"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Updated on each DHCP lease renewal/acquisition",
};

// ── NTFS last access update status ───────────────────────────────────────────

pub(crate) static NTFS_LAST_ACCESS_STATUS: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntfs_last_access_status",
    name: "NTFS Last Access Update Status",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\FileSystem",
    value_name: Some("NtfsDisableLastAccessUpdate"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "If NtfsDisableLastAccessUpdate is 1 (or 0x80000001 on Win10+), the $STANDARD_INFORMATION Last Access timestamp is NOT updated on file reads. This makes last-access-based timeline analysis unreliable and is an anti-forensic indicator when set by an attacker.",
    mitre_techniques: &["T1070.006"],
    fields: &[FieldSchema {
        name: "last_access_update_disabled",
        value_type: ValueType::Integer,
        description: "0 or absent = last access updated; 1 or 0x80000001 = disabled",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification or OS install"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["prefetch_status"],
    sources: &[
        "https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Default value on Win10/11 is 0x80000001 (system-managed) — not necessarily attacker activity"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicit modification",
};

// ── Prefetch enabled/disabled ─────────────────────────────────────────────────

pub(crate) static PREFETCH_STATUS: ArtifactDescriptor = ArtifactDescriptor {
    id: "prefetch_status",
    name: "Prefetch Enable Status",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
    value_name: Some("EnablePrefetcher"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "EnablePrefetcher=0 disables Windows Prefetch, eliminating .pf files that record program execution. An attacker who disables prefetch removes a key source of execution evidence (T1070). Value 3 = both application and boot prefetch enabled (normal). Value 0 = disabled (suspicious on non-server OS).",
    mitre_techniques: &["T1070"],
    fields: &[FieldSchema {
        name: "enable_prefetcher",
        value_type: ValueType::Integer,
        description: "0=disabled, 1=app prefetch only, 2=boot only, 3=both (default)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["ntfs_last_access_status"],
    sources: &[
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452747(v=ws.11)",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Default disabled on Server SKUs and SSD-only configurations on some builds — not always attacker activity"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicit modification",
};

// ── Windows Firewall rules ────────────────────────────────────────────────────

pub(crate) static FIREWALL_RULES: ArtifactDescriptor = ArtifactDescriptor {
    id: "firewall_rules",
    name: "Windows Firewall Rules",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "All Windows Firewall rules as pipe-delimited strings. Attackers add rules to allow inbound C2 connections, permit lateral movement tools (PSExec, WMI), or expose services. Suspicious patterns: rules named after common attacker tools, rules allowing all ports for a specific executable, or rules disabling the firewall.",
    mitre_techniques: &["T1562.004"],
    fields: &[FieldSchema {
        name: "firewall_rule",
        value_type: ValueType::Text,
        description: "Pipe-delimited firewall rule definition (Action, Protocol, LPort, RPort, App, etc.)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until rule deletion"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["portproxy_config", "network_shares_server"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_firewall_rule_added.yml",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Many legitimate applications add firewall rules during install",
        "Group Policy may push rules that look attacker-like",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit rule deletion",
};

// ── Event log channel enable/disable status ───────────────────────────────────

pub(crate) static EVENT_LOG_CHANNEL_STATUS: ArtifactDescriptor = ArtifactDescriptor {
    id: "event_log_channel_status",
    name: "Event Log Channel Enabled/Disabled Status",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\WINEVT\Channels",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Each subkey is an event log channel with an Enabled DWORD value. Attackers disable Security, System, Microsoft-Windows-Sysmon/Operational, or PowerShell channels to suppress evidence of their activity. A disabled Security or Sysmon channel found during an incident is a strong indicator of defensive tampering.",
    mitre_techniques: &["T1562.002"],
    fields: &[FieldSchema {
        name: "channel_enabled",
        value_type: ValueType::Integer,
        description: "1 = channel enabled; 0 = channel disabled (subkey name = channel name)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until channel re-enabled or configuration reset"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["windows_defender_disabled_av"],
    sources: &[
        "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_disable_event_logging.yml",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Disabled Security or Sysmon channel during an incident is near-certain evidence of tampering"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persistent until channel re-enabled",
};

// ── NTFS 8.3 short-name creation policy ───────────────────────────────────────

/// `NtfsDisable8dot3NameCreation` — the volume policy that decides whether a
/// DOS-namespace `$FILE_NAME` exists at all.
///
/// Source: <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-8dot3name>
/// Source: <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc>
pub(crate) static NTFS_8DOT3_NAME_CREATION: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntfs_8dot3_name_creation",
    name: "NTFS 8.3 Short-Name Creation Policy",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\FileSystem",
    value_name: Some("NtfsDisable8dot3NameCreation"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The system-wide default for 8.3 (short) name creation, which `fsutil 8dot3name set <defaultvalue>` writes here. It decides whether a file gets a second, DOS-namespace name in addition to its long name — so it is the setting to read before calling a missing short name an anomaly. Consult it in two situations: when a file has no DOS-namespace $FILE_NAME (on a volume where creation is disabled that is the expected state, not tampering or timestomping), and when building a directory listing from a $I30 index, where a file holding both a Win32 and a DOS name produces two entries and inflates the count unless entries are collapsed on the file reference rather than on the name. `fsutil 8dot3name query [<volumepath>]` reports the effective state, and `fsutil 8dot3name strip` removes existing short names from a directory tree, writing a log to %temp%\\8dot3_removal_log@(GMT <timestamp>).log unless /l redirects it — that log is itself a lead that short names were removed after the fact.",
    mitre_techniques: &[],
    fields: &[FieldSchema {
        name: "disable_8dot3_name_creation",
        value_type: ValueType::Integer,
        description: "0 = 8.3 name creation enabled on all volumes; 1 = disabled on all volumes; 2 = set per volume (the per-volume flag on the volume decides, and the default must be 2 before a volume can be set individually); 3 = disabled on all volumes except the system volume. Use it to decide whether an absent DOS-namespace name is policy or an anomaly",
        is_uid_component: true,
    }],
    retention: Some("Persistent until the value is changed; existing short names survive a later policy change"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["mft", "ntfs_i30_index", "ntfs_last_access_status"],
    sources: &[
        // Names the registry key and value, the four default values, and the
        // query/scan/set/strip subcommands including the strip log location.
        "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-8dot3name",
        // $FILE_NAME namespace and the file reference carried by each index entry.
        "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "The value states the policy in force when it was read, not the policy in force when a given file was created — short names created under an earlier setting persist unchanged",
        "With the default set to 2 the answer is per volume, so this value alone does not decide the question for the volume under examination",
        "Absence of a DOS-namespace $FILE_NAME is a volume-policy fact; do not report it as evidence of name manipulation without reading this value",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicitly changed",
};

// ── SMB signing (relay feasibility) ───────────────────────────────────────────

/// `RequireSecuritySignature` on the Server service — inbound SMB signing.
///
/// Source: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview>
pub(crate) static SMB_SERVER_REQUIRE_SIGNING: ArtifactDescriptor = ArtifactDescriptor {
    id: "smb_server_require_signing",
    name: "SMB Server Signing Required (LanmanServer RequireSecuritySignature)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\LanmanServer\Parameters",
    value_name: Some("RequireSecuritySignature"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The registry form of the security policy 'Microsoft network server: Digitally sign communications (always)' — REG_DWORD, 0 disables and 1 enables the requirement that inbound SMB traffic to this host be signed. Signing binds a message to the session key and to the identities of sender and recipient, which is what Microsoft describes as protecting against relay and spoofing, so this value answers whether authentication coerced out of another host could have been relayed into SMB on this one. Microsoft states that SMB is signed whenever either end requires it and is unsigned only when both ends are set to 0, so a conclusion about a specific session needs the peer's value as well as this host's. Recoverable from an offline SYSTEM hive.",
    mitre_techniques: &["T1557.001", "T1187"],
    fields: &[FieldSchema {
        name: "require_security_signature",
        value_type: ValueType::Integer,
        description: "0 = inbound SMB signing not required on this host (a relay into SMB here is not blocked by signing); 1 = required. Pair it with the initiating host's client-side value before concluding anything about a particular session",
        is_uid_component: true,
    }],
    retention: Some("Persistent until the value is changed"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["smb_client_require_signing", "network_shares_server", "lanman_auto_share_admin"],
    sources: &[
        // Policy-to-registry mapping (LanManServer\Parameters, RequireSecuritySignature,
        // REG_DWORD 0/1), the either-end rule, the DC default, and the note that
        // EnableSecuritySignature is ignored for SMB2 and later.
        "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview",
        // Per-edition signing requirements introduced with Windows 11 24H2 / Windows Server 2025.
        "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "The sibling EnableSecuritySignature value is ignored by SMB2 and later and applies only to SMB1 — do not read it as a signing state for a modern session",
        "Domain controllers require SMB signing of connecting clients by default, so a DC is not described by this value alone",
        "Per-edition defaults differ: Windows 11 24H2 Enterprise, Pro and Education require both outbound and inbound signing, Windows Server 2025 requires outbound only, and 24H2 Home requires neither — use the pair of values as a version corroboration point, not as proof of deliberate weakening",
        "Signing prevents relay of the session; it does not prevent the credential coercion that precedes it",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicitly changed",
};

/// `RequireSecuritySignature` on the Workstation service — outbound SMB signing.
///
/// Source: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview>
pub(crate) static SMB_CLIENT_REQUIRE_SIGNING: ArtifactDescriptor = ArtifactDescriptor {
    id: "smb_client_require_signing",
    name: "SMB Client Signing Required (LanmanWorkstation RequireSecuritySignature)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\LanmanWorkstation\Parameters",
    value_name: Some("RequireSecuritySignature"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The registry form of the security policy 'Microsoft network client: Digitally sign communications (always)' — REG_DWORD, 0 disables and 1 enables the requirement that outbound SMB traffic from this host be signed. It is read on the side that was made to authenticate: if this host's sessions had to be signed, an intercepted authentication could not be replayed into an SMB session elsewhere. Because Microsoft documents that signing happens when either end requires it, the question 'was this session signed' is answered by this value together with the destination server's. Recoverable from an offline SYSTEM hive.",
    mitre_techniques: &["T1557.001", "T1187"],
    fields: &[FieldSchema {
        name: "require_security_signature",
        value_type: ValueType::Integer,
        description: "0 = outbound SMB signing not required from this host; 1 = required. Read together with the destination server's value to decide whether a specific session would have been signed",
        is_uid_component: true,
    }],
    retention: Some("Persistent until the value is changed"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["smb_server_require_signing", "network_shares_server"],
    sources: &[
        // Policy-to-registry mapping (LanManWorkstation\Parameters,
        // RequireSecuritySignature, REG_DWORD 0/1) and the either-end rule.
        "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview",
        // Per-edition signing requirements introduced with Windows 11 24H2 / Windows Server 2025.
        "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "The sibling EnableSecuritySignature value is ignored by SMB2 and later and applies only to SMB1",
        "Connecting by IP address or CNAME causes NTLM rather than Kerberos to be used, which changes the exposure independently of this value",
        "A host set to 0 still produced signed sessions against any server that required signing — the value bounds the possibility, it does not record what happened",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicitly changed",
};

// ── Remote UAC token filtering ────────────────────────────────────────────────

/// `LocalAccountTokenFilterPolicy` — whether a local administrator keeps a full
/// token over the network.
///
/// Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction>
pub(crate) static LOCAL_ACCOUNT_TOKEN_FILTER_POLICY: ArtifactDescriptor = ArtifactDescriptor {
    id: "local_account_token_filter_policy",
    name: "LocalAccountTokenFilterPolicy (Remote UAC Token Filtering)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\Policies\System",
    value_name: Some("LocalAccountTokenFilterPolicy"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Controls UAC remote restrictions. Microsoft documents the value as a DWORD that is 0 by default, which builds a filtered token with the administrator credentials removed, and 1, which builds an elevated token; setting it to 1 is the documented way to disable UAC remote restrictions. With the default in force, a member of the local Administrators group connecting over the network — the `net use \\\\host\\Share$` case Microsoft gives — does not connect as a full administrator and cannot perform administrative tasks, which is what frustrates remote use of a local account's credentials or hash. A single DWORD set to 1 restores full remote administrative use of every local account on the host, so read it whenever local-account access to admin shares is in question. The asymmetry matters: Microsoft states that a domain user in the local Administrators group runs with a full administrator token on the remote computer and UAC is not in effect, so this value changes nothing for domain accounts.",
    mitre_techniques: &["T1112", "T1078.003"],
    fields: &[FieldSchema {
        name: "local_account_token_filter_policy",
        value_type: ValueType::Integer,
        description: "1 = elevated token built for local administrators authenticating over the network (remote UAC restrictions disabled — local-account admin access to C$/ADMIN$ becomes possible); 0 or absent = the documented default filtered token. Treat a 1 on a workstation as a configuration change that needs an owner",
        is_uid_component: true,
    }],
    retention: Some("Persistent until the value is changed or deleted"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["restricted_admin_rdp", "network_shares_server", "lanman_auto_share_admin"],
    sources: &[
        // KB951016: the key, the value name, the 0/1 table, and the local-account
        // versus domain-account asymmetry.
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Management, backup and deployment tooling legitimately sets this value to 1 — establish whether the change is attributable to such a product before calling it attacker activity",
        "The value governs only local (SAM) accounts; a domain account holding local administrator rights is unaffected either way, so a 0 here does not mean remote administrative access was impossible",
        "The key's LastWrite time dates the most recent change to any value in the key, not to this value specifically",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicitly changed",
};

// ── Remote registry write path (MS-RRP) ───────────────────────────────────────

/// The RemoteRegistry service key — the server side of a `reg add \\HOST\HKLM\…`.
///
/// Source: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/01e7fc6d-0c96-425a-a26a-6b75c67ca77d>
/// Source: <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree>
pub(crate) static REMOTE_REGISTRY_SERVICE: ArtifactDescriptor = ArtifactDescriptor {
    id: "remote_registry_service",
    name: "Remote Registry Service (MS-RRP endpoint)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\RemoteRegistry",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The service that answers the Windows Remote Registry Protocol, and therefore the host-side precondition for any registry write performed across the network (the `reg add \\\\HOST\\HKLM\\...` pattern). MS-RRP is an RPC protocol whose server is identified by the well-known endpoint \\PIPE\\winreg with RPC over SMB as the protocol sequence, so a remote registry write rides the same SMB session and IPC$ named-pipe surface as other lateral-movement traffic rather than opening a port of its own. Read the Start value to establish whether the service could have answered at all, and read it together with the ACL key CurrentControlSet\\Control\\SecurePipeServers\\winreg, which is what an application references to decide remote access. The commit artifact left on the target is the modified key's LastWrite FILETIME, which Windows maintains per KEY: Microsoft documents the last-write time as the last time the key OR ANY OF ITS VALUE ENTRIES was modified, so a Run-key write updates the key's timestamp but cannot on its own be attributed to a particular value.",
    mitre_techniques: &["T1112", "T1021.002"],
    fields: &[
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree
        FieldSchema {
            name: "start",
            value_type: ValueType::Integer,
            description: "Start REG_DWORD: 0 = boot, 1 = system, 2 = automatic (started by the Service Control Manager at startup), 3 = demand, 4 = disabled. A 4 means the host could not have answered a remote registry call while that setting was in force; a 2 or 3 means it could",
            is_uid_component: true,
        },
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree
        FieldSchema {
            name: "image_path",
            value_type: ValueType::Text,
            description: "ImagePath — the service binary. Compare against the expected host process to catch a service key repurposed to run something else",
            is_uid_component: false,
        },
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw
        FieldSchema {
            name: "key_last_write",
            value_type: ValueType::Timestamp,
            description: "The key's last-write FILETIME, documented as the last time the key or any of its value entries was modified. It dates the most recent change to the key as a whole — never attribute it to one named value without corroboration from another source",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until the service configuration is changed"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["secure_pipe_servers_winreg", "network_shares_server", "evtx_system"],
    sources: &[
        // MS-RRP Server: the \PIPE\winreg well-known endpoint and RPC over SMB.
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/01e7fc6d-0c96-425a-a26a-6b75c67ca77d",
        // Services registry tree: Start, Type, ErrorControl, ImagePath value semantics.
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree",
        // RegQueryInfoKey lpftLastWriteTime — "the last time that the key or any of
        // its value entries is modified", i.e. per key, not per value.
        "https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw",
        // IPC$ is the share that carries the named pipes used for communication
        // between programs — the surface \PIPE\winreg is reached through.
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/remove-administrative-shares",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "The Start value read from an image describes the configuration at acquisition, not necessarily at the time of the activity under examination",
        "Remote registry access is a normal management path — inventory, monitoring and configuration tools use it, so an enabled service is a capability finding, not an intrusion finding",
        "A key's LastWrite time is per key: it cannot show which value changed, nor how many times, nor by whom",
        "The registry stores no record of the account or source host behind a remote write; that attribution has to come from the SMB/authentication logs on the target",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until the service configuration is changed",
};

/// `SecurePipeServers\winreg` — the ACL and exemption list for remote registry access.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-remotely-accessible-registry-paths-and-subpaths>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959392(v=technet.10)>
pub(crate) static SECURE_PIPE_SERVERS_WINREG: ArtifactDescriptor = ArtifactDescriptor {
    id: "secure_pipe_servers_winreg",
    name: "SecurePipeServers winreg (Remote Registry Access Control)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\SecurePipeServers\winreg",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The key an application or process references to determine who may read the registry of this host across the network. Its own security descriptor is the gate; the AllowedPaths subkey holds a list of registry paths that all users can reach remotely even without permission on the winreg key, and Microsoft notes those listed paths can be accessed anonymously. Two uses in an examination: establish the reachable surface at the time of an alleged remote-registry pivot (the winreg ACL plus whatever AllowedPaths exempts), and spot a widened list — a path added to AllowedPaths quietly exposes that subtree to unauthenticated readers. Microsoft's default exemptions are a short, well-known list (printer, Eventlog, Perflib, Terminal Server and similar keys); entries outside it deserve an explanation. Remote access also requires the Remote Registry service to be enabled, so neither key answers the question alone.",
    mitre_techniques: &["T1012", "T1112"],
    fields: &[
        // Source: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959392(v=technet.10)
        FieldSchema {
            name: "allowed_path",
            value_type: ValueType::Text,
            description: "One registry path listed under the AllowedPaths subkey — reachable remotely by all users regardless of the winreg key's permissions, and documented as accessible anonymously. Compare the list against Microsoft's documented defaults and treat additions as a widened exposure",
            is_uid_component: true,
        },
        FieldSchema {
            name: "winreg_security_descriptor",
            value_type: ValueType::Bytes,
            description: "The security descriptor on the winreg key itself — the ACL deciding which users and groups may connect to this host's registry remotely. Parse it to state who had remote read access; the absence of the key means per-key permissions govern instead",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until the key or its permissions are changed"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["remote_registry_service", "network_shares_server"],
    sources: &[
        // The WinReg key's role, the documented default remotely accessible paths,
        // and the statement that remote access also requires the Remote Registry service.
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-remotely-accessible-registry-paths-and-subpaths",
        // AllowedPaths subkey under SecurePipeServers\winreg and its anonymous-access note.
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959392(v=technet.10)",
        // MS-RRP Server: the \PIPE\winreg endpoint this key protects.
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/01e7fc6d-0c96-425a-a26a-6b75c67ca77d",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Management products legitimately extend the list — remote management tooling depends on remote registry reads, so an added path needs attribution before it is called tampering",
        "The key describes what was reachable, not what was read; it records no access history",
        "Group Policy can overwrite these entries at the next refresh, so the observed list may be the policy's rather than a local change",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until the key or its permissions are changed",
};

// ── PowerShell logging policy (did 4103/4104/transcripts exist?) ──────────────

/// `ScriptBlockLogging\EnableScriptBlockLogging` — whether 4104 records could exist.
///
/// Source: <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1>
pub(crate) static POWERSHELL_SCRIPT_BLOCK_LOGGING_POLICY: ArtifactDescriptor = ArtifactDescriptor {
    id: "powershell_script_block_logging_policy",
    name: "PowerShell Script Block Logging Policy",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
    value_name: Some("EnableScriptBlockLogging"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The registry switch Microsoft documents for turning on Windows PowerShell script block logging, set to 1 under HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging. With it enabled PowerShell records the content of every script block it processes to the Microsoft-Windows-PowerShell/Operational log as Event ID 4104. Read it out of an offline SOFTWARE hive to answer the prior question in any PowerShell investigation — should 4104 records have existed at all? — because an empty Operational log means nothing until the policy state is known. It is also a direct target for impairing defences: an actor who sets the value to 0 blinds script block logging for every session started afterwards, while sessions already running are unaffected. On PowerShell 7 the equivalent switch lives under Policies\\Microsoft\\PowerShellCore\\ScriptBlockLogging and logs to the PowerShellCore/Operational channel, so check both before concluding logging was off.",
    mitre_techniques: &["T1562.002", "T1059.001"],
    fields: &[FieldSchema {
        name: "enable_script_block_logging",
        value_type: ValueType::Integer,
        description: "1 = script block logging on, so absence of 4104 records for an interval is meaningful; 0 or absent = the log was never going to hold them and an empty Operational log proves nothing about what ran",
        is_uid_component: true,
    }],
    retention: Some("Persistent until the value is changed or the policy is reapplied"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "powershell_module_logging_policy",
        "powershell_transcription_policy",
        "powershell_transcripts",
        "event_log_channel_status",
    ],
    sources: &[
        // Names the HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
        // key, the EnableScriptBlockLogging value, Event ID 4104 and the
        // Microsoft-Windows-PowerShell/Operational channel.
        "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1",
        // PowerShell 7 equivalent under Policies\Microsoft\PowerShellCore\ScriptBlockLogging.
        "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "The value states the policy at acquisition; a value set back to 1 after an intrusion leaves the same reading as one that was never touched — corroborate with the key's LastWrite time and with Group Policy history",
        "The setting takes effect for sessions started after the change, so an interval of missing 4104 records can coincide with a still-running session",
        "The same policy offers an additional invocation-logging option that records the start and stop of each command, script block, function or script; its absence explains missing start/stop events without implying script block logging was off",
        "A Group Policy refresh can restore or overwrite the value, so the current reading may not be the value in force during the period examined",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until changed or reapplied by policy",
};

/// `ModuleLogging\EnableModuleLogging` — whether pipeline execution events could exist.
///
/// Source: <https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-powershellexecutionpolicy>
pub(crate) static POWERSHELL_MODULE_LOGGING_POLICY: ArtifactDescriptor = ArtifactDescriptor {
    id: "powershell_module_logging_policy",
    name: "PowerShell Module Logging Policy",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Policies\Microsoft\Windows\PowerShell\ModuleLogging",
    value_name: Some("EnableModuleLogging"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The 'Turn on Module Logging' policy, which Microsoft documents as the value EnableModuleLogging under the registry key Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging. Enabled, it records pipeline execution events for the selected modules to the Windows PowerShell log; disabled, no module records execution events. Not configured is the third state and the usual one: each module's own LogPipelineExecutionDetails property then decides, and Microsoft documents that property as False by default for all modules — so the absence of pipeline records is the expected reading on an unconfigured host, not a sign that records were deleted. The policy also carries the list of modules selected for logging, which bounds what could have been recorded even when the switch is on: a module absent from the list produced nothing.",
    mitre_techniques: &["T1562.002", "T1059.001"],
    fields: &[FieldSchema {
        name: "enable_module_logging",
        value_type: ValueType::Integer,
        description: "1 = pipeline execution events recorded for the selected modules; 0 = logging disabled for all modules; absent = not configured, each module's LogPipelineExecutionDetails decides and defaults to off. Use it to decide whether missing pipeline records are meaningful",
        is_uid_component: true,
    }],
    retention: Some("Persistent until the value is changed or the policy is reapplied"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[
        "powershell_script_block_logging_policy",
        "powershell_transcription_policy",
        "event_log_channel_status",
    ],
    sources: &[
        // ADMX mapping: Registry Key Name Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging,
        // Registry Value Name EnableModuleLogging.
        "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-powershellexecutionpolicy",
        // Enabled / disabled / not-configured semantics and the LogPipelineExecutionDetails default.
        "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Absent is the common state and is not evidence of tampering — module logging is off by default",
        "Enabling the policy without selecting modules records nothing, so the switch alone does not establish that a given module's activity would have been logged",
        "The setting exists under both Computer and User configuration, and Microsoft documents the computer setting as taking precedence — read both before stating the effective policy",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until changed or reapplied by policy",
};

/// `Transcription\EnableTranscripting` — whether transcripts were written, and where.
///
/// Source: <https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-powershellexecutionpolicy>
pub(crate) static POWERSHELL_TRANSCRIPTION_POLICY: ArtifactDescriptor = ArtifactDescriptor {
    id: "powershell_transcription_policy",
    name: "PowerShell Transcription Policy",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Policies\Microsoft\Windows\PowerShell\Transcription",
    value_name: Some("EnableTranscripting"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The 'Turn on PowerShell Transcription' policy, documented as the value EnableTranscripting under the registry key Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription. Enabled, PowerShell captures the input and output of commands for PowerShell, the ISE and anything else hosting the PowerShell engine — the equivalent of calling Start-Transcript in every session. Two answers come out of this key. First, whether transcripts should exist for the period under examination. Second, and available from no other artifact, WHERE they were written: the policy's OutputDirectory setting redirects transcripts away from the documented default of each user's Documents directory, and a remote or attacker-chosen directory means the transcripts an examiner needs are not on the host at all. Microsoft warns that a shared OutputDirectory exposes one user's transcripts to others, which is also why a redirected directory is worth reading as an exposure, not just as a path.",
    mitre_techniques: &["T1562.002", "T1059.001"],
    fields: &[
        FieldSchema {
            name: "enable_transcripting",
            value_type: ValueType::Integer,
            description: "1 = transcription on for every PowerShell host on the system, so transcripts should exist for the period; 0 or absent = transcripts were written only where Start-Transcript was called explicitly",
            is_uid_component: true,
        },
        FieldSchema {
            name: "output_directory",
            value_type: ValueType::Text,
            description: "The policy's OutputDirectory setting — where transcripts were written. Absent means the documented default, a file under each user's Documents directory whose name includes PowerShell_transcript plus computer name and start time. A UNC or non-default path tells the examiner to collect from there, and is the only artifact that reveals the redirection",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until the value is changed or the policy is reapplied"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "powershell_transcripts",
        "powershell_script_block_logging_policy",
        "powershell_module_logging_policy",
    ],
    sources: &[
        // ADMX mapping: Registry Key Name Software\Policies\Microsoft\Windows\PowerShell\Transcription,
        // Registry Value Name EnableTranscripting; names the OutputDirectory setting
        // and the default transcript location and filename pattern.
        "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-powershellexecutionpolicy",
        // Policy description: transcription applies to any application hosting the
        // PowerShell engine, and the OutputDirectory shared-location warning.
        "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Transcription can also be started per session with Start-Transcript, so transcripts may exist with the policy disabled",
        "A redirected OutputDirectory means the host holds no transcripts for the period even though transcription was on — read the path before reporting that transcripts are missing",
        "The setting exists under both Computer and User configuration, with the computer setting documented as taking precedence",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until changed or reapplied by policy",
};

// ── Default administrative shares ─────────────────────────────────────────────

/// `AutoShareServer` / `AutoShareWks` — whether C$ and ADMIN$ were published.
///
/// Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/remove-administrative-shares>
/// Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/problems-administrative-shares-missing>
pub(crate) static LANMAN_AUTO_SHARE_ADMIN: ArtifactDescriptor = ArtifactDescriptor {
    id: "lanman_auto_share_admin",
    name: "Administrative Share Policy (AutoShareServer / AutoShareWks)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\LanmanServer\Parameters",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The two REG_DWORD values that decide whether Windows automatically publishes the hidden administrative shares — <DriveLetter>$ for each shared root volume and ADMIN$ for remote administration. Microsoft documents AutoShareServer set to 0 as the way to stop Windows automatically creating administrative shares, notes that this does not apply to IPC$ or to manually created shares, and states that when the values do not exist there is no need to create them because the default behaviour is to create the administrative shares automatically. This is the precondition behind any `net use \\\\host\\C$` pivot: a 0 here means the administrative shares were not published automatically, a different question from the explicitly created shares enumerated under LanmanServer\\Shares — read both keys rather than inferring one from the other. The values also read in the other direction — Microsoft's guidance treats administrative shares that stay missing even with the values set to 1 as a sign the host is running malicious software that removes them at startup.",
    mitre_techniques: &["T1021.002", "T1070"],
    fields: &[
        // Source: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/remove-administrative-shares
        FieldSchema {
            name: "auto_share_server",
            value_type: ValueType::Integer,
            description: "REG_DWORD documented for Windows Server: 0 = Windows does not automatically create the administrative shares (IPC$ and manually created shares are unaffected); 1 or absent = they are created automatically. Read it before accepting that C$/ADMIN$ were reachable for an alleged SMB pivot",
            is_uid_component: true,
        },
        // Source: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/problems-administrative-shares-missing
        FieldSchema {
            name: "auto_share_wks",
            value_type: ValueType::Integer,
            description: "The workstation-side counterpart checked under the same key: 0 suppresses automatic creation, 1 or absent leaves the default in force. Microsoft's own procedure inspects both values together, so report the pair rather than one",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until the values are changed; the Server service must be restarted for a change to take effect"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[
        "network_shares_server",
        "local_account_token_filter_policy",
        "smb_server_require_signing",
    ],
    sources: &[
        // Registry subkey, REG_DWORD type, the value-0 behaviour, and the exclusion
        // of IPC$ and manually created shares.
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/remove-administrative-shares",
        // KB842715: both values checked under LanmanServer\Parameters, the absent-means-default
        // statement, and the malware interpretation when shares stay missing.
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/problems-administrative-shares-missing",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Absence of both values is the default state and means the administrative shares were published — do not read a missing value as 'shares disabled'",
        "Hardening baselines legitimately set these to 0, so a 0 is a configuration finding rather than an intrusion finding on its own",
        "The values describe the configuration at acquisition; a change takes effect only after the Server service restarts, so the running state during the period examined may differ",
        "IPC$ is unaffected by these values, so named-pipe access (and the remote-registry and service-control paths that ride it) can persist with the admin shares suppressed",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry values; persist until explicitly changed",
};
