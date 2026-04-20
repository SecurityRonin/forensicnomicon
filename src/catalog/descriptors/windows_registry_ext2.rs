//! Extended Windows registry threat-hunting artifact descriptors — Phase 2.
//!
//! Sources: RECmd Kroll_Batch.reb, RECmd_Batch_MC.reb (EricZimmerman), SigmaHQ,
//! MITRE ATT&CK, Elastic Detection Rules, CrowdStrike threat intelligence.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactType, DataScope, Decoder, FieldSchema, HiveTarget, OsScope,
    TriagePriority, ValueType,
};

// ── WinLogon credential exposure ─────────────────────────────────────────────

pub(crate) static WINLOGON_AUTOADMIN_LOGON: ArtifactDescriptor = ArtifactDescriptor {
    id: "winlogon_autoadmin_logon",
    name: "WinLogon AutoAdminLogon",
    artifact_type: ArtifactType::RegistryValue,
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
        "https://attack.mitre.org/techniques/T1547/001/",
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

pub(crate) static WINLOGON_DEFAULT_PASSWORD: ArtifactDescriptor = ArtifactDescriptor {
    id: "winlogon_default_password",
    name: "WinLogon DefaultPassword",
    artifact_type: ArtifactType::RegistryValue,
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
        "https://attack.mitre.org/techniques/T1552/002/",
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

pub(crate) static WINLOGON_DEFAULT_USERNAME: ArtifactDescriptor = ArtifactDescriptor {
    id: "winlogon_default_username",
    name: "WinLogon DefaultUserName",
    artifact_type: ArtifactType::RegistryValue,
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
        "https://attack.mitre.org/techniques/T1552/002/",
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon",
    ],
};

// ── LogonUI last logged-on user ───────────────────────────────────────────────

pub(crate) static LOGONUI_LAST_LOGGEDON_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "logonui_last_loggedon_user",
    name: "LogonUI LastLoggedOnUser",
    artifact_type: ArtifactType::RegistryValue,
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
        "https://attack.mitre.org/techniques/T1078/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── PortProxy (netsh port forwarding) ────────────────────────────────────────

pub(crate) static PORTPROXY_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "portproxy_config",
    name: "PortProxy v4tov4 TCP",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1572/",
        "https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── Windows Defender tampering ────────────────────────────────────────────────

pub(crate) static WINDOWS_DEFENDER_EXCLUSIONS_LOCAL: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_defender_exclusions_local",
    name: "Windows Defender Exclusions",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1562/001/",
        "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_windows_defender_exclusion_added.yml",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

pub(crate) static WINDOWS_DEFENDER_DISABLED_AV: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_defender_disabled_av",
    name: "Windows Defender DisableAntiVirus",
    artifact_type: ArtifactType::RegistryValue,
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
        "https://attack.mitre.org/techniques/T1562/001/",
        "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_windows_defender_disabled.yml",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

pub(crate) static WINDOWS_DEFENDER_REALTIME: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_defender_realtime",
    name: "Windows Defender Real-Time Protection",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1562/001/",
        "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_windows_defender_realtime_protection_disabled.yml",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── Office macro trust records ────────────────────────────────────────────────

pub(crate) static MS_OFFICE_TRUSTED_DOCS: ArtifactDescriptor = ArtifactDescriptor {
    id: "ms_office_trusted_docs",
    name: "MS Office Trusted Documents (TrustRecords)",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1566/001/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://docs.microsoft.com/en-us/deployoffice/security/trusted-documents",
    ],
};

// ── VSS / shadow copy evasion ─────────────────────────────────────────────────

pub(crate) static VSS_FILES_NOT_TO_SNAPSHOT: ArtifactDescriptor = ArtifactDescriptor {
    id: "vss_files_not_to_snapshot",
    name: "VSS FilesNotToSnapshot",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1490/",
        "https://www.bleepingcomputer.com/news/security/revil-ransomware-has-a-secret-backdoor-and-its-been-used/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

pub(crate) static VSS_FILES_NOT_TO_BACKUP: ArtifactDescriptor = ArtifactDescriptor {
    id: "vss_files_not_to_backup",
    name: "VSS FilesNotToBackup",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1490/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── IFEO SilentProcessExit (T1546.012) ───────────────────────────────────────

pub(crate) static IFEO_SILENT_EXIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "ifeo_silent_exit",
    name: "IFEO SilentProcessExit",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1546/012/",
        "https://www.deepinstinct.com/blog/ifeo-injections",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── .exe handler hijack ───────────────────────────────────────────────────────

pub(crate) static EXEFILE_SHELL_OPEN_SOFTWARE: ArtifactDescriptor = ArtifactDescriptor {
    id: "exefile_shell_open_software",
    name: "Exefile Shell Open Command (HKLM SOFTWARE)",
    artifact_type: ArtifactType::RegistryValue,
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
        "https://attack.mitre.org/techniques/T1546/001/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

pub(crate) static EXEFILE_SHELL_OPEN_USRCLASS: ArtifactDescriptor = ArtifactDescriptor {
    id: "exefile_shell_open_usrclass",
    name: "Exefile Shell Open Command (UsrClass.dat)",
    artifact_type: ArtifactType::RegistryValue,
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
        "https://attack.mitre.org/techniques/T1546/001/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── RDP shadow sessions / credential abuse ────────────────────────────────────

pub(crate) static RDP_SHADOW_SESSIONS: ArtifactDescriptor = ArtifactDescriptor {
    id: "rdp_shadow_sessions",
    name: "RDP Shadow Session Policy",
    artifact_type: ArtifactType::RegistryValue,
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
        "https://attack.mitre.org/techniques/T1021/001/",
        "https://attack.mitre.org/techniques/T1563/002/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

pub(crate) static RESTRICTED_ADMIN_RDP: ArtifactDescriptor = ArtifactDescriptor {
    id: "restricted_admin_rdp",
    name: "Restricted Admin RDP (DisableRestrictedAdmin)",
    artifact_type: ArtifactType::RegistryValue,
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
        "https://attack.mitre.org/techniques/T1550/002/",
        "https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── Network shares ────────────────────────────────────────────────────────────

pub(crate) static NETWORK_SHARES_SERVER: ArtifactDescriptor = ArtifactDescriptor {
    id: "network_shares_server",
    name: "LanmanServer Shares",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1021/002/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── Sysinternals EULA (tool execution indicator) ──────────────────────────────

pub(crate) static SYSINTERNALS_EULA: ArtifactDescriptor = ArtifactDescriptor {
    id: "sysinternals_eula",
    name: "Sysinternals EulaAccepted",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1012/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://learn.microsoft.com/en-us/sysinternals/",
    ],
};

// ── MS Office Server Cache (Follina IOC) ──────────────────────────────────────

pub(crate) static MS_OFFICE_SERVER_CACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "ms_office_server_cache",
    name: "MS Office Server Cache",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1566/001/",
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── Cobalt Strike PowerShell IOC ──────────────────────────────────────────────

pub(crate) static POWERSHELL_COBALT_INFO: ArtifactDescriptor = ArtifactDescriptor {
    id: "powershell_cobalt_info",
    name: "PowerShell Cobalt Strike Info Key",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1059/001/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/RECmd_Batch_MC.reb",
        "https://www.crowdstrike.com/blog/registry-analysis-with-crowdresponse/",
    ],
};

// ── StartupApproved Run keys ──────────────────────────────────────────────────

pub(crate) static STARTUP_APPROVED_RUN_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "startup_approved_run_system",
    name: "StartupApproved Run (HKLM)",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1547/001/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

pub(crate) static STARTUP_APPROVED_RUN_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "startup_approved_run_user",
    name: "StartupApproved Run (HKCU)",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1547/001/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── Task Scheduler cache ──────────────────────────────────────────────────────

pub(crate) static TASKCACHE_TASKS_PATH: ArtifactDescriptor = ArtifactDescriptor {
    id: "taskcache_tasks_path",
    name: "TaskCache Tree (Scheduled Task Paths)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Registry tree mirroring the Task Scheduler folder hierarchy. Each subkey is a task path with an Id GUID and SD (security descriptor). Attackers create scheduled tasks here for persistence; the registry copy survives deletion of the XML task file and is faster to parse than the XML store.",
    mitre_techniques: &["T1053.005"],
    fields: &[FieldSchema {
        name: "task_path",
        value_type: ValueType::Text,
        description: "Full scheduled task path (subkey hierarchy relative to Tree)",
        is_uid_component: true,
    }],
    retention: Some("Persistent until task deletion"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["ifeo_silent_exit", "startup_approved_run_system"],
    sources: &[
        "https://attack.mitre.org/techniques/T1053/005/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://nasbench.medium.com/a-deep-dive-into-windows-scheduled-tasks-and-the-processes-running-them-218d1eed4cce",
    ],
};

// ── User profile list ─────────────────────────────────────────────────────────

pub(crate) static PROFILE_LIST_USERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "profile_list_users",
    name: "ProfileList (User SIDs and Profile Paths)",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1087/001/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://learn.microsoft.com/en-us/windows/win32/sysinfo/profilelist",
    ],
};

// ── Registrar favorites ───────────────────────────────────────────────────────

pub(crate) static REGISTRAR_FAVORITES: ArtifactDescriptor = ArtifactDescriptor {
    id: "registrar_favorites",
    name: "Registrar Registry Editor Favorites",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1012/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── DHCP interface configuration ──────────────────────────────────────────────

pub(crate) static DHCP_IPV4_INTERFACE: ArtifactDescriptor = ArtifactDescriptor {
    id: "dhcp_ipv4_interface",
    name: "DHCP Interface IPv4 Configuration",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1016/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── NTFS last access update status ───────────────────────────────────────────

pub(crate) static NTFS_LAST_ACCESS_STATUS: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntfs_last_access_status",
    name: "NTFS Last Access Update Status",
    artifact_type: ArtifactType::RegistryValue,
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
        "https://attack.mitre.org/techniques/T1070/006/",
        "https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── Prefetch enabled/disabled ─────────────────────────────────────────────────

pub(crate) static PREFETCH_STATUS: ArtifactDescriptor = ArtifactDescriptor {
    id: "prefetch_status",
    name: "Prefetch Enable Status",
    artifact_type: ArtifactType::RegistryValue,
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
        "https://attack.mitre.org/techniques/T1070/",
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452747(v=ws.11)",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};

// ── Windows Firewall rules ────────────────────────────────────────────────────

pub(crate) static FIREWALL_RULES: ArtifactDescriptor = ArtifactDescriptor {
    id: "firewall_rules",
    name: "Windows Firewall Rules",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1562/004/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_firewall_rule_added.yml",
    ],
};

// ── Event log channel enable/disable status ───────────────────────────────────

pub(crate) static EVENT_LOG_CHANNEL_STATUS: ArtifactDescriptor = ArtifactDescriptor {
    id: "event_log_channel_status",
    name: "Event Log Channel Enabled/Disabled Status",
    artifact_type: ArtifactType::RegistryKey,
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
        "https://attack.mitre.org/techniques/T1562/002/",
        "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_disable_event_logging.yml",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
};
