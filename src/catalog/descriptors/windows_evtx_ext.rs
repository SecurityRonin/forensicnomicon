//! Extended Windows Event Log channel descriptors.
//!
//! Sources: Hayabusa rules, Chainsaw, SigmaHQ, EVTX-ATTACK-SAMPLES,
//! Microsoft event documentation, Yamato-Security hayabusa-rules.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactType, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

pub(crate) static EVTX_TASK_SCHEDULER: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_task_scheduler",
    name: "Task Scheduler Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records scheduled task lifecycle: task registered (4698), enabled (4700), disabled (4701), updated (4702), and task action executed (4698/106). Critical for detecting persistence via scheduled tasks and T1053.005 activity.",
    mitre_techniques: &["T1053.005"],
    fields: &[
        FieldSchema { name: "task_name", value_type: ValueType::Text, description: "Scheduled task name", is_uid_component: true },
        FieldSchema { name: "action_path", value_type: ValueType::Text, description: "Executable path the task runs", is_uid_component: false },
    ],
    retention: Some("Default 1 MB, overwritten"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["scheduled_tasks_dir", "scheduled_task_registry_cache"],
    sources: &[
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Event log; may be cleared by attackers"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_RDP_CLIENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_rdp_client",
    name: "RDP Client Operational Log (outbound)",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records outbound RDP connection attempts (1024 = success, 1102 = disconnect). Shows which systems this machine connected to via RDP — lateral movement source artifact. Complements the registry-based RDP MRU.",
    mitre_techniques: &["T1021.001"],
    fields: &[
        FieldSchema { name: "server_name", value_type: ValueType::Text, description: "RDP target server hostname or IP", is_uid_component: true },
        FieldSchema { name: "event_id", value_type: ValueType::UnsignedInt, description: "1024=connect, 1102=disconnect", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["rdp_client_servers", "evtx_rdp_inbound", "rdp_bitmap_cache"],
    sources: &[
        "https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Outbound RDP; proves this host pivoted to another"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_RDP_INBOUND: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_rdp_inbound",
    name: "RDP Remote Connection Manager Log (inbound)",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records inbound RDP authentication (1149 = user authenticated without password prompt; used with NLA). Critical for detecting unauthorized remote access — shows source IP and authenticating user even before Security log logon event fires.",
    mitre_techniques: &["T1021.001", "T1078"],
    fields: &[
        FieldSchema { name: "source_ip", value_type: ValueType::Text, description: "Source IP address of the RDP connection", is_uid_component: true },
        FieldSchema { name: "username", value_type: ValueType::Text, description: "Authenticating username", is_uid_component: false },
    ],
    retention: Some("Default 20 MB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_rdp_client", "evtx_rdp_session", "evtx_security"],
    sources: &[
        "https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["1149 events confirm source IP before session; not easily faked"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_RDP_SESSION: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_rdp_session",
    name: "RDP Local Session Manager Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records RDP session lifecycle: logon (21), logoff (23), session disconnect (24), reconnect (25), session start (41). With source IP in event 21, this is the primary artifact for RDP session timeline reconstruction.",
    mitre_techniques: &["T1021.001", "T1563.002"],
    fields: &[
        FieldSchema { name: "username", value_type: ValueType::Text, description: "Session user", is_uid_component: true },
        FieldSchema { name: "source_ip", value_type: ValueType::Text, description: "Source IP (event 21)", is_uid_component: false },
        FieldSchema { name: "session_id", value_type: ValueType::UnsignedInt, description: "RDP session ID", is_uid_component: false },
    ],
    retention: Some("Default 20 MB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_rdp_inbound", "evtx_security"],
    sources: &[
        "https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Session lifecycle with timestamps; event 39 = RDP hijack"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_WINRM: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_winrm",
    name: "WinRM Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-WinRM%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records WinRM (Windows Remote Management) connection activity. Used by PowerShell remoting, CIM sessions, and tools like Evil-WinRM for lateral movement. Event 6 = WSMan session created; key lateral movement evidence source.",
    mitre_techniques: &["T1021.006", "T1059.001"],
    fields: &[
        FieldSchema { name: "connection_uri", value_type: ValueType::Text, description: "Target WSMan URI", is_uid_component: true },
        FieldSchema { name: "user", value_type: ValueType::Text, description: "Authenticating user", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_security", "powershell_history"],
    sources: &[
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Confirms PowerShell Remoting lateral movement with account"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_WMI_ACTIVITY: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_wmi_activity",
    name: "WMI Activity Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-WMI-Activity%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records WMI query and operation events (5857-5861). WMI is heavily abused for lateral movement, persistence (subscriptions), and reconnaissance. Event 5861 records new permanent event subscriptions — critical persistence indicator.",
    mitre_techniques: &["T1047", "T1546.003"],
    fields: &[
        FieldSchema { name: "namespace", value_type: ValueType::Text, description: "WMI namespace targeted", is_uid_component: true },
        FieldSchema { name: "query", value_type: ValueType::Text, description: "WQL query executed (5858)", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["wmi_subscriptions", "wmi_mof_dir", "evtx_security"],
    sources: &[
        "https://www.fireeye.com/blog/threat-research/2019/03/windows-management-instrumentation-wmi-offense-defense-and-forensics.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["5861 = permanent WMI subscription — near-certain persistence"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_BITS_CLIENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_bits_client",
    name: "BITS Client Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Bits-Client%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records BITS (Background Intelligent Transfer Service) job creation, progress, and completion (59=job created, 60=completed, 61=error). BITS is abused for stealthy file downloads and C2 — transfers appear as legitimate background Windows traffic.",
    mitre_techniques: &["T1197"],
    fields: &[
        FieldSchema { name: "job_name", value_type: ValueType::Text, description: "BITS job name", is_uid_component: true },
        FieldSchema { name: "url", value_type: ValueType::Text, description: "Download/upload URL", is_uid_component: false },
        FieldSchema { name: "local_path", value_type: ValueType::Text, description: "Local destination path", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["bits_db"],
    sources: &[
        "https://isc.sans.edu/forums/diary/Investigating+Windows+BITS+Activity/23281/",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_APPLOCKER: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_applocker",
    name: "AppLocker EXE and DLL Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-AppLocker%4EXE and DLL.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "AppLocker allow/block decisions for EXE and DLL execution (8002=allowed, 8004=blocked). Blocked events reveal attacker tool execution attempts; allowed events confirm LOLBin abuse or policy bypass techniques.",
    mitre_techniques: &["T1562.001", "T1218"],
    fields: &[
        FieldSchema { name: "file_path", value_type: ValueType::Text, description: "Path of the executable/DLL evaluated", is_uid_component: true },
        FieldSchema { name: "policy_name", value_type: ValueType::Text, description: "AppLocker rule that matched", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_security"],
    sources: &[
        "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_APPLOCKER_SCRIPT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_applocker_script",
    name: "AppLocker MSI and Script Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-AppLocker%4MSI and Script.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "AppLocker decisions for script (.ps1, .vbs, .js, .cmd) and MSI execution. Reveals script-based attack tool execution attempts and bypass techniques (e.g., encoded PowerShell, .hta files).",
    mitre_techniques: &["T1562.001", "T1059"],
    fields: &[
        FieldSchema { name: "file_path", value_type: ValueType::Text, description: "Script or MSI path evaluated", is_uid_component: true },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_applocker", "evtx_powershell"],
    sources: &[
        "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_DEFENDER: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_defender",
    name: "Windows Defender Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records Defender detections (1116=malware detected, 1117=action taken), real-time protection state changes (5001=disabled), scan events, and exclusion modifications. Detection events often directly name attacker tools; disablement events are critical indicators.",
    mitre_techniques: &["T1562.001", "T1036"],
    fields: &[
        FieldSchema { name: "threat_name", value_type: ValueType::Text, description: "Malware/PUA name detected", is_uid_component: true },
        FieldSchema { name: "file_path", value_type: ValueType::Text, description: "Path of the detected file", is_uid_component: false },
        FieldSchema { name: "action", value_type: ValueType::Text, description: "Action taken (quarantine, remove, allow)", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_security", "evtx_system"],
    sources: &[
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Detection events survive file deletion; tamper events are highly suspicious"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_FIREWALL: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_firewall",
    name: "Windows Firewall with Advanced Security Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records firewall rule additions (2004), deletions (2006), and setting changes (2009). Attackers commonly open firewall ports (for C2/reverse shells) or disable the firewall entirely — these events capture those modifications.",
    mitre_techniques: &["T1562.004"],
    fields: &[
        FieldSchema { name: "rule_name", value_type: ValueType::Text, description: "Firewall rule name", is_uid_component: true },
        FieldSchema { name: "rule_action", value_type: ValueType::Text, description: "Allow or Block", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_security", "evtx_system"],
    sources: &[
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_CODE_INTEGRITY: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_code_integrity",
    name: "Code Integrity Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-CodeIntegrity%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records kernel driver and DLL signature violations (3001-3034). Event 3001 = unsigned driver load attempted; critical for detecting rootkits and malicious kernel modules that bypass driver signing requirements (BYOVD attacks).",
    mitre_techniques: &["T1014", "T1068", "T1553.006"],
    fields: &[
        FieldSchema { name: "file_path", value_type: ValueType::Text, description: "Path of the unsigned/invalid file", is_uid_component: true },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_system"],
    sources: &[
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_NTLM: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_ntlm",
    name: "NTLM Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-NTLM%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records NTLM authentication events when NTLM audit policy is enabled. Shows NTLM challenge/response pairs that may indicate pass-the-hash attacks, NTLM relay, or legacy application authentication from unexpected sources.",
    mitre_techniques: &["T1550.002", "T1187"],
    fields: &[
        FieldSchema { name: "user_name", value_type: ValueType::Text, description: "Authenticating username", is_uid_component: true },
        FieldSchema { name: "workstation_name", value_type: ValueType::Text, description: "Source workstation", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_security", "dcc2_cache"],
    sources: &[
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_PRINT_SERVICE: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_print_service",
    name: "Print Service Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-PrintService%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records print operations and driver loads. Critical for PrintNightmare (CVE-2021-34527) and print spooler exploitation analysis — event 316 records driver installation which attackers abuse to load malicious DLLs as SYSTEM.",
    mitre_techniques: &["T1068", "T1574"],
    fields: &[
        FieldSchema { name: "printer_name", value_type: ValueType::Text, description: "Printer or driver name", is_uid_component: true },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["print_monitors"],
    sources: &[
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_NETLOGON: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_netlogon",
    name: "Netlogon Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-Netlogon%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records Netlogon service events including Zerologon (CVE-2020-1472) exploitation attempts (5827-5829), secure channel establishment, and domain authentication failures. Critical for domain compromise and lateral movement investigations.",
    mitre_techniques: &["T1210", "T1078.002"],
    fields: &[
        FieldSchema { name: "machine_name", value_type: ValueType::Text, description: "Machine authenticating via Netlogon", is_uid_component: true },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_security", "ntds_dit"],
    sources: &[
        "https://www.secura.com/blog/zero-logon",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["5827/5828 = ZeroLogon exploitation attempt — very low false-positive rate"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_SMB_CLIENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_smb_client",
    name: "SMB Client Security Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-SMBClient%4Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records SMB client security events including failed authentication (31001), unauthorized access attempts, and SMB signing violations. Useful for detecting PsExec lateral movement and SMB relay attack victims.",
    mitre_techniques: &["T1021.002", "T1550.002"],
    fields: &[
        FieldSchema { name: "server_name", value_type: ValueType::Text, description: "SMB server targeted", is_uid_component: true },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_security", "network_drives"],
    sources: &[
        "https://github.com/Yamato-Security/hayabusa-rules",
        "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_NETWORK_PROFILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_network_profile",
    name: "Network Profile Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-NetworkProfile%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records network connect/disconnect events with network name and category (domain/private/public). Provides precise timestamps for when the machine joined or left a network — valuable for placing a device at a location or detecting rogue network connections.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "network_name", value_type: ValueType::Text, description: "Network profile name", is_uid_component: true },
        FieldSchema { name: "category", value_type: ValueType::Text, description: "Domain/Private/Public classification", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["networklist_profiles", "wifi_profiles"],
    sources: &["https://github.com/Yamato-Security/hayabusa-rules"],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_KERNEL_PNP: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_kernel_pnp",
    name: "Kernel PnP Device Configuration Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Kernel-PnP%4Device Configuration.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records hardware device installation events with timestamps. Complements USBSTOR registry and setupapi.dev.log with precise event timestamps for USB and other device connections — critical for USB forensics timeline.",
    mitre_techniques: &["T1052.001"],
    fields: &[
        FieldSchema { name: "device_instance_id", value_type: ValueType::Text, description: "PnP device instance ID", is_uid_component: true },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["usb_stor_enum", "setupapi_dev_log", "usb_enum"],
    sources: &[
        "https://www.sans.org/blog/computer-forensic-guide-to-profiling-usb-device-thumbdrives-on-win7-xp-2003/",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_DRIVER_FRAMEWORKS: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_driver_frameworks",
    name: "DriverFrameworks-UserMode Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records USB device connect (2003) and disconnect (2100) events at the driver framework level. Provides another timestamp source for USB forensics, often more precise than registry last-write times. CAVEAT: this channel is DISABLED BY DEFAULT on modern Windows (Win10/11) and \"doesn't provide much depth\" even when enabled — per Carvey 2026 it must be turned on proactively (wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true) before an incident, otherwise post-hoc collection yields nothing. When empty, fall back to USBSTOR registry keys, EMDMgmt (ReadyBoost), setupapi.dev.log first-install timestamps, the Microsoft-Windows-Partition/Diagnostic channel, and MsiInstaller records in Application.evtx (for installs from removable media). Also note: smartphones and digital cameras typically enumerate via MTP/PTP rather than USBSTOR, so this channel and the classic USB registry pivots may both miss them entirely.",
    mitre_techniques: &["T1052.001"],
    fields: &[
        FieldSchema { name: "device_id", value_type: ValueType::Text, description: "USB device ID", is_uid_component: true },
    ],
    retention: Some("Default 1 MB; channel DISABLED by default on Win10+"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["usb_stor_enum", "evtx_kernel_pnp", "evtx_application_msiinstaller"],
    sources: &[
        "https://www.sans.org/blog/windows-usb-forensics-part-2/",
        "https://windowsir.blogspot.com/2026/02/devices.html",
        "https://windowsir.blogspot.com/2022/05/usb-devices-redux.html",
        "https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_LSA_PROTECTION: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_lsa_protection",
    name: "LSA Protection Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-LSA%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records LSA (Local Security Authority) protection events including code injection attempts into lsass.exe (3065/3066). Critical for detecting credential dumping attempts blocked by Credential Guard or PPL protection.",
    mitre_techniques: &["T1003.001"],
    fields: &[
        FieldSchema { name: "caller_process", value_type: ValueType::Text, description: "Process attempting to inject into LSASS", is_uid_component: true },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_security", "lsa_secrets"],
    sources: &[
        "https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["PPL changes indicate credential dumping preparation"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_CAPI2: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_capi2",
    name: "CAPI2 Operational Log (certificate validation)",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-CAPI2%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records certificate validation events, chain building (11), and revocation checks (53/70). Reveals SSL/TLS certificate usage for C2 traffic, code-signing certificate validation for malware execution, and certificate abuse in lateral movement.",
    mitre_techniques: &["T1553.004", "T1071.001"],
    fields: &[
        FieldSchema { name: "cert_subject", value_type: ValueType::Text, description: "Certificate subject being validated", is_uid_component: true },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["machine_cert_store", "user_cert_private_key"],
    sources: &[
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/enable-debug-logging-capi2",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_POWERSHELL_CLASSIC: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_powershell_classic",
    name: "Windows PowerShell Classic Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Windows PowerShell.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Legacy PowerShell event log (pre-5.0 style). Events 400 (engine start) and 600 (provider start) record PowerShell session initiation and can show HostApplication (the full command line). Complements the Operational log for older PowerShell versions.",
    mitre_techniques: &["T1059.001"],
    fields: &[
        FieldSchema { name: "host_application", value_type: ValueType::Text, description: "Command or script that launched PowerShell", is_uid_component: true },
    ],
    retention: Some("Default 15 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_powershell", "powershell_history"],
    sources: &[
        "https://www.sans.org/blog/powershell-logging-for-the-blue-team/",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Group C: Additional EVTX Channels ────────────────────────────────────────

pub(crate) static EVTX_DNS_CLIENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_dns_client",
    name: "DNS Client Operational Event Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-DNS-Client%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Windows DNS client query/response log. DISABLED by default — must be enabled via Group Policy or: wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true. Key EventIDs: 3008 (DNS query sent — includes QueryName, QueryType, QueryResults, InterfaceIndex), 3020 (DNS response received). Forensically critical for detecting C2 channel activity: reveals domain lookups even without network packet capture. Compare QueryName values against threat intel feeds, look for DGA-pattern names, excessive NXDOMAIN responses (T1071.004 DNS C2), and tunneling indicators (long labels, high-entropy names).",
    mitre_techniques: &["T1071.004"],
    fields: &[
        FieldSchema { name: "event_id", value_type: ValueType::UnsignedInt, description: "3008=query sent, 3020=response received", is_uid_component: false },
        FieldSchema { name: "query_name", value_type: ValueType::Text, description: "DNS name queried", is_uid_component: true },
        FieldSchema { name: "query_type", value_type: ValueType::UnsignedInt, description: "DNS record type (1=A, 28=AAAA, 15=MX, 16=TXT)", is_uid_component: false },
        FieldSchema { name: "query_results", value_type: ValueType::Text, description: "Resolved IP addresses or NXDOMAIN", is_uid_component: false },
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Event timestamp (UTC)", is_uid_component: false },
    ],
    retention: Some("Disabled by default; when enabled, default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_security", "networklist_profiles"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/win32/ndf/microsoft-windows-dns-client",
        "https://github.com/palantir/windows-event-forwarding/tree/master/group-policy-objects",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static EVTX_TERMINAL_SERVICES: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_terminal_services",
    name: "Terminal Services Local Session Manager Operational Log",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "TerminalServices-LocalSessionManager/Operational log. Primary artifact for RDP lateral movement destination analysis. Key EventIDs: 21 (session logon — includes Source Network Address = attacker IP), 22 (shell start), 23 (session logoff), 24 (session disconnect), 25 (session reconnect). EventID 21 with a non-loopback Source Network Address = RDP inbound connection. Combined with evtx_rdp_inbound for full RDP session reconstruction. Note: 'localhost' or '127.0.0.1' in Source Network Address indicates console session, not remote.",
    mitre_techniques: &["T1021.001"],
    fields: &[
        FieldSchema { name: "event_id", value_type: ValueType::UnsignedInt, description: "21=logon, 22=shell, 23=logoff, 24=disconnect, 25=reconnect", is_uid_component: false },
        FieldSchema { name: "user", value_type: ValueType::Text, description: "Username of the session user (Domain\\Username format)", is_uid_component: true },
        FieldSchema { name: "session_id", value_type: ValueType::UnsignedInt, description: "RDP/Terminal Services session number", is_uid_component: false },
        FieldSchema { name: "source_network_address", value_type: ValueType::Text, description: "Source IP address of RDP client (attacker IP on event 21)", is_uid_component: true },
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Event timestamp (UTC)", is_uid_component: false },
    ],
    retention: Some("Default 20 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_rdp_inbound", "evtx_security", "evtx_rdp_client"],
    sources: &[
        "https://www.13cubed.com/downloads/rdp_forensics.pdf",
        "https://dfironthemountain.wordpress.com/2019/02/15/rdp-event-log-dfir/",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

/// Microsoft-Windows-Application-Experience/Program-Telemetry — driver-block
/// validation channel.
///
/// Per Carvey's "Events Ripper Update" (windowsir.blogspot.com, 2023-06-05),
/// Event ID 875 records when Windows blocks a driver from loading via the
/// Driver Block List / vulnerable-driver enforcement (HVCI / Microsoft
/// Vulnerable Driver Blocklist). This is the validation pivot for EDR
/// telemetry that shows a `sc.exe create` or driver-load attempt: EDR sees
/// the command launched, but only Event 875 confirms whether the driver
/// actually loaded or was blocked. Carvey added an `appissue.pl` plugin
/// specifically for this — without it, analysts assume blocked driver-load
/// attacks (BYOVD, T1068) succeeded when they did not.
pub(crate) static EVTX_APPLICATION_EXPERIENCE_TELEMETRY: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_application_experience_telemetry",
    name: "Application-Experience Program-Telemetry Log (driver-block validation)",
    artifact_type: ArtifactType::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Application-Experience%4Program-Telemetry.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Application-Experience / Program-Telemetry channel. Key Event ID: \
              875 — driver blocked from loading by the Microsoft Vulnerable Driver Blocklist \
              / Driver Block List / HVCI policy (T1068 BYOVD validation). When EDR shows a \
              driver-load attempt or `sc.exe create type= kernel`, 875 is the host artifact \
              that confirms whether the driver actually loaded or was blocked. Absence of an \
              875 record alongside an EDR-observed driver-load command implies the driver \
              successfully loaded. Pair with System.evtx 7045 (service installed) and \
              CodeIntegrity (5038/3023/3033) for the full BYOVD chain.",
    mitre_techniques: &["T1068", "T1543.003"],
    fields: &[
        FieldSchema {
            name: "event_id",
            value_type: ValueType::UnsignedInt,
            description: "875 = driver blocked from loading",
            is_uid_component: false,
        },
        FieldSchema {
            name: "driver_path",
            value_type: ValueType::Text,
            description: "Path of the driver that was blocked from loading",
            is_uid_component: true,
        },
        FieldSchema {
            name: "timestamp",
            value_type: ValueType::Timestamp,
            description: "Event timestamp (UTC)",
            is_uid_component: false,
        },
    ],
    retention: Some("Default 1 MB; rolls over on busy systems"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_system", "evtx_code_integrity", "evtx_security"],
    sources: &[
        // Source: https://windowsir.blogspot.com/2023/06/events-ripper-update_5.html
        // — Carvey adds appissue.pl Events Ripper plugin for Event ID 875
        //   (driver block) as validation pivot for EDR-observed driver-load
        //   attempts; cites Josh's Twitter finding and
        //   intelligentsystemsmonitoring.com/tag/event-875/ as channel
        //   reference.
        "https://windowsir.blogspot.com/2023/06/events-ripper-update_5.html",
        // Source: https://intelligentsystemsmonitoring.com/tag/event-875/
        // — Channel-level documentation that 875 in the
        //   Application-Experience / Program-Telemetry log denotes a blocked
        //   driver load.
        "https://intelligentsystemsmonitoring.com/tag/event-875/",
        // Source: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules
        // — Microsoft Vulnerable Driver Blocklist / Driver Block List policy
        //   that produces these block events when HVCI / WDAC enforcement is
        //   active.
        "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};
