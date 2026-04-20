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
        "https://attack.mitre.org/techniques/T1053/005/",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
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
        "https://attack.mitre.org/techniques/T1021/001/",
        "https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/",
    ],
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
        "https://attack.mitre.org/techniques/T1021/001/",
    ],
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
        "https://attack.mitre.org/techniques/T1021/001/",
    ],
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
        "https://attack.mitre.org/techniques/T1021/006/",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
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
        "https://attack.mitre.org/techniques/T1047/",
        "https://www.fireeye.com/blog/threat-research/2019/03/windows-management-instrumentation-wmi-offense-defense-and-forensics.html",
    ],
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
        "https://attack.mitre.org/techniques/T1197/",
        "https://isc.sans.edu/forums/diary/Investigating+Windows+BITS+Activity/23281/",
    ],
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
        "https://attack.mitre.org/techniques/T1562/001/",
        "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker",
    ],
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
    sources: &["https://attack.mitre.org/techniques/T1562/001/"],
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
        "https://attack.mitre.org/techniques/T1562/001/",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
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
        "https://attack.mitre.org/techniques/T1562/004/",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
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
        "https://attack.mitre.org/techniques/T1014/",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
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
        "https://attack.mitre.org/techniques/T1550/002/",
        "https://github.com/Yamato-Security/hayabusa-rules",
    ],
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
        "https://attack.mitre.org/techniques/T1210/",
        "https://www.secura.com/blog/zero-logon",
    ],
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
    sources: &["https://attack.mitre.org/techniques/T1021/002/"],
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
    meaning: "Records USB device connect (2003) and disconnect (2100) events at the driver framework level. Provides another timestamp source for USB forensics, often more precise than registry last-write times.",
    mitre_techniques: &["T1052.001"],
    fields: &[
        FieldSchema { name: "device_id", value_type: ValueType::Text, description: "USB device ID", is_uid_component: true },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["usb_stor_enum", "evtx_kernel_pnp"],
    sources: &["https://www.sans.org/blog/windows-usb-forensics-part-2/"],
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
        "https://attack.mitre.org/techniques/T1003/001/",
        "https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection",
    ],
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
    sources: &["https://attack.mitre.org/techniques/T1553/004/"],
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
    sources: &["https://attack.mitre.org/techniques/T1059/001/"],
};
