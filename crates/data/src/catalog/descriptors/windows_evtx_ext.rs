//! Extended Windows Event Log channel descriptors.
//!
//! Sources: Hayabusa rules, Chainsaw, SigmaHQ, EVTX-ATTACK-SAMPLES,
//! Microsoft event documentation, Yamato-Security hayabusa-rules.
//!
//! The hand-written descriptors in Group D carry the Security-log families and
//! channel records the generated channel stubs cannot: explicit-credential
//! logons (4648), logon-failure status decoding (4625), service installation
//! (4697), account and group management (4720 / 4722-4726 / 4738 / 4798 / 4799
//! and the 472x-473x group events), SACL-driven object access (4656 / 4658 /
//! 4660 / 4663 / 4670), Window Station reconnect and disconnect (4778 / 4779),
//! the RdpCoreTS connection records, the Application-log crash pair (1000 /
//! 1001), the PowerShell 7 channel, auto-archived logs and the Eventlog
//! provider's audit-gap records (`Archive-<Log>-*.evtx` with 1104 / 1105, plus
//! the undocumented 1101 / 1106), and the target-side process lineage that
//! separates one remote-execution channel from another.
//!
//! Field names, value tables and message templates are taken from the Microsoft
//! Learn event reference, [MS-ERREF] NTSTATUS values, the Win32 and WMI
//! documentation, and mechanical dumps of the providers' own manifests; every
//! description is written here rather than copied.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

pub(crate) static EVTX_TASK_SCHEDULER: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_task_scheduler",
    name: "Task Scheduler Operational Log",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records scheduled task lifecycle and execution on the TaskScheduler provider's OWN channel. Its event ids are three digits, not the four-digit Security-log task events (4698 create / 4699 delete / 4700 enable / 4701 disable / 4702 update live in Security.evtx and are gated by an audit subcategory — cross-check both logs, they fail independently). The channel's own ids, read from the provider manifest: 106 task registered (records the registering account and the task path), 140 task registration updated, 141 task registration deleted, 142 task disabled, 129 a task process was created (names the task, the instance and the new PROCESS ID), 200 an action was launched (names the action — the executable the task runs — with the task name and instance id), 201 the action completed (repeats the action and adds the process RETURN CODE), 102 the task instance finished. Registration (106/140) and execution (129/200/201) are separate questions: a task registered and never run leaves only 106, and a task deleted after use leaves 141 with the 200/201 pair still recording what it ran. 141 is the cleanup step an actor takes after execution, so a 141 with no surviving task definition on disk is the shape to hunt.",
    mitre_techniques: &["T1053.005", "T1070.001"],
    fields: &[
        FieldSchema { name: "task_name", value_type: ValueType::Text, description: "Scheduled task name (the \\Folder\\TaskName path) — the join key across 106/140/141/200/201 and to the task XML on disk", is_uid_component: true },
        FieldSchema { name: "action_path", value_type: ValueType::Text, description: "Executable path the task runs, as recorded in the ActionName of events 200/201 — the binary to hash, timeline and check against the task XML still on disk", is_uid_component: false },
        FieldSchema { name: "event_id", value_type: ValueType::UnsignedInt, description: "106=registered, 140=registration updated, 141=registration deleted, 142=disabled, 129=task process created, 200=action started, 201=action completed, 102=task instance completed", is_uid_component: false },
        FieldSchema { name: "user_context", value_type: ValueType::Text, description: "Account that registered (106), updated (140) or deleted (141) the task — the attribution the execution events do not carry", is_uid_component: false },
        FieldSchema { name: "task_instance_id", value_type: ValueType::Guid, description: "Instance GUID joining one run's 129/200/201/102 records together; use it to pair an action with its own return code rather than pairing by time", is_uid_component: false },
        FieldSchema { name: "result_code", value_type: ValueType::UnsignedInt, description: "Process return code from event 201 — 0 is a clean exit; a non-zero value says the launched binary ran and failed, which still proves execution", is_uid_component: false },
        FieldSchema { name: "process_id", value_type: ValueType::UnsignedInt, description: "PID of the process the scheduler launched (event 129) — the pivot into process-creation records and into memory for the same run", is_uid_component: false },
    ],
    retention: Some("Default 1 MB, overwritten"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["scheduled_tasks_dir", "scheduled_task_registry_cache", "evtx_security"],
    sources: &[
        "https://github.com/Yamato-Security/hayabusa-rules",
        // Mechanical dump of the Microsoft-Windows-TaskScheduler provider manifest — the
        // channel, task name and message template of ids 102/106/129/140/141/142/200/201:
        "https://github.com/nasbench/EVTX-ETW-Resources",
        // Microsoft — 4699(S): A scheduled task was deleted (the Security-log counterpart):
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4699",
        // Microsoft — wevtutil: `gl <channel>` reads a channel's enabled state and size,
        // `sl <channel> /e:true` turns it on:
        "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Event log; may be cleared by attackers",
        "The channel can be turned off, and an empty log is then a configuration fact, not an empty task history — read the channel's own enabled state (wevtutil gl Microsoft-Windows-TaskScheduler/Operational) before reporting that nothing ran",
        "The literal channel name contains no space: Microsoft-Windows-TaskScheduler/Operational, stored as Microsoft-Windows-TaskScheduler%4Operational.evtx — a collector configured with a space matches no file and returns nothing",
        "Registration events (106/140/141) name the account; the execution events (129/200/201) do not — do not attribute a run to the registering user without the task definition or a separate process-creation record",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_RDP_CLIENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_rdp_client",
    name: "RDP Client Operational Log (outbound)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records outbound RDP connection attempts (1024 = success, 1102 = disconnect). Shows which systems this machine connected to via RDP — lateral movement source artifact. Complements the registry-based RDP MRU. EID 1029 records the connecting username as a case-sensitive Base64(SHA-256(UTF-16LE(username))) digest (provider Microsoft-Windows-TerminalServices-ClientActiveXCore), logged on the SOURCE/client host; the TraceMessage payload holds zero, one, or two hash-hash values (username and/or domain). Recover the plaintext by hashing candidate usernames through the same UTF-16LE->SHA-256->Base64 pipeline and matching the string (EvtxECmd's 1029 map does this automatically), then correlate against the DESTINATION host's TerminalServices-LocalSessionManager/Operational EID 21/22 and Security 4624 Type 10 to tie the source pivot to the target logon.",
    mitre_techniques: &["T1021.001"],
    fields: &[
        FieldSchema { name: "server_name", value_type: ValueType::Text, description: "RDP target server hostname or IP", is_uid_component: true },
        FieldSchema { name: "event_id", value_type: ValueType::UnsignedInt, description: "1024=connect, 1102=disconnect, 1029=connecting-username hash", is_uid_component: false },
        FieldSchema { name: "username_hash", value_type: ValueType::Text, description: "EID 1029: Base64(SHA-256(UTF-16LE(username))) of the connecting user (and optionally the domain), logged on the source host; one-way but wordlist-reversible by re-hashing candidate usernames", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["rdp_client_servers", "evtx_rdp_inbound", "rdp_bitmap_cache", "evtx_security"],
    sources: &[
        "https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/",
        // Stroz Friedberg / Aon — EID 1029 SHA-256+domain dual-hash + the three no-hash conditions:
        "https://www.strozfriedberg.com/",
        // Eric Zimmerman EvtxECmd — the 1029 map (channel/provider/Base64-SHA256 decode):
        "https://github.com/EricZimmerman/evtx",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Outbound RDP; proves this host pivoted to another",
        "No EID 1029 hash is logged when NLA is disabled on the target, when 'Save Credentials' is used, or on Windows 7 / Windows Server 2008 (which record no events in this log); Windows 8 records some events but not EID 1029 — absence of 1029 does NOT mean no RDP connection occurred",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_RDP_INBOUND: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_rdp_inbound",
    name: "RDP Remote Connection Manager Log (inbound)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records inbound RDP network connection events. EID 1149 label says 'User authentication succeeded' but fires on network connection established — before NLA credential verification. Shows source IP and claimed username. Critical for detecting unauthorized remote access — fires before the Security log logon event.",
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
    evidence_tier: None,
    evidence_caveats: &[
        "EID 1149 label says 'user authentication succeeded' but actually fires on network connection established — before NLA credential check; presence does NOT confirm a successful login",
        "Source IP and username fields are populated from the connection request, not from a validated authentication — treat as claimed identity until corroborated by Security EID 4624",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_RDP_SESSION: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_rdp_session",
    name: "RDP Local Session Manager Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_tier: None,
    evidence_caveats: &["Session lifecycle with timestamps; event 39 = RDP hijack"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_WINRM: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_winrm",
    name: "WinRM Operational Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_tier: None,
    evidence_caveats: &["Confirms PowerShell Remoting lateral movement with account"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_WMI_ACTIVITY: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_wmi_activity",
    name: "WMI Activity Operational Log",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-WMI-Activity%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records WMI operation and subscription events (5857-5861). WMI is heavily abused for lateral movement, persistence (subscriptions), and reconnaissance. Read the manifest's own message templates rather than the id alone. 5857: a provider started — '{ProviderName} provider started with result code {Code}. HostProcess = {HostProcess}; ProcessID = {ProcessID}; ProviderPath = {ProviderPath}', so it names the provider BINARY loaded into the host process; a provider path outside %SystemRoot%\\System32\\wbem is the detection surface for a registered malicious provider. 5858: an operation failed — 'Id; ClientMachine; User; ClientProcessId; Component; Operation; ResultCode; PossibleCause', and ClientMachine + User is the field pair that attributes a WMI call to a REMOTE origin host and account, while ResultCode decodes against the WBEM_E_* error constants. 5859/5860 record notification-query (temporary subscription) registration with the namespace, the query, the owner/user and the client machine; 5861 records a permanent consumer binding (Namespace; Eventfilter; Consumer) — the persistence triple. Pivot from a subscription to the process that RUNS it: an ActiveScriptEventConsumer body executes in scrcons.exe (Microsoft lists Scrcons.exe as the class's server), so a scrcons.exe execution record dates a subscription firing even when the consumer object has been deleted.",
    mitre_techniques: &["T1047", "T1546.003"],
    fields: &[
        FieldSchema { name: "namespace", value_type: ValueType::Text, description: "WMI namespace targeted (5859/5860/5861) — root\\subscription hosts the documented permanent subscriptions, but any namespace can, so enumerate rather than assume", is_uid_component: true },
        FieldSchema { name: "query", value_type: ValueType::Text, description: "The notification (WQL) query registered, from the NotificationQuery item of 5859/5860 — the trigger condition in the subscriber's own words", is_uid_component: false },
        FieldSchema { name: "event_id", value_type: ValueType::UnsignedInt, description: "5857=provider started, 5858=operation failed, 5859/5860=notification query registered, 5861=permanent consumer bound", is_uid_component: false },
        FieldSchema { name: "client_machine", value_type: ValueType::Text, description: "ClientMachine from 5858/5860 — the host the WMI call came FROM. On a 5858 recorded on a server this is the origin of remote WMI, the single field that turns an unattributed WMI operation into a lateral-movement source", is_uid_component: false },
        FieldSchema { name: "user", value_type: ValueType::Text, description: "The account the operation ran as (User/OwnerName). Pair with client_machine to name who reached this host over WMI", is_uid_component: false },
        FieldSchema { name: "client_process_id", value_type: ValueType::UnsignedInt, description: "ClientProcessId from 5858 — the PID on the CLIENT side, not this host; join it against that host's process records, never this one's", is_uid_component: false },
        FieldSchema { name: "operation", value_type: ValueType::Text, description: "The failed WMI operation text from 5858 (method call, class or query) — shows what was attempted even though it failed, which is often the recon itself", is_uid_component: false },
        FieldSchema { name: "result_code", value_type: ValueType::Text, description: "ResultCode from 5858 — decode against the WBEM_E_* constants; an access-denied result still proves the attempt and names the caller", is_uid_component: false },
        FieldSchema { name: "provider_path", value_type: ValueType::Text, description: "ProviderPath from 5857 — the provider DLL loaded into the WMI host process. Hash it and check its location: a provider registered from a user-writable path is a WMI extension the host was made to load", is_uid_component: false },
        FieldSchema { name: "host_process", value_type: ValueType::Text, description: "HostProcess and ProcessID from 5857 — the process hosting the provider, the pivot into process-creation records and memory for the same moment", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["wmi_subscriptions", "wmi_mof_dir", "evtx_security", "evtx_remote_execution_host_lineage"],
    sources: &[
        "https://www.fireeye.com/blog/threat-research/2019/03/windows-management-instrumentation-wmi-offense-defense-and-forensics.html",
        // Mechanical dump of the Microsoft-Windows-WMI-Activity provider manifest — the exact
        // message templates and data-item names of 5857/5858/5859/5860/5861:
        "https://github.com/nasbench/EVTX-ETW-Resources",
        // Microsoft — WMI error constants, the WBEM_E_* space a 5858 ResultCode decodes against:
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-error-constants",
        // Microsoft — ActiveScriptEventConsumer: the class's server is Scrcons.exe, and the
        // consumer does not run under Windows Script Host:
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "5861 = permanent WMI subscription — near-certain persistence",
        "5858 is an operation-FAILED record: a quiet log means operations succeeded, not that no remote WMI occurred — absence of 5858 is not absence of activity",
        "ClientProcessId in 5858 belongs to the calling host, so resolving it against this host's process list produces a false attribution",
        "5857 fires for every provider start, including the stock providers loaded during ordinary management traffic; the discriminator is the ProviderPath and its signer, not the event",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_BITS_CLIENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_bits_client",
    name: "BITS Client Operational Log",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Bits-Client%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records the BITS (Background Intelligent Transfer Service) job lifecycle (3=job created, 59=transfer started, 60=transfer stopped at Information level, 61=transfer stopped at Warning level). Events 60 and 61 carry identical message text and differ only by level and the hr status code. BITS is abused for stealthy file downloads and C2 — transfers appear as legitimate background Windows traffic.",
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Legitimate Windows Update and BITS-aware applications also generate these events",
        "Channel rotates and may not retain history of older transfers",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_APPLOCKER: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_applocker",
    name: "AppLocker EXE and DLL Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Only populated when AppLocker policy is configured and enforced",
        "Audit-only mode may suppress block evidence",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_APPLOCKER_SCRIPT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_applocker_script",
    name: "AppLocker MSI and Script Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Requires AppLocker script policy to be enabled",
        "Some script hosts (.NET, COM scriptlets) may bypass AppLocker enforcement",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_DEFENDER: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_defender",
    name: "Windows Defender Operational Log",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records Defender detections (1116=malware detected, 1117=action taken), real-time protection state changes (5001=disabled), scan events, and exclusion modifications. Detection events often directly name attacker tools; disablement events are critical indicators. The Path field of 1116 and 1117 is the part most often mis-parsed: Microsoft documents it as 'File path', but it is a semicolon-delimited list of typed <scheme>:_<value> references covering the file, the archive that contained it, the download URL and the downloader, the responsible process with its PID and creation time, and any Run key, Startup shortcut or scheduled task the detection touched. A tool that reports Path as a single filename loses the download URL, the responsible PID and the persistence key, and files archive-member and in-memory detections as on-disk ones. The same grammar appears on the older Microsoft Antimalware provider in the System channel, so parse both the same way. That reading is undocumented by Microsoft and is established from raw EVTX XML in unrelated 2017, 2020, 2023 and 2024 captures together with several independent parsers and mappings that agree.",
    mitre_techniques: &["T1562.001", "T1036"],
    fields: &[
        FieldSchema { name: "threat_name", value_type: ValueType::Text, description: "Malware/PUA name detected", is_uid_component: true },
        FieldSchema { name: "path", value_type: ValueType::Text, description: "The EVTX Path data item of 1116/1117 — NOT a file path, despite the name and despite Microsoft documenting only 'Path: File path'. It is a SEMICOLON-DELIMITED LIST of typed resource references, each <scheme>:_<value>, naming every object the detection touched. Schemes seen in raw <Data Name=\"Path\"> XML: file:_<path>, which may carry a nested-content suffix ->(<tag>) or -><member> such as ->(Zip), ->(VFS:svchost.exe) or ->(UTF-16LE); containerfile:_<archive path>, the OUTERMOST archive, whose members follow as separate file:_ segments; webfile:_<local path>|<source URL>|<downloader>, three '|'-delimited parts; process:_pid:<PID>,ProcessStart:<FILETIME>; behavior:_pid:<PID>:<N>; amsi:_<NT device path of the AMSI host process>; regkey:_ and runkey:_ over HKLM\\... or HKCU@<SID>\\...; startup:_<Startup-folder .lnk path>; taskscheduler:_<scheduled task path>. Split on ';' and TRIM — a trailing space is optional and varies by build — and match the scheme case-insensitively. The responsible process is frequently ONLY here: when Process Name reads Unknown, the PID still sits in the process:_ segment or in webfile:_'s third component. Undocumented by Microsoft; the grammar is established from raw <Data Name=\"Path\"> XML in unrelated 2017, 2020, 2023 and 2024 captures and corroborated by independent parsers and mappings", is_uid_component: false },
        FieldSchema { name: "process_start", value_type: ValueType::Timestamp, description: "The ProcessStart: token inside the Path field's process:_ and webfile:_ segments — a standard Windows FILETIME, an unsigned decimal count of 100-nanosecond intervals since 1601-01-01T00:00:00 UTC, absolute and in UTC. It is not boot-relative, not local time, and not relative to the event. It is the creation time of the process named by the adjacent pid:, and the (PID, ProcessStart) pair exists because PIDs are recycled — join to Sysmon 1 or Security 4688 on the PAIR, never on the PID alone. Undocumented by Microsoft; the FILETIME reading was checked against each record's own clock in two unrelated captures — ProcessStart:133173854939240064 decodes to 2023-01-05T09:44:53.924Z against that record's systemTime of 2023-01-05T09:44:55.1124563Z, and ProcessStart:132441294671252668 decodes to 2020-09-09T12:51:07.125Z against an event header reading 9/9/2020 5:52:10 AM on a UTC-7 host", is_uid_component: false },
        FieldSchema { name: "action", value_type: ValueType::Text, description: "Action taken (quarantine, remove, allow)", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_security", "evtx_system"],
    sources: &[
        "https://github.com/Yamato-Security/hayabusa-rules",
        // Microsoft's event reference — the ONLY vendor statement about the field is
        // "Path: File path" for both 1116 and 1117; the composite grammar is undocumented:
        "https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus",
        // A real 2017 1116/1117 EICAR capture carried verbatim in decoder comments — establishes
        // the ';' separator and webfile:_<local path>|<source URL>|<downloader>:
        "https://github.com/wazuh/wazuh/blob/master/ruleset/decoders/0380-windows_decoders.xml",
        // A Windows 11 / 2023 capture whose own systemTime brackets
        // ProcessStart:133173854939240064 — the independent oracle for the FILETIME reading:
        "https://github.com/wazuh/wazuh-documentation/blob/master/source/user-manual/capabilities/malware-detection/win-defender-logs-collection.rst",
        // Raw <Data> XML showing containerfile:_ with the ->(Zip) and ->(VFS:svchost.exe)
        // nested-member notation, and container and members as separate segments:
        "https://groups.google.com/g/ossec-list/c/dYC6Mk1vz4w",
        // EvtxECmd map whose "Example Event Data" real 2020 event carries regkey:_,
        // taskscheduler:_ and file:_...->(UTF-16LE) on the older Microsoft Antimalware provider:
        "https://github.com/EricZimmerman/evtx/blob/master/evtx/Maps/System_Microsoft-Antimalware_1116.map",
        // OCSF 1.2.0 maps sub-parts of Path to separate entities (file, process pid, container),
        // independent corroboration that the field is composite rather than one path:
        "https://github.com/ocsf/examples/blob/main/mappings/markdown/Microsoft/Windows%20Defender/README.md",
        // Raw EVTX XML for amsi:_ with the corroborating Source Name=AMSI field:
        "https://github.com/joetanx/sentinel/blob/main/detection/mdav-malware-events.md",
        // An independent parser plus committed test data recovering
        // behavior:_pid:<PID>:<N> and process:_pid:<PID>,ProcessStart:<FILETIME>:
        "https://github.com/puffyCid/artemis-api/blob/main/src/windows/eventlogs/defender.ts",
        // Leaked Conti/TrickBot operator chats quoting Defender 1116 alerts verbatim across many
        // hosts and dates — the source of runkey:_, startup:_ and the HKCU@<SID> key form:
        "https://github.com/TheParmak/conti-leaks-englished",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Detection events survive file deletion; tamper events are highly suspicious",
        "Path is a LIST, not a path: semicolon-delimited <scheme>:_<value> segments. A tool reporting Path as a single filename silently loses the download URL, the responsible PID and the persistence key, and mis-buckets archive-member and in-memory detections as on-disk files",
        "The segment separator is ';' with an OPTIONAL trailing space — both forms occur across builds. Split on ';' and trim; do not anchor a parser to '; '",
        "Microsoft documents only 'Path: File path' for 1116 and 1117. The composite grammar recorded here is second-tier — read out of raw <Data Name=\"Path\"> XML across unrelated 2017, 2020, 2023 and 2024 captures and corroborated by independent parsers and the OCSF 1.2.0 mapping. State it as observed behaviour, never as a documented format",
        "The scheme set is NOT proven exhaustive, and no sample was found of a segment carrying a bare path with no <scheme>:_ prefix — though none was proven impossible either. Surface an unrecognised scheme verbatim, with its full value and segment index, rather than dropping it; degrade an unprefixed segment to a file path rather than erroring",
        "Do NOT decode the trailing number in behavior:_pid:<PID>:<N> as a time. It is not a FILETIME (every observed value falls in 1601) and it is not per-process — one value recurs across four PIDs on different hosts and dates, all carrying the same threat name, and another recurs across three PIDs. It reads as a behavior- or signature-scoped identifier, but no source establishes its meaning; carry it opaquely",
        "webfile:_'s third '|'-delimited component changed shape between builds: a bare image name in 2017 captures, pid:<PID>,ProcessStart:<FILETIME> in 2023 ones. Accept both",
        "amsi:_ carries an NT device path (\\Device\\HarddiskVolumeN\\...) naming the AMSI HOST process — not a DOS path, and not the malicious content; resolve the volume before joining to any DOS-path artifact. Support for this scheme is weaker than for the others: the two public samples are byte-identical, so it rests on effectively one raw capture",
        "A published mapping records the container token capitalised (Containerfile:_) while every raw sample is lowercase — match the scheme case-insensitively",
        "Widely deployed SIEM normalisation truncates this field: Wazuh's shipped Defender decoder strips a single scheme prefix and cannot represent a multi-segment Path, so a normalised path field is commonly a fragment. Re-parse from the raw EVTX rather than trusting it",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_FIREWALL: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_firewall",
    name: "Windows Firewall with Advanced Security Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Requires firewall auditing policy to be enabled",
        "Group Policy refresh can generate noisy benign change events",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_CODE_INTEGRITY: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_code_integrity",
    name: "Code Integrity Operational Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Driver developer test signing or third-party kernel drivers may produce benign violations"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_NTLM: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_ntlm",
    name: "NTLM Operational Log",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-NTLM%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records NTLM authentication events when NTLM audit policy is enabled. Shows NTLM challenge/response pairs that may indicate pass-the-hash attacks, NTLM relay, or legacy application authentication from unexpected sources. Forced-authentication coercion abuses low-privilege RPC methods that force a victim (frequently a domain controller's machine account) to authenticate outbound over NTLM to an attacker-chosen host: PetitPotam drives EFSRPC methods (e.g. EfsRpcOpenFileRaw) over the \\pipe\\lsarpc or \\pipe\\efsrpc named pipe ([MS-EFSR]); PrinterBug/Dementor drives RpcRemoteFindFirstPrinterChangeNotificationEx over \\pipe\\spoolss ([MS-RPRN]); Coercer and DFSCoerce cover further RPC interfaces. The coerced NTLM authentication is then relayed (ntlmrelayx) to LDAP/ADCS/SMB. Here, a DC or server machine account ($) authenticating to an unexpected host is CONSISTENT WITH coercion + relay — it does not by itself prove it.",
    mitre_techniques: &["T1550.002", "T1187"],
    fields: &[
        FieldSchema { name: "user_name", value_type: ValueType::Text, description: "Authenticating username", is_uid_component: true },
        FieldSchema { name: "workstation_name", value_type: ValueType::Text, description: "Source workstation", is_uid_component: false },
    ],
    retention: Some("Default 1 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_security", "dcc2_cache", "evtx_smb_client", "evtx_print_service"],
    sources: &[
        "https://github.com/Yamato-Security/hayabusa-rules",
        // [MS-EFSR] Standards Assignments — \pipe\lsarpc / \pipe\efsrpc + UUIDs (PetitPotam vector):
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/1baaad2f-7a84-4238-b113-f32827a39cd2",
        // [MS-RPRN] Standards Assignments — \pipe\spoolss + UUID (PrinterBug vector):
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/848b8334-134a-4d02-aea4-03b673d6c515",
        // Microsoft — Event 5145 (Detailed File Share) — the upstream coercion signal:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Disabled by default; only populated when NTLM audit policy is enabled",
        "Legacy applications generate substantial benign NTLM traffic",
        "Upstream coercion is best seen in Security.evtx (evtx_security) via event 5145 — the sole event of the Object Access > Detailed File Share subcategory — showing access to Share Name IPC$ with a Relative Target Name of the coercion pipe (efsrpc, lsarpc, or spoolss); that subcategory is OFF by default and high-volume, so absence of 5145 is not absence of coercion",
        "A machine-account NTLM authentication to an unexpected destination is consistent with coercion/relay but also occurs during benign cross-host service auth; corroborate with evtx_smb_client (relay victim), evtx_print_service (spooler coercion), and Security 4624/4768 machine-account logons",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_PRINT_SERVICE: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_print_service",
    name: "Print Service Operational Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Operational channel may be disabled by default on some Windows builds",
        "Legitimate driver installation also generates Event 316",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_NETLOGON: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_netlogon",
    name: "Netlogon Operational Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_tier: None,
    evidence_caveats: &["5827/5828 = ZeroLogon exploitation attempt — very low false-positive rate"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_SMB_CLIENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_smb_client",
    name: "SMB Client Security Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Failed authentications occur for many benign reasons (typo, expired credential, stale mapped drive)"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_NETWORK_PROFILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_network_profile",
    name: "Network Profile Operational Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_KERNEL_PNP: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_kernel_pnp",
    name: "Kernel PnP Device Configuration Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Records all PnP device events; benign hardware changes also appear"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_DRIVER_FRAMEWORKS: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_driver_frameworks",
    name: "DriverFrameworks-UserMode Operational Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Disabled by default on Win10/11 — must be enabled proactively before incident",
        "MTP/PTP devices (phones, cameras) typically do not appear here",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_LSA_PROTECTION: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_lsa_protection",
    name: "LSA Protection Operational Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_tier: None,
    evidence_caveats: &["PPL changes indicate credential dumping preparation"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log; rotated on size limit",
};

pub(crate) static EVTX_CAPI2: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_capi2",
    name: "CAPI2 Operational Log (certificate validation)",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "High-volume noisy log; certificate validation occurs constantly",
        "Frequently disabled or rapidly rotates due to size",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_POWERSHELL_CLASSIC: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_powershell_classic",
    name: "Windows PowerShell Classic Log",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Windows PowerShell.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Legacy PowerShell event log (pre-5.0 style). Events 400 (engine start) and 600 (provider start) record PowerShell session initiation and can show HostApplication (the full command line). Complements the Operational log for older PowerShell versions. Event 400 is the engine-lifecycle record and it carries the EngineVersion — the field that answers 'the PowerShell logs are empty'. Script-block logging, transcription and the 4103/4104 records only exist from engine version 5.0, so an execution routed through an older engine produces none of them while still writing a 400 here. Reading EngineVersion on every 400 and flagging any value below 5.0 is therefore the host-side detection for a deliberately downgraded engine; the engine's own author published exactly that query. Two routes reach the old engine: the -Version switch on powershell.exe, and a host application compiled against the v2 reference assemblies (so the loading binary, not the command line, chooses the engine). The engine-lifecycle records come in a PAIR that brackets a session — 400 when the engine becomes available and 403 when it stops — and both carry HostName, the name of the PSHost implementation that loaded the engine, alongside HostVersion. That field separates a session someone typed at (HostName ConsoleHost) from one the remoting stack created: ServerRemoteHost is the host class the engine ships for the remoting server side, so a 400/403 pair carrying it brackets a session built on the remoting infrastructure ON THIS HOST. Read it as a lead rather than a finding — local background jobs run on the same infrastructure and report the same host name — so corroborate against evtx_winrm and a Security 4624 Logon Type 3 before calling a session inbound. The pair also bounds the session in time when nothing else does: on a downgraded engine there is no transcript and no 4103/4104, and 400/403 are the only records of when it started and ended.",
    mitre_techniques: &["T1059.001", "T1562.002", "T1021.006"],
    fields: &[
        FieldSchema { name: "host_application", value_type: ValueType::Text, description: "Command or script that launched PowerShell", is_uid_component: true },
        FieldSchema { name: "event_id", value_type: ValueType::UnsignedInt, description: "400=engine lifecycle (engine became available), 403=engine lifecycle (engine stopped) — the two bracket one session, 600=provider lifecycle (provider started)", is_uid_component: false },
        FieldSchema { name: "engine_version", value_type: ValueType::Text, description: "EngineVersion from event 400 — the PowerShell engine actually loaded. A value below 5.0 means the session ran on an engine that predates script-block logging and transcription, so the absence of 4103/4104 records for that session is explained by the engine, not by inactivity", is_uid_component: false },
        FieldSchema { name: "host_name", value_type: ValueType::Text, description: "HostName from events 400/403 — the PSHost implementation that loaded the engine, not the computer name. ConsoleHost is an interactive console; ServerRemoteHost is the engine's own remoting server-side host class, marking a session the remoting stack created on this host. Use it to sort sessions by how they were started, then establish direction elsewhere: the value does not distinguish an inbound remoting session from a local background job", is_uid_component: false },
        FieldSchema { name: "runspace_id", value_type: ValueType::Guid, description: "RunspaceId carried by the engine-lifecycle records — the key that pairs one session's 400 with its own 403 rather than pairing them by time, which matters on a host running several sessions at once", is_uid_component: false },
    ],
    retention: Some("Default 15 MB"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_powershell", "powershell_history", "evtx_powershell_core_operational"],
    sources: &[
        "https://www.sans.org/blog/powershell-logging-for-the-blue-team/",
        "https://github.com/Yamato-Security/hayabusa-rules",
        // Lee Holmes (PowerShell engine developer) — event 400 is the engine-lifecycle record
        // carrying EngineVersion, the two routes to the v2 engine, and the detection query:
        "https://www.leeholmes.com/detecting-and-preventing-powershell-downgrade-attacks/",
        // PowerShell engine source — ServerRemoteHost is the PSHost the remoting server side
        // constructs, which is where the HostName value in a remoting session's 400/403 comes from:
        "https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/remoting/server/ServerRemoteHost.cs",
        // PowerShell issue tracker — a local background job also runs on the remoting
        // infrastructure and reports the same host name, which is why ServerRemoteHost alone
        // does not establish that a session arrived over the network:
        "https://github.com/PowerShell/PowerShell/issues/11293",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Legacy log; modern PowerShell activity is in PowerShell/Operational and Microsoft-Windows-PowerShell/Operational",
        "A low EngineVersion is not by itself proof of evasion: the v2 engine also loads for an application legitimately built against the v2 reference assemblies, and on Windows 10 and later it requires the .NET Framework 2.0 feature to be present at all — so establish whether that feature was installed before calling it a downgrade",
        "HostName = ServerRemoteHost does NOT prove an inbound remoting session: PowerShell runs local background jobs on the same remoting infrastructure, so they report the identical host name. Corroborate with the WinRM channel and a network logon before reporting remote execution",
        "A 403 can be missing for a session that did start — an engine killed with its host process, or a log that rotated between the two records, leaves a 400 with no partner. Treat an unpaired 400 as an unbounded session, not as a session that never ended",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

// ── Group C: Additional EVTX Channels ────────────────────────────────────────

pub(crate) static EVTX_DNS_CLIENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_dns_client",
    name: "DNS Client Operational Event Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Disabled by default — must be enabled via wevtutil or Group Policy before the incident",
        "Extremely high volume when enabled — rotates quickly",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

pub(crate) static EVTX_TERMINAL_SERVICES: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_terminal_services",
    name: "Terminal Services Local Session Manager Operational Log",
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Source Network Address may be 'localhost' or '127.0.0.1' for console sessions, not remote"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
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
    artifact_type: ArtifactLocation::EventLog,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Only populated when Microsoft Vulnerable Driver Blocklist or HVCI policy is active",
        "Absence of EID 875 alongside an attempted driver load implies the driver loaded successfully",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when size limit reached",
};

// ── Assessed artifacts (moved out of descriptors/generated/) ──────────────────
//
// Each of these carries a curated evidence strength and volatility class. No
// upstream corpus supplies that judgement, so it used to be written into the
// generated module by hand after every run — which a full-corpus regeneration
// erased. Here the ingest pipeline sees the id is already catalogued and skips
// its own record, so the judgement survives, and the triage priority is the
// artifact's own rather than the generator's High ceiling.

pub(crate) static EVTX_MICROSOFT_WINDOWS_NETWORKSECURITY_DEBUG: ArtifactDescriptor =
    ArtifactDescriptor {
        id: "evtx_microsoft_windows_networksecurity_debug",
        name: "Microsoft-Windows-NetworkSecurity/Debug",
        artifact_type: ArtifactLocation::EventLog,
        hive: None,
        key_path: "",
        value_name: None,
        file_path: Some(
            "%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-NetworkSecurity\\Debug.evtx",
        ),
        scope: DataScope::Mixed,
        os_scope: OsScope::Win7Plus,
        decoder: Decoder::Identity,
        meaning: "Windows Event Log channel 'Microsoft-Windows-NetworkSecurity/Debug'.",
        mitre_techniques: &[],
        fields: &[],
        retention: None,
        triage_priority: TriagePriority::Critical,
        related_artifacts: &[],
        sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
        evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
        evidence_tier: None,
        evidence_caveats: &[
            "Windows Security audit log; check Policy log for channel disable events",
        ],
        volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
        volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
    };

pub(crate) static EVTX_MICROSOFT_WINDOWS_SMBCLIENT_SECURITY: ArtifactDescriptor =
    ArtifactDescriptor {
        id: "evtx_microsoft_windows_smbclient_security",
        name: "Microsoft-Windows-SMBClient/Security",
        artifact_type: ArtifactLocation::EventLog,
        hive: None,
        key_path: "",
        value_name: None,
        file_path: Some(
            "%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-SMBClient\\Security.evtx",
        ),
        scope: DataScope::Mixed,
        os_scope: OsScope::Win7Plus,
        decoder: Decoder::Identity,
        meaning: "Windows Event Log channel 'Microsoft-Windows-SMBClient/Security'.",
        mitre_techniques: &[],
        fields: &[],
        retention: None,
        triage_priority: TriagePriority::Critical,
        related_artifacts: &[],
        sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
        evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
        evidence_tier: None,
        evidence_caveats: &[
            "Windows Security audit log; check Policy log for channel disable events",
        ],
        volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
        volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
    };

pub(crate) static EVTX_MICROSOFT_WINDOWS_SMBSERVER_SECURITY: ArtifactDescriptor =
    ArtifactDescriptor {
        id: "evtx_microsoft_windows_smbserver_security",
        name: "Microsoft-Windows-SMBServer/Security",
        artifact_type: ArtifactLocation::EventLog,
        hive: None,
        key_path: "",
        value_name: None,
        file_path: Some(
            "%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-SMBServer\\Security.evtx",
        ),
        scope: DataScope::Mixed,
        os_scope: OsScope::Win7Plus,
        decoder: Decoder::Identity,
        meaning: "Windows Event Log channel 'Microsoft-Windows-SMBServer/Security'.",
        mitre_techniques: &[],
        fields: &[],
        retention: None,
        triage_priority: TriagePriority::Critical,
        related_artifacts: &[],
        sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
        evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
        evidence_tier: None,
        evidence_caveats: &[
            "Windows Security audit log; check Policy log for channel disable events",
        ],
        volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
        volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
    };

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_ADMINLESS_OPERATIONAL: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_adminless_operational",
    name: "Microsoft-Windows-Security-Adminless/Operational",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-Adminless\\Operational.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-Adminless/Operational'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_AUDIT_CONFIGURATION_CLIENT_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_audit_configuration_client_d",
    name: "Microsoft-Windows-Security-Audit-Configuration-Client/Diagnostic",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-Audit-Configuration-Client\\Diagnostic.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-Audit-Configuration-Client/Diagnostic'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_AUDIT_CONFIGURATION_CLIENT_O: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_audit_configuration_client_o",
    name: "Microsoft-Windows-Security-Audit-Configuration-Client/Operational",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-Audit-Configuration-Client\\Operational.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-Audit-Configuration-Client/Operational'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_CONFIGURATION_WIZARD_DIAGNOS: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_configuration_wizard_diagnos",
    name: "Microsoft-Windows-Security-Configuration-Wizard/Diagnostic",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-Configuration-Wizard\\Diagnostic.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-Configuration-Wizard/Diagnostic'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_CONFIGURATION_WIZARD_OPERATI: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_configuration_wizard_operati",
    name: "Microsoft-Windows-Security-Configuration-Wizard/Operational",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-Configuration-Wizard\\Operational.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-Configuration-Wizard/Operational'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_ENTERPRISEDATA_FILEREVOCATIO: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_enterprisedata_filerevocatio",
    name: "Microsoft-Windows-Security-EnterpriseData-FileRevocationManager/Operational",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-EnterpriseData-FileRevocationManager\\Operational.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-EnterpriseData-FileRevocationManager/Operational'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_EXCHANGEACTIVESYNCPROVISIONI: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_exchangeactivesyncprovisioni",
    name: "Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Performance",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-ExchangeActiveSyncProvisioning\\Performance.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Performance'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_IDENTITYSTORE_PERFORMANCE: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_identitystore_performance",
    name: "Microsoft-Windows-Security-IdentityStore/Performance",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-IdentityStore\\Performance.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-IdentityStore/Performance'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_LESSPRIVILEGEDAPPCONTAINER_O: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_lessprivilegedappcontainer_o",
    name: "Microsoft-Windows-Security-LessPrivilegedAppContainer/Operational",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-LessPrivilegedAppContainer\\Operational.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-LessPrivilegedAppContainer/Operational'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_LICENSING_SLC_PERF: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_licensing_slc_perf",
    name: "Microsoft-Windows-Security-Licensing-SLC/Perf",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-Licensing-SLC\\Perf.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-Licensing-SLC/Perf'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_NETLOGON_OPERATIONAL: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_netlogon_operational",
    name: "Microsoft-Windows-Security-Netlogon/Operational",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-Netlogon\\Operational.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-Netlogon/Operational'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_SPP_UX_GC_ANALYTIC: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_spp_ux_gc_analytic",
    name: "Microsoft-Windows-Security-SPP-UX-GC/Analytic",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-SPP-UX-GC\\Analytic.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-SPP-UX-GC/Analytic'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_SPP_UX_GENUINECENTER_LOGGING: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_spp_ux_genuinecenter_logging",
    name: "Microsoft-Windows-Security-SPP-UX-GenuineCenter-Logging/Operational",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-SPP-UX-GenuineCenter-Logging\\Operational.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-SPP-UX-GenuineCenter-Logging/Operational'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_SPP_UX_NOTIFICATIONS_ACTIONC: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_spp_ux_notifications_actionc",
    name: "Microsoft-Windows-Security-SPP-UX-Notifications/ActionCenter",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-SPP-UX-Notifications\\ActionCenter.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-SPP-UX-Notifications/ActionCenter'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_SPP_UX_ANALYTIC: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_spp_ux_analytic",
    name: "Microsoft-Windows-Security-SPP-UX/Analytic",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-SPP-UX\\Analytic.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-SPP-UX/Analytic'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_SPP_PERF: ArtifactDescriptor =
    ArtifactDescriptor {
        id: "evtx_microsoft_windows_security_spp_perf",
        name: "Microsoft-Windows-Security-SPP/Perf",
        artifact_type: ArtifactLocation::EventLog,
        hive: None,
        key_path: "",
        value_name: None,
        file_path: Some(
            "%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-SPP\\Perf.evtx",
        ),
        scope: DataScope::Mixed,
        os_scope: OsScope::Win7Plus,
        decoder: Decoder::Identity,
        meaning: "Windows Event Log channel 'Microsoft-Windows-Security-SPP/Perf'.",
        mitre_techniques: &[],
        fields: &[],
        retention: None,
        triage_priority: TriagePriority::Critical,
        related_artifacts: &[],
        sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
        evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
        evidence_tier: None,
        evidence_caveats: &[
            "Windows Security audit log; check Policy log for channel disable events",
        ],
        volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
        volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
    };

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_USERCONSENTVERIFIER_AUDIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_userconsentverifier_audit",
    name: "Microsoft-Windows-Security-UserConsentVerifier/Audit",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-UserConsentVerifier\\Audit.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-UserConsentVerifier/Audit'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITY_VAULT_PERFORMANCE: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_security_vault_performance",
    name: "Microsoft-Windows-Security-Vault/Performance",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Security-Vault\\Performance.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-Security-Vault/Performance'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITYMITIGATIONSBROKER_PERF: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_securitymitigationsbroker_perf",
    name: "Microsoft-Windows-SecurityMitigationsBroker/Perf",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-SecurityMitigationsBroker\\Perf.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-SecurityMitigationsBroker/Perf'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITYMITIGATIONSBROKER_OPERATIONAL: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_securitymitigationsbroker_operational",
    name: "Microsoft-Windows-SecurityMitigationsBroker/Operational",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-SecurityMitigationsBroker\\Operational.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-SecurityMitigationsBroker/Operational'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

pub(crate) static EVTX_MICROSOFT_WINDOWS_SECURITYMITIGATIONSBROKER_ADMIN: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_microsoft_windows_securitymitigationsbroker_admin",
    name: "Microsoft-Windows-SecurityMitigationsBroker/Admin",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-SecurityMitigationsBroker\\Admin.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Event Log channel 'Microsoft-Windows-SecurityMitigationsBroker/Admin'.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/nasbench/EVTX-ETW-Resources"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Event log rotates on size limit; Security channel is high-value",
};

// ── Group D: hand-written Security-log families and channel records ──────────

/// Field schema for Security event 4648 — a logon was attempted using explicit
/// credentials.
///
/// The record carries TWO identities, and keeping them apart is the whole
/// value of the event: the Subject block is the session that acted, and the
/// "Account Whose Credentials Were Used" block is the identity it borrowed.
/// Target Server Name is the documented destination field; Microsoft defines
/// Network Address as the machine the logon attempt was performed FROM, so the
/// two answer different questions and must not be merged into one "remote
/// host" column.
///
/// Additional Information (XML `TargetInfo`) is the third member of the Target
/// Server block, and Microsoft declines to define it. What it carries — usually
/// a verbatim copy of Target Server Name, less often a Service Principal Name
/// whose host element is that same name — is established outside the vendor
/// docs, and the field's own description says so and names the evidence.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/ad/name-formats-for-unique-spns>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/adschema/a-spnmappings>
pub(crate) static EVTX_SECURITY_EXPLICIT_CREDENTIALS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "Always 4648. Success-only: Microsoft documents no failure variant, so this event says credentials were supplied, never that they worked",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the credentials were supplied on THIS host — the start of an outbound movement, earlier than the destination's own logon record",
        is_uid_component: true,
    },
    FieldSchema {
        name: "subject_account",
        value_type: ValueType::Text,
        description: "Subject Account Name and Domain — the logged-on identity whose session launched the process. This is who was at the keyboard or owned the running session, not the identity used on the wire",
        is_uid_component: true,
    },
    FieldSchema {
        name: "subject_logon_id",
        value_type: ValueType::Text,
        description: "Subject Logon ID — joins this event to other records of the same session on this host, 4624 among them. A runas with alternate network credentials also mints a Logon Type 9 (NewCredentials) session, which is the 4624 to look for beside this record",
        is_uid_component: false,
    },
    FieldSchema {
        name: "credentials_account",
        value_type: ValueType::Text,
        description: "Account Whose Credentials Were Used — the borrowed identity that will appear on the DESTINATION host's logon record. Comparing it with subject_account separates ordinary self-service activity from one account reaching out as another",
        is_uid_component: true,
    },
    FieldSchema {
        name: "credentials_logon_guid",
        value_type: ValueType::Guid,
        description: "Logon GUID of the credentials used — Microsoft names it as the correlator to the domain controller's 4769 service-ticket record and to events on the host reached, which is what ties this origin-side record to the rest of the chain",
        is_uid_component: false,
    },
    FieldSchema {
        name: "target_server_name",
        value_type: ValueType::Text,
        description: "Target Server Name — the server the new process was run on, or 'localhost' when it ran locally. A non-localhost value is this host enumerating where it reached out TO, which no target-side event can give you. When additional_information carries a Service Principal Name, this field is that SPN's <host> element verbatim — the two are then the same host said twice, and only additional_information names the service",
        is_uid_component: false,
    },
    FieldSchema {
        name: "additional_information",
        value_type: ValueType::Text,
        description: "Additional Information (XML TargetInfo) — the target name the local process handed the security package for this outbound authentication. Microsoft declines to define it (\"there is no detailed information about this field in this document\"), so everything that follows is undocumented by Microsoft and established from four lines with no shared ancestry that agree: the Microsoft-published Sentinel hunting query MultipleExplicitCredentialUsage4648Events.yaml, JPCERT/CC's Tool Analysis Result Sheet for mstsc, a real sanitised event in elastic/detection-rules#2819, and a scan of 724 4648 records across six independent public EVTX corpora. \
                      The value takes one of two shapes. USUALLY it repeats target_server_name verbatim — 'localhost', a NetBIOS name, an FQDN, or a machine account ending '$'; that is the common case, and Microsoft's own Event XML sample for 4648 is of it. LESS OFTEN it is a Service Principal Name in Microsoft's documented <service class>/<host>[:<port>][/<service name>] grammar, and then the <host> element equals target_server_name exactly. Service classes seen in real records: cifs, ldap (also spelled LDAP), RPCSS and host in the corpus scan, and TERMSRV for RDP in the two independent RDP captures. Microsoft's own hunting query splits this field on '/' and expects cifs, ldap, RPCSS, host, HTTP, RestrictedKrbHost, TERMSRV, msomsdksvc and mssqlsvc — an expectation list, not a list of observations. \
                      Read the class as the service the CLIENT asked Kerberos or Negotiate for, never as a wire protocol: host and RestrictedKrbHost are alias classes registered on every machine at domain join, and Microsoft's sPNMappings attribute documents 'ldap/...' SPNs as mappable to 'host/...'. Split on '/' rather than parsing the whole value as one name, and match the class case-insensitively",
        is_uid_component: false,
    },
    FieldSchema {
        name: "process_name",
        value_type: ValueType::Text,
        description: "Full path of the LOCAL process that supplied the credentials — runas.exe, a remote-admin tool, a script host. This names the tool used to pivot and is the reason the event is worth collecting on every workstation, not just servers",
        is_uid_component: false,
    },
    FieldSchema {
        name: "process_id",
        value_type: ValueType::UnsignedInt,
        description: "PID of that local process; join to the same host's process-creation record (4688 New Process ID) to recover its command line and parent",
        is_uid_component: false,
    },
    FieldSchema {
        name: "network_address",
        value_type: ValueType::Text,
        description: "Network Address as Microsoft defines it: the IP of the machine the logon attempt was performed from (::1 or 127.0.0.1 meaning localhost). Read it as provenance of the attempt, and take the destination from target_server_name instead",
        is_uid_component: false,
    },
    FieldSchema {
        name: "network_port",
        value_type: ValueType::UnsignedInt,
        description: "Source port of the attempt; 0 for interactive logons. A zero here is normal and is not a sign of a truncated record",
        is_uid_component: false,
    },
];

/// Security event 4648 — the origin-side record of an explicit-credential logon.
///
/// Every other lateral-movement event in this catalog is written where the
/// movement LANDS. 4648 is written where it STARTS: the process supplying the
/// credentials is local, and the server it reached is named in the record. One
/// compromised host's Security log therefore enumerates the outbound movement
/// attempted from it, including attempts that never authenticated anywhere.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624>
pub(crate) static EVTX_SECURITY_EXPLICIT_CREDENTIALS: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_security_explicit_credentials",
    name: "Explicit-Credential Logon (Security 4648)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Written when a process attempts a logon by explicitly supplying an account's credentials — the runas case, scheduled tasks configured with stored credentials, and remote-administration tooling that takes a username and password. Gated by the Audit Logon subcategory. The record is produced on the host where that process ran, so it inverts the geometry of the rest of the logon evidence: 4624 tells you who arrived HERE, 4648 tells you where this host tried to go. Two identity blocks make it readable — Subject (the session that acted) and Account Whose Credentials Were Used (the identity put on the wire) — and Target Server Name gives the destination, or 'localhost' when the new process ran locally. Process Name is the local tool that pivoted. Subject Logon ID joins the record to the same session's other events on this host; the credentials' Logon GUID is Microsoft's documented correlator to the domain controller's 4769 and to events on the host reached. Microsoft also states plainly that 4648 occurs routinely during normal operating-system activity, so the finding is never the event alone: it is a non-localhost Target Server Name, an unexpected borrowed account, or a process name that has no business supplying credentials. One further read is available when Additional Information carries a service class: it names the service the local client asked Kerberos or Negotiate for — cifs for SMB, TERMSRV for RDP (Microsoft documents TERMSRV/<host> among a server's default RDP SPNs), ldap, RPCSS, HTTP — which is a lead on the movement channel and not a determination of it, because one operation emits several records with different classes and the string is composed by the client process itself. That reading is undocumented by Microsoft and rests on the sources cited against the additional_information field.",
    mitre_techniques: &["T1078", "T1021", "T1550.002"],
    fields: EVTX_SECURITY_EXPLICIT_CREDENTIALS_FIELDS,
    retention: Some("Security.evtx is a rolling channel sized by policy; on a busy host the window is hours to days"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "evtx_security",
        "evtx_remote_execution_host_lineage",
        "evtx_security_logon_failure",
        "evtx_winrm",
    ],
    sources: &[
        // Microsoft — 4648: the field blocks, Target Server Name semantics, the Logon ID and
        // Logon GUID correlations, and the statement that the event occurs routinely:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648",
        // Microsoft — 4624: Logon Type 9 (NewCredentials), the session shape a runas with
        // alternate network credentials leaves beside a 4648:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624",
        // Microsoft — SPN grammar <service class>/<host>[:<port>][/<service name>] and the
        // well-known service-class concept Additional Information is read against:
        "https://learn.microsoft.com/en-us/windows/win32/ad/name-formats-for-unique-spns",
        // Microsoft — the CLIENT composes the SPN, which is why the value is attacker-influenced
        // on a compromised host rather than an assertion by the service:
        "https://learn.microsoft.com/en-us/windows/win32/ad/how-clients-compose-a-serviceampaposs-spn",
        // Microsoft — sPNMappings: "ldap/..." SPNs mappable to "host/...", the documented basis
        // for treating host/ and RestrictedKrbHost/ as alias classes rather than services:
        "https://learn.microsoft.com/en-us/windows/win32/adschema/a-spnmappings",
        // Microsoft — TERMSRV/<host> and TERMSRV/<fqdn> registered as a server's default RDP SPNs:
        "https://github.com/MicrosoftDocs/windowsserverdocs/blob/main/WindowsServerDocs/identity/ad-ds/manage/how-to-configure-spn.md",
        // Microsoft-published hunting query — splits TargetInfo on '/' into a service class and a
        // machine and names the classes it expects; the vendor's own treatment of an undocumented
        // field, and the strongest single support for reading it as an SPN:
        "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Windows%20Security%20Events/Hunting%20Queries/MultipleExplicitCredentialUsage4648Events.yaml",
        // JPCERT/CC Tool Analysis Result Sheet (mstsc) — a 2017 lab run recording Additional
        // Information as TERMSRV/<destination host> on the SOURCE host:
        "https://github.com/JPCERTCC/ToolAnalysisResultSheet/blob/master/details/mstsc.htm",
        // A real sanitised 4648 carrying TargetInfo=TERMSRV/Computer1 beside
        // TargetServerName=Computer1, reported independently of the two above:
        "https://github.com/elastic/detection-rules/issues/2819",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Microsoft documents 4648 as a routine occurrence during normal operating-system activity — volume alone is meaningless, and a single event proves only that credentials were supplied",
        "The event does not say the logon succeeded; corroborate with the destination host's own 4624/4625 before claiming the account reached the target",
        "Additional Information is undocumented by Microsoft, whose reference says only that \"there is no detailed information about this field in this document\". It is nonetheless readable, and the reading recorded here is second-tier — established from a Microsoft-published Sentinel hunting query, a JPCERT/CC lab sheet, a real event reported in elastic/detection-rules#2819 and a public-corpus scan, four lines that agree. State it as observed behaviour, never as a documented format",
        "An SPN in Additional Information is the MINORITY shape. Across the public-corpus scan behind this entry the field overwhelmingly repeated target_server_name verbatim, and Microsoft's own Event XML sample does exactly that — so a rule that assumes a '/' is present matches almost nothing. The scan covered attack-sample collections with unknown sampling bias, so read the shape and not a rate",
        "The service class is not case-normalised: 'ldap/' and 'LDAP/' were recorded on one host, from one process, ten milliseconds apart. A case-sensitive match on the class silently under-reports",
        "One logical action emits SEVERAL 4648 records carrying different service classes — an observed WMIC run produced RPCSS/<host>, host/<host> and a bare hostname within 40 ms across two processes. Counting classes as distinct services reached, or reading one record as the whole operation, both over-count",
        "The SPN is composed by the client process, so on a compromised host the value is attacker-influenced; combined with 4648 having no failure variant, an SPN here evidences what the caller ASKED FOR and never that the service was reached",
        "Network Address is documented as the address the attempt came FROM, not the destination; treating it as the target inverts the direction of the finding",
        "Present only where the Audit Logon subcategory was enabled at the time — absence is a policy fact until the audit configuration is established",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when the configured maximum size is reached",
};

/// Field schema for Security event 4625 — an account failed to log on.
///
/// The event carries a Status and a Sub Status, both NTSTATUS values from the
/// same space ([MS-ERREF] 2.3.1). Status is the reason the logon failed and
/// Sub Status is the additional detail; Microsoft's own sample record shows
/// Status carrying the real cause with Sub Status at 0x0, so a decoder must
/// read both rather than assuming one is always the informative one.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625>
/// Source: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55>
pub(crate) static EVTX_SECURITY_LOGON_FAILURE_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "Always 4625, and always a Failure record — the successful counterpart is 4624",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the attempt failed. The inter-event spacing across a run of these is what separates a human retyping a password from an automated sweep",
        is_uid_component: true,
    },
    FieldSchema {
        name: "target_account",
        value_type: ValueType::Text,
        description: "Account Name and Account Domain specified in the attempt — the identity that was tried. Attribute failed logons on this pair, never on the SID (see target_sid)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "target_sid",
        value_type: ValueType::Text,
        description: "Security ID of the specified account. Microsoft's published sample carries the NULL SID S-1-0-0 here while the account name resolves normally, so a correlator keyed on SID silently drops failed logons",
        is_uid_component: false,
    },
    FieldSchema {
        name: "status",
        value_type: ValueType::Text,
        description: "Status — the NTSTATUS reason the logon failed. 0xC000006D STATUS_LOGON_FAILURE is the deliberately vague generic ('either due to a bad username or authentication information'), which is when the sub_status carries the real cause",
        is_uid_component: false,
    },
    FieldSchema {
        name: "sub_status",
        value_type: ValueType::Text,
        description: "Sub Status — the discriminating NTSTATUS: 0xC0000064 STATUS_NO_SUCH_USER (the account does not exist), 0xC000006A STATUS_WRONG_PASSWORD (it exists, the password was wrong), 0xC000006E STATUS_ACCOUNT_RESTRICTION, 0xC000006F STATUS_INVALID_LOGON_HOURS, 0xC0000070 STATUS_INVALID_WORKSTATION, 0xC0000071 STATUS_PASSWORD_EXPIRED, 0xC0000072 STATUS_ACCOUNT_DISABLED, 0xC0000193 STATUS_ACCOUNT_EXPIRED, 0xC0000234 STATUS_ACCOUNT_LOCKED_OUT. Separating 0xC0000064 from 0xC000006A tells spraying a wordlist of invented usernames apart from guessing against a real account, without touching the account database",
        is_uid_component: false,
    },
    FieldSchema {
        name: "failure_reason",
        value_type: ValueType::Text,
        description: "Failure Reason — Microsoft's rendered explanation of the Status value (a %%-prefixed message id in the raw XML). Convenient for reading, but the hex codes are what a rule should match, since the rendered string is locale-dependent",
        is_uid_component: false,
    },
    FieldSchema {
        name: "logon_type",
        value_type: ValueType::UnsignedInt,
        description: "Logon Type of the failed attempt — 3 network, 10 RemoteInteractive (RDP), 2 interactive, 5 service. It says which door was tried and therefore which other log to open next",
        is_uid_component: false,
    },
    FieldSchema {
        name: "workstation_name",
        value_type: ValueType::Text,
        description: "Network Information Workstation Name — the name the client SUPPLIED, so it is attacker-controllable free text and can be absent; treat it as a claim, corroborated only by source_network_address",
        is_uid_component: false,
    },
    FieldSchema {
        name: "source_network_address",
        value_type: ValueType::Text,
        description: "Source Network Address and Port of the attempt — the observable to pivot on for a remote failure, and the field that separates one noisy source from a distributed sweep",
        is_uid_component: false,
    },
    FieldSchema {
        name: "authentication_package",
        value_type: ValueType::Text,
        description: "Authentication Package (and Package Name for NTLM) — names the protocol that refused. NTLM failures also leave a 4776 on the computer authoritative for the account, carrying an Error Code from this same NTSTATUS space",
        is_uid_component: false,
    },
    FieldSchema {
        name: "caller_process_name",
        value_type: ValueType::Text,
        description: "Full path of the process that attempted the logon, when the attempt was local — a local brute force names its own tool here, while a network attempt typically leaves it empty",
        is_uid_component: false,
    },
];

/// Security event 4625 — a failed logon, with the status pair that says WHY.
///
/// The value is in the decode, not the count. Status and Sub Status come from
/// the NTSTATUS space, and the distinction between "no such user" and "wrong
/// password" is recorded in every failure — which is what lets an examiner
/// tell a username-enumeration sweep from targeted password guessing straight
/// out of the log.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625>
/// Source: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55>
pub(crate) static EVTX_SECURITY_LOGON_FAILURE: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_security_logon_failure",
    name: "Failed Logon with Status Decode (Security 4625)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Records a logon that failed, with a Status and Sub Status pair drawn from the NTSTATUS space that Microsoft's own reference points at for decoding. Status is the reason; Sub Status is the additional detail, and it is the field that carries the discriminator when Status is the generic 0xC000006D STATUS_LOGON_FAILURE, whose rendered text ('unknown user name or bad password') deliberately tells an attacker nothing. Decoded, the log answers a question the raw count cannot: a run of 0xC0000064 STATUS_NO_SUCH_USER is a sweep against names that do not exist (enumeration or a spray from a wordlist), whereas a run of 0xC000006A STATUS_WRONG_PASSWORD is guessing against accounts that DO exist, and 0xC0000234 STATUS_ACCOUNT_LOCKED_OUT marks where a lockout policy caught it. The remaining codes are policy facts rather than credential facts — 0xC000006F invalid logon hours, 0xC0000070 invalid workstation, 0xC0000071 expired password, 0xC0000072 disabled account, 0xC0000193 expired account — and each says the credentials may have been correct while something else refused. Microsoft's sample record shows the Status carrying the cause with Sub Status at 0x0, so read the pair, never one alone. The same NTSTATUS space appears as the Error Code of 4776, so NTLM failures can be decoded with the same table on the authenticating host.",
    mitre_techniques: &["T1110.001", "T1110.003", "T1087.002", "T1078"],
    fields: EVTX_SECURITY_LOGON_FAILURE_FIELDS,
    retention: Some("Security.evtx is a rolling channel sized by policy; failure bursts fill it quickly"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "evtx_security",
        "evtx_ntlm",
        "evtx_security_explicit_credentials",
        "evtx_rdp_core_ts",
    ],
    sources: &[
        // Microsoft — 4625: the Status/Sub Status field definitions, the monitoring table of
        // codes, the NULL SID in the published sample, and the pointer to NTSTATUS Values:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625",
        // [MS-ERREF] 2.3.1 NTSTATUS Values — the symbolic names and definitions behind the
        // 0xC00000xx codes this event reports:
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "A failed logon is an attempt, not an intrusion: expired passwords, stale mapped drives, saved credentials in a service and a mistyped username all generate the same event",
        "Sub Status is frequently 0x0, with the cause in Status — a decoder that reads only Sub Status reports 'unknown' on well-formed records",
        "Workstation Name is supplied by the client and is not authenticated; only the source network address is an observable",
        "The published sample shows the NULL SID S-1-0-0 in the target account's Security ID — joining failed to successful logons on SID loses the link",
        "Absence of 4625 does not mean no attempt: Failure auditing for the Logon subcategory can be off, and a protocol may refuse before reaching this host at all",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; a failure burst is exactly the traffic that rotates the window shut",
};

/// Field schema for Security event 4697 — a service was installed in the system.
///
/// The Service Start Type values are the same numbering the Service Control
/// Manager takes in `CreateService`, and the same numbering stored as the
/// `Start` value under the service's own registry key — so the event, the API
/// and the hive all speak one vocabulary.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew>
/// Source: <https://learn.microsoft.com/en-us/windows/application-management/per-user-services-in-windows>
pub(crate) static EVTX_SECURITY_SERVICE_INSTALL_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "Always 4697. The System-log counterpart written by the Service Control Manager is 7045 — different log, different gate, so check for both",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the service was registered with the Service Control Manager — an installation time, not a first-run time",
        is_uid_component: true,
    },
    FieldSchema {
        name: "subject_account",
        value_type: ValueType::Text,
        description: "Subject Account Name, Domain and Logon ID — the security context the registration ran in. Microsoft's own sample shows the machine account with Logon ID 0x3e7 (SYSTEM), which is the common case: the installer's own account is often absent here, so attribution needs the 7045 record or the process that created it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_name",
        value_type: ValueType::Text,
        description: "Service Name as registered — the key name under the services hive and the string to hunt for in the registry, task and network evidence. Attacker-chosen free text, so it is a label, never a verdict",
        is_uid_component: true,
    },
    FieldSchema {
        name: "service_file_name",
        value_type: ValueType::Text,
        description: "Service File Name — the binary path AND its arguments, the highest-signal field in the record. A service hosted by svchost.exe shows the host with its -k group; a path in a user-writable directory, an interpreter with an encoded argument, or a binary under a temp path is what separates a real installation from the operating system's own",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_type",
        value_type: ValueType::Text,
        description: "Service Type — whether the installed thing is a user-mode service or a KERNEL DRIVER. A driver install is the BYOVD/rootkit shape and deserves its own path: hash the file and check its signature",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_start_type",
        value_type: ValueType::UnsignedInt,
        description: "Service Start Type, same numbering as the registry Start value: 0 Boot (driver loaded by the system loader), 1 System (driver loaded during kernel initialisation), 2 Automatic (started by the SCM at startup, including delayed auto-start), 3 Manual (started on demand), 4 Disabled. 0/1 on a newly installed driver means it will load before most defensive software",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_account",
        value_type: ValueType::Text,
        description: "Service Account — the security context the service will run AS. LocalSystem gives the service the machine's identity on the network, which is what makes a service install a privilege and persistence step rather than merely a start-up entry",
        is_uid_component: false,
    },
];

/// Security event 4697 — a service was installed, recorded in the Security log.
///
/// The catalog already carries the System-log 7045. 4697 is the Security-log
/// counterpart, and the two fail independently: 7045 is written by the Service
/// Control Manager and survives whatever the audit policy says, while 4697
/// exists only under the Audit Security System Extension subcategory but sits
/// in the same log as the logon events, so no cross-log join is needed to put
/// an installation beside the session that preceded it.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-system-extension>
pub(crate) static EVTX_SECURITY_SERVICE_INSTALL: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_security_service_install",
    name: "Service Installed (Security 4697)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Generated when a service is registered with the Service Control Manager, under the Audit Security System Extension subcategory (Microsoft's stated reason for recommending Success auditing of that subcategory is this very event). It records the service name, the binary path and arguments, the service type, the start type and the account the service will run as — the whole definition of a new execution path that survives reboot. Two things make it worth carrying separately from the System log's 7045. First, it lives in the same log as the logon and process events, so the session that installed it is in the same file and the same rotation window. Second, the subject it records is the context the registration ran in, which on Microsoft's own sample is the machine account rather than the human who initiated it — so 4697 and 7045 are cross-checked to keep attribution honest. The base rate is the trap: Windows 10 and Server 2016 and later mint a per-logon instance of each per-user service template, named <TemplateServiceName>_<LUID> (both the service name and the display name carry the same LUID suffix), and each fresh instance is a service the Security log has never seen before. Filter that noise on the service_file_name — the template family's host binary — rather than on the underscore in the name, which is trivially imitated.",
    mitre_techniques: &["T1543.003", "T1569.002", "T1068"],
    fields: EVTX_SECURITY_SERVICE_INSTALL_FIELDS,
    retention: Some("Security.evtx is a rolling channel sized by policy"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_security", "evtx_system", "evtx_security_account_management"],
    sources: &[
        // Microsoft — 4697: the subcategory, the field list, the Service Start Type table and
        // the sample showing the machine account as Subject:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697",
        // Microsoft — Audit Security System Extension: what the subcategory covers and why
        // Success auditing is recommended for it:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-system-extension",
        // Microsoft — CreateServiceW: the dwStartType constants the event's numbering follows:
        "https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew",
        // Microsoft — Per-user services in Windows: the <service name>_LUID instance naming
        // that produces the benign 4697 volume:
        "https://learn.microsoft.com/en-us/windows/application-management/per-user-services-in-windows",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Exists only where the Audit Security System Extension subcategory was configured — absence is a policy fact, and the System log's 7045 is the record that survives without it",
        "The Subject is the context the registration ran in, which is frequently a system account; reading it as the initiating user misattributes the install",
        "Per-user service instances (<TemplateServiceName>_<LUID>) generate a 4697 per logon session, so raw 4697 volume is dominated by benign operating-system instances",
        "Microsoft documents this event from Windows 10 / Server 2016 onward; on earlier builds the Service Control Manager's 7045 is the only record",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when the channel's maximum size is reached",
};

/// Field schema for the Security-log account and group management family.
///
/// One `net user /add` is not one event: the subcategories emit a cluster
/// inside the same second, and the CLUSTER is the signature. The group events
/// encode the group's scope in the id itself — Microsoft documents the global
/// and universal variants as identical to the local ones except for scope —
/// so 4732 / 4728 / 4756 answer "which kind of group" before a single field is
/// read.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4798>
pub(crate) static EVTX_SECURITY_ACCOUNT_MANAGEMENT_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "Which account-management act this is. User account management: 4720 created, 4722 enabled, 4723 password changed BY THE ACCOUNT ITSELF, 4724 password RESET by another principal, 4725 disabled, 4726 deleted, 4738 changed, 4740 locked out, 4767 unlocked, 4781 renamed, 4798 the user's local group membership was enumerated. Security group management: 4731/4734/4735 local group created/deleted/changed, 4732/4733 member added/removed from a local group, 4727/4730/4737 and 4728/4729 the same acts on a GLOBAL group, 4754/4756 on a UNIVERSAL group, 4764 group type changed, 4799 a group's membership was enumerated",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the act occurred. Cluster the events by second: a single account creation via the built-in tooling emits a create, an enable, a password set and a change record together, so the burst shape — not the lone 4720 — is what the analyst matches",
        is_uid_component: true,
    },
    FieldSchema {
        name: "subject_account",
        value_type: ValueType::Text,
        description: "Subject Account Name, Domain and Logon ID — WHO performed the act. Join the Logon ID back to the session's 4624 to place the change inside a specific logon, remote or local",
        is_uid_component: true,
    },
    FieldSchema {
        name: "target_account",
        value_type: ValueType::Text,
        description: "Target Account Name, Domain and SID — the account acted upon. For 4723 the subject and target are the same principal (a self-service password change); for 4724 they differ, which is an administrative reset of someone else's password and a very different fact",
        is_uid_component: true,
    },
    FieldSchema {
        name: "target_group",
        value_type: ValueType::Text,
        description: "Group Name, Domain and SID for the group events — the privilege actually granted. Read the SID rather than the name for the built-in groups, because names are localised and renameable while S-1-5-32-544 is not",
        is_uid_component: false,
    },
    FieldSchema {
        name: "member_name",
        value_type: ValueType::Text,
        description: "Member Name / Member SID on 4732/4728/4756 and their removal counterparts — the principal added to or removed from the group. The added member is the account that inherits the group's rights at its next logon",
        is_uid_component: false,
    },
    FieldSchema {
        name: "process_name",
        value_type: ValueType::Text,
        description: "Full path of the process that performed the enumeration on 4798/4799 — the field that makes those two usable. It separates a shell or scripting host walking the local Administrators membership from the management, shell and service processes that do the same thing as background work",
        is_uid_component: false,
    },
    FieldSchema {
        name: "process_id",
        value_type: ValueType::UnsignedInt,
        description: "PID of that process; join to the same host's process-creation record to recover its command line and parent, which is where the recon's intent actually shows",
        is_uid_component: false,
    },
];

/// Security-log account and group management — creation, enablement, password
/// changes, group membership and the two enumeration events.
///
/// The catalog previously named only 4720 and 4732 in a summary string. This
/// descriptor carries the family, including the pair that distinguishes a
/// self-service password change (4723) from an administrative reset (4724),
/// the group ids that encode scope, and 4798/4799 — the enumeration events
/// that record the CALLING PROCESS, which is what makes local-group recon
/// visible at all.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management>
pub(crate) static EVTX_SECURITY_ACCOUNT_MANAGEMENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_security_account_management",
    name: "Account and Group Management (Security 4720-4799 family)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Two subcategories write this family. Audit User Account Management covers the account lifecycle — 4720 created, 4722 enabled, 4723 an attempt to CHANGE an account's password, 4724 an attempt to RESET one, 4725 disabled, 4726 deleted, 4738 changed, 4740 locked out, 4767 unlocked, 4781 renamed — plus 4798, a user's local group membership was enumerated. Audit Security Group Management covers the groups — local groups as 4731 created, 4732 member added, 4733 member removed, 4734 deleted, 4735 changed; the identical acts on GLOBAL groups as 4727/4728/4729/4730/4737 and on UNIVERSAL groups as 4754/4756/4757/4758/4755, both of which Microsoft notes generate only for domain groups; 4764 a group's type changed; and 4799, a security-enabled local group's membership was enumerated. Microsoft documents the global and universal events as the same event with the same fields, differing only in the scope of the group — so the event id itself already tells an examiner whether a membership change reached a domain-wide privilege. Three readings are worth naming. 4723 versus 4724 separates a user changing their own password from someone resetting another account's, which is the difference between housekeeping and an account takeover step. A creation performed with the built-in tooling emits several of these ids inside the same second, so the burst — create, enable, password set, change — is the recognisable shape, not the lone 4720. And 4798/4799 are the only records that name the PROCESS that read a group's membership, which is what lets a shell enumerating the local administrators be separated from the management and shell processes that do it constantly as background work.",
    mitre_techniques: &["T1136.001", "T1098", "T1087.001", "T1069.001", "T1078"],
    fields: EVTX_SECURITY_ACCOUNT_MANAGEMENT_FIELDS,
    retention: Some("Security.evtx is a rolling channel sized by policy"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_security", "evtx_security_service_install", "evtx_security_object_access"],
    sources: &[
        // Microsoft — Audit User Account Management: the subcategory's own event list
        // (4720/4722/4723/4724/4725/4726/4738/4740/4767/4781/4798 and more):
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management",
        // Microsoft — Audit Security Group Management: the event list and the statement that
        // the global/universal events are identical to the local ones but for group scope:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management",
        // Microsoft — 4798: a user's local group membership was enumerated, with the calling
        // Process ID and Process Name (documented from Windows 10 / Server 2016):
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4798",
        // Microsoft — 4799: the group-side enumeration event, under the group subcategory:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4799",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "4798 and 4799 are documented from Windows 10 / Server 2016 onward — on earlier builds local-group enumeration leaves no event at all, and its absence says nothing",
        "4798/4799 are high-volume on a normal desktop: shell, management console and service processes enumerate group membership routinely, so the calling process is the discriminator, never the event count",
        "Each event is gated by its own subcategory (user account management or security group management), so half the family can be present while the other half is silent",
        "The group's display name is localised and can be renamed; match built-in groups on their well-known SID instead",
        "An account created and deleted between two collections leaves only these records — and only until the channel rotates",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; account-management records are low volume but share the rotation window with high-volume logon traffic",
};

/// Field schema for the Security-log object access family (4656 / 4658 / 4660 /
/// 4663 / 4670).
///
/// These events exist only where an object's SACL carries the matching ACE
/// *and* the relevant audit subcategory is on — two independent switches, both
/// off by default on a stock host. Where both are set, 4663 is the only
/// event-level record that a named account actually exercised a given access
/// right against a given object.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4656>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4660>
pub(crate) static EVTX_SECURITY_OBJECT_ACCESS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "4656 a handle to an object was requested (Success or Failure — it records the request and its result, not the use), 4663 an access right was USED (Success only), 4658 the handle was closed, 4660 an object was deleted, 4670 permissions on an object were changed",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the access happened. With 4656 and 4658 bracketing it, the pair also bounds how long the handle was held — Microsoft's stated reason for 4658 existing",
        is_uid_component: true,
    },
    FieldSchema {
        name: "subject_account",
        value_type: ValueType::Text,
        description: "Subject Account Name, Domain, SID and Logon ID — the account that touched the object. The Logon ID places the access inside one session, so a file read can be tied back to the logon that opened it",
        is_uid_component: true,
    },
    FieldSchema {
        name: "object_type",
        value_type: ValueType::Text,
        description: "Object Type — File, Key, SAM, Process, Token, Directory and the rest of the kernel object types. It says which subcategory produced the record and how to read Object Name",
        is_uid_component: false,
    },
    FieldSchema {
        name: "object_name",
        value_type: ValueType::Text,
        description: "The object touched: a full file path, a registry key path, or a SAM object path. This is the evidentiary payload — the named thing a named account read, wrote or deleted",
        is_uid_component: true,
    },
    FieldSchema {
        name: "handle_id",
        value_type: ValueType::Text,
        description: "Handle ID — the join key across the family. The same handle links 4656 (requested), 4663 (used) and 4658 (closed), and it is the ONLY identifier on 4660, which does not carry the deleted object's name; recover that name from the matching 4656/4663",
        is_uid_component: false,
    },
    FieldSchema {
        name: "accesses",
        value_type: ValueType::Text,
        description: "Accesses — the rights actually exercised, rendered as names: ReadData/ListDirectory (0x1), WriteData/AddFile (0x2), AppendData/AddSubdirectory (0x4), ReadEA (0x8), WriteEA (0x10), Execute/Traverse (0x20), DELETE, WriteDAC, WriteOwner and so on. For registry objects the same bits carry the key-specific names (query value, set value, enumerate sub-keys). This is the field that separates a file being READ from a file being MODIFIED",
        is_uid_component: false,
    },
    FieldSchema {
        name: "access_mask",
        value_type: ValueType::Text,
        description: "The same rights as the raw bitmask. Match rules on the mask rather than on the rendered Accesses text, which is locale-dependent",
        is_uid_component: false,
    },
    FieldSchema {
        name: "process_name",
        value_type: ValueType::Text,
        description: "Full path and PID of the process that performed the access — names the tool, which is what turns 'this account read the file' into 'this account read it with an archiver at 02:00'",
        is_uid_component: false,
    },
];

/// Security-log object access — the SACL-driven record that a named account
/// read, wrote or deleted a named object.
///
/// The whole family is conditional: an object SACL with the right ACE, plus
/// the subcategory. Where those were configured, this is the only per-event
/// evidence that a specific file was opened by a specific account — the
/// question timestamps alone can never answer.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4670>
pub(crate) static EVTX_SECURITY_OBJECT_ACCESS: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_security_object_access",
    name: "Object Access — SACL Audit (Security 4656/4658/4660/4663/4670)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The object-access family records what a named account did to a named file, registry key or kernel object. 4656 is the handle REQUEST and its outcome (it has Failure variants, so a denied attempt is recorded); 4663 is an access right being USED, which Microsoft draws as the distinction from 4656, and it has no Failure variant; 4658 closes the handle, bounding how long it was held; 4660 records a deletion but carries only the Handle ID, so the name of the deleted object comes from the matching 4656/4663 — Microsoft's own guidance is to track deletions as 4663 with DELETE access instead; 4670 records a permission change on an object, though not a change to the SACL itself. Two switches gate all of it: the object's SACL must carry an ACE for the access in question, and the corresponding subcategory (Audit File System, Audit Registry, Audit Kernel Object, Audit Removable Storage, Audit Handle Manipulation for 4658) must be enabled. Neither is on for ordinary data on a stock host, which is why these events are usually absent — and why, where an organisation did configure them on a sensitive share, they are the strongest available answer to 'did this account open this document'. Read the Accesses/Access Mask to tell reading from writing, and the process name to tell the tool used.",
    mitre_techniques: &["T1005", "T1083", "T1222.001", "T1070.004"],
    fields: EVTX_SECURITY_OBJECT_ACCESS_FIELDS,
    retention: Some("Security.evtx is a rolling channel; object auditing on a busy path is high volume and shortens the window sharply"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_security", "evtx_security_account_management"],
    sources: &[
        // Microsoft — 4663: the SACL precondition, the subcategories, the Accesses table with
        // hex values, Object Type, Handle ID and the difference from 4656:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663",
        // Microsoft — 4656: the handle-request event, with Failure variants:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4656",
        // Microsoft — 4658: handle closed, gated by Audit Handle Manipulation:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4658",
        // Microsoft — 4660: deletion, Handle ID only, and the recommendation to use 4663 with
        // DELETE access instead:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4660",
        // Microsoft — 4670: permissions changed on an object, and what it does NOT cover:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4670",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Absent unless BOTH the object's SACL and the audit subcategory were configured before the activity — absence is a configuration fact and proves nothing about access",
        "4656 records that access was requested and the result, not that the operation was performed; 4663 is the record of a right actually being used",
        "4660 does not name the deleted object — only the Handle ID; resolving it requires the paired 4656/4663 to still be in the log",
        "Indexing, backup and antimalware components exercise exactly the same rights against the same objects as a person does — the subject account and the process name are what separate a user's read from a service's",
        "Auditing a busy path generates enormous volume and rotates the rest of the Security log out of existence — check the channel's size and its earliest record before treating a gap as inactivity",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; object-access auditing is the highest-volume Security traffic when enabled",
};

/// Field schema for Security events 4778 and 4779 — a session was reconnected
/// to, or disconnected from, a Window Station.
///
/// Additional Information carries Client Name and Client Address: the true
/// client identity as the destination host saw it, which is the repair for a
/// Workstation Name that a network logon record never establishes. Session
/// Name is what keeps the pair honest — a console session is Fast User
/// Switching, not RDP.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4778>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4779>
pub(crate) static EVTX_SECURITY_SESSION_RECONNECT_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "4778 a session was reconnected to a Window Station, 4779 a session was disconnected from one. Together they bracket every period a disconnected session was actually in use",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the session was picked up or dropped. A logon followed by several 4778/4779 pairs is one session used across several sittings, which a single logon/logoff pair would flatten into one continuous block",
        is_uid_component: true,
    },
    FieldSchema {
        name: "account_name",
        value_type: ValueType::Text,
        description: "Account Name and Account Domain of the session that was reconnected or disconnected — the identity already logged on, not a fresh authentication",
        is_uid_component: true,
    },
    FieldSchema {
        name: "logon_id",
        value_type: ValueType::Text,
        description: "Logon ID of the session — Microsoft names it as the correlator to recent events carrying the same value, 4624 among them, which is how a reconnect is tied back to the logon that created the session",
        is_uid_component: false,
    },
    FieldSchema {
        name: "session_name",
        value_type: ValueType::Text,
        description: "Session Name: RDP-Tcp#N for a Terminal Services session, 'Console' for the Fast User Switching case, and an identifier ending in #N for a Hyper-V Enhanced Session. Read it before calling a 4778 an RDP reconnection — not every one is",
        is_uid_component: false,
    },
    FieldSchema {
        name: "client_name",
        value_type: ValueType::Text,
        description: "Additional Information Client Name — the computer name the user reconnected FROM, as reported to this host; 'Unknown' for a console session. This is the client-identity field the network logon record does not give you",
        is_uid_component: false,
    },
    FieldSchema {
        name: "client_address",
        value_type: ValueType::Text,
        description: "Additional Information Client Address — the IP of the client, in IPv6 or ::ffff:IPv4 form, with ::1 or 127.0.0.1 meaning localhost and the literal 'LOCAL' for a console session. Pair it with client_name to place the reconnect on a source host",
        is_uid_component: false,
    },
];

/// Security events 4778 / 4779 — the reconnect and disconnect pair that brackets
/// an RDP session's actual periods of use on the destination host.
///
/// A logon record says a session was created; these say when it was being
/// used. They also carry Client Name and Client Address, so a session resumed
/// from a different machine than it was created from is visible — and the
/// Session Name distinguishes RDP from Fast User Switching, which a rule
/// keyed on the event id alone would conflate.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4778>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4779>
pub(crate) static EVTX_SECURITY_SESSION_RECONNECT: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_security_session_reconnect",
    name: "Session Reconnected / Disconnected (Security 4778/4779)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Written on the DESTINATION host under the Audit Other Logon/Logoff Events subcategory when a user reconnects to an existing session (4778) or disconnects from one (4779). Microsoft documents three cases that produce them: reconnecting to a Terminal Services session, switching to an existing desktop via Fast User Switching, and reconnecting to a Hyper-V Enhanced Session — so the Session Name is load-bearing: RDP-Tcp#N is RDP, 'Console' is Fast User Switching. The forensic value is twofold. First, an RDP session is commonly disconnected rather than logged off, so the logon and logoff records bound a session that may have sat idle for days; the 4778/4779 pairs inside it are the periods it was actually being driven. Second, Additional Information carries Client Name and Client Address — the client computer name and IP as this host saw them — which is a truer statement of where the operator sat than a workstation name supplied during authentication, and it exposes a session resumed from a second machine. The Logon ID is Microsoft's documented correlator to the session's other records, including its 4624.",
    mitre_techniques: &["T1021.001", "T1563.002", "T1078"],
    fields: EVTX_SECURITY_SESSION_RECONNECT_FIELDS,
    retention: Some("Security.evtx is a rolling channel sized by policy"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "evtx_security",
        "evtx_rdp_session",
        "evtx_terminal_services",
        "evtx_rdp_core_ts",
    ],
    sources: &[
        // Microsoft — 4778: the subcategory, the three generating cases, Session Name examples
        // (RDP-Tcp#N / Console / Hyper-V Enhanced Session), Client Name and Client Address:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4778",
        // Microsoft — 4779: the disconnect counterpart with the same field blocks:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4779",
        // Practitioner reference already used by the RDP descriptors here, for how these
        // events pair with LocalSessionManager 24/25 in a session timeline:
        "https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Not every 4778 is RDP: Fast User Switching produces one with Session Name 'Console', Client Name 'Unknown' and Client Address 'LOCAL'",
        "Gated by the Audit Other Logon/Logoff Events subcategory — absence is a policy fact, and the TerminalServices-LocalSessionManager channel's 24/25 records cover the same ground independently",
        "Client Name is the name the client reported; corroborate it with Client Address before treating it as the identity of a machine",
        "These events mark reconnection to an EXISTING session, so the account was authenticated earlier — the authentication evidence is the session's original logon record, not this one",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when the channel's maximum size is reached",
};

/// Field schema for Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.
///
/// The message templates come from the provider's own manifest, which settles
/// the direction question: id 131 reads "The server accepted a new {ConnType}
/// connection from client {ClientIP}" — a DESTINATION-side record naming the
/// client's address, not a source-side one.
///
/// Source: <https://github.com/nasbench/EVTX-ETW-Resources>
/// Source: <https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/>
pub(crate) static EVTX_RDP_CORE_TS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "65 a connection object was created, 98 connection established (opcode EstablishConnection), 131 the server accepted a new connection from a client, 140 a connection failed because the user name or password was wrong, 102 the connection was closed, 103 the disconnect reason code",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the transport-level connection was accepted or refused — earlier than any logon record for the same attempt, and present even when no logon follows",
        is_uid_component: true,
    },
    FieldSchema {
        name: "client_ip",
        value_type: ValueType::Text,
        description: "The connecting client's address, from the ClientIP item of 131 (and IPString on 140). This is the destination host's own record of who connected, which survives when the Security log and LocalSessionManager have rotated",
        is_uid_component: true,
    },
    FieldSchema {
        name: "connection_type",
        value_type: ValueType::Text,
        description: "ConnType from 131 — the transport the client negotiated (TCP or UDP). A pair of records for one session is normal, not two sessions",
        is_uid_component: false,
    },
    FieldSchema {
        name: "disconnect_reason",
        value_type: ValueType::UnsignedInt,
        description: "ReasonCode from 103 — the numeric disconnect reason, useful to separate a user-initiated disconnect from a dropped transport when reconstructing why a session ended",
        is_uid_component: false,
    },
];

/// Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational — the
/// destination host's transport-level record of RDP connections.
///
/// This channel sits below the credential check, so it records connections
/// that never authenticate and therefore leave nothing in the session manager
/// or the Security log. It supersedes the generated stub for the same channel,
/// which carries no event ids and no fields.
///
/// Source: <https://github.com/nasbench/EVTX-ETW-Resources>
/// Source: <https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/>
pub(crate) static EVTX_RDP_CORE_TS: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_rdp_core_ts",
    name: "RDP Core TS Operational Log (destination-side connections)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The RDP stack's own operational channel on the machine being connected TO. Its key record is 131, whose manifest text is 'The server accepted a new {ConnType} connection from client {ClientIP}' — a destination-side statement carrying the client's IP, written when the transport is accepted and before any credential check succeeds. That placement is the point: a connection that fails authentication, or that is probed and abandoned, produces a 131 here while leaving nothing in TerminalServices-LocalSessionManager and nothing in the Security log. 140 goes further and records that a connection from a named client address failed because the user name or password was wrong — a destination-side failed-RDP record independent of Security-log auditing. 98 (opcode EstablishConnection) and 102 (CloseConnection) carry no message text in the manifest at all, so a dumped record shows as blank rather than missing; read their data items directly instead of concluding the log is damaged. 103 carries the numeric disconnect reason. The channel has its own size limit, so its retained window is independent of Security.evtx and of the session-manager channel: read all three earliest records before deciding a date is out of range, because this one can still hold the connection after the others have rotated past it.",
    mitre_techniques: &["T1021.001", "T1110.001"],
    fields: EVTX_RDP_CORE_TS_FIELDS,
    retention: Some("Separate channel with its own size limit; commonly reaches back further than Security.evtx on the same host"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "evtx_rdp_inbound",
        "evtx_rdp_session",
        "evtx_terminal_services",
        "evtx_security_session_reconnect",
        "evtx_security_logon_failure",
    ],
    sources: &[
        // Mechanical dump of the RdpCoreTS provider manifest — the channel, opcodes and the
        // message templates of 65/98/102/103/131/140:
        "https://github.com/nasbench/EVTX-ETW-Resources",
        // Practitioner reference already cited by the sibling RDP descriptors, for how this
        // channel fills the gaps left by the other RDP logs:
        "https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "131 records that the server ACCEPTED a transport connection — it is not an authentication, and on its own proves reachability, not access",
        "Events 98 and 102 have no message template in the provider manifest, so tooling renders them without a description; that is the manifest's shape, not a corrupted record",
        "Internet-facing hosts accumulate 131 records from untargeted scanning; the client address matters, the event count does not",
        "One session can produce more than one 131 (the client may negotiate more than one transport) — counting 131s overcounts sessions",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; rotates on its own size limit, independently of Security.evtx",
};

/// Field schema for the Application-log crash pair — Application Error (1000)
/// and Windows Error Reporting (1001).
///
/// The two records come from DIFFERENT sources in the same channel, and they
/// carry the same attribution twice: 1000 in named fields, 1001 in the
/// report's problem-signature parameters. Either can survive the other.
///
/// Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-application-service-crashing-behavior>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wer/windows-error-reporting>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-werreportsetparameter>
pub(crate) static EVTX_APPLICATION_CRASH_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "1000 the crash itself, from the Application Error source; 1001 the error report, from the Windows Error Reporting source. Filter on the source name as well as the id — other providers also write 1000 into this channel",
        is_uid_component: true,
    },
    FieldSchema {
        name: "source_name",
        value_type: ValueType::Text,
        description: "The event source: 'Application Error' for 1000, 'Windows Error Reporting' for 1001. The pair is what makes the record identifiable, since the ids are not unique within the Application channel",
        is_uid_component: true,
    },
    FieldSchema {
        name: "faulting_application_name",
        value_type: ValueType::Text,
        description: "Faulting application name, with its version and PE time stamp — the executable that died. This is execution evidence for a binary that may no longer exist on disk, and the version/time-stamp pair identifies WHICH build ran",
        is_uid_component: true,
    },
    FieldSchema {
        name: "faulting_application_path",
        value_type: ValueType::Text,
        description: "Full path of the faulting executable — the location matters as much as the name: the same filename under a temp or profile directory is a different fact from the one in System32",
        is_uid_component: false,
    },
    FieldSchema {
        name: "faulting_module_name",
        value_type: ValueType::Text,
        description: "Faulting module name, version and time stamp, with the module path — the DLL (or the executable itself) executing when the fault hit. Microsoft notes it is often a heavily used system module such as ntdll.dll or kernelbase.dll, so a system module here does not implicate that module",
        is_uid_component: false,
    },
    FieldSchema {
        name: "exception_code",
        value_type: ValueType::Text,
        description: "Exception code — 0xc0000005 is an access violation, the usual shape of both an ordinary bug and a failed exploit attempt. It classifies the crash; it does not attribute it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "fault_offset",
        value_type: ValueType::Text,
        description: "Offset within the faulting module where execution stopped — with the module version, this is what makes two crashes comparable across hosts",
        is_uid_component: false,
    },
    FieldSchema {
        name: "faulting_process_id",
        value_type: ValueType::UnsignedInt,
        description: "PID of the crashed process, for joining to process-creation records and to any dump written for the same run",
        is_uid_component: false,
    },
    FieldSchema {
        name: "faulting_application_start_time",
        value_type: ValueType::Timestamp,
        description: "Raw FILETIME of when the crashed process STARTED — a process start time recovered from a crash record, independent of the event's own rendered time, and often the only surviving evidence of when a short-lived process ran",
        is_uid_component: false,
    },
    FieldSchema {
        name: "report_id",
        value_type: ValueType::Guid,
        description: "Report Id — joins the 1000 record to the 1001 error report and to the report directory on disk, so a crash can be followed into the WER report and any dump it kept",
        is_uid_component: false,
    },
    FieldSchema {
        name: "problem_signature",
        value_type: ValueType::List,
        description: "Problem-signature parameters P1..P10 carried by the 1001 report. Their meaning is defined per report type by whatever created the report (the Win32 API sets them by index), so read them against the report's own event/bucket name rather than assuming a fixed order — for crash reports they repeat the application and module identity that the 1000 record holds in named fields",
        is_uid_component: false,
    },
];

/// Application.evtx crash records — the execution evidence of last resort.
///
/// Where process-creation auditing was never enabled, a crash still names the
/// executable, its path, its build and the time its process STARTED. The
/// generated `evtx_application` stub describes the channel; this descriptor
/// carries the two records worth reading in it.
///
/// Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-application-service-crashing-behavior>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wer/windows-error-reporting>
pub(crate) static EVTX_APPLICATION_CRASH: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_application_crash",
    name: "Application Crash Records (Application 1000 / 1001)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Application.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Two records in the Application channel turn a crash into execution evidence. Event 1000, from the 'Application Error' source, is the crash itself: it names the faulting application (name, version, PE time stamp and full path), the faulting module (name, version, time stamp and path), the exception code, the fault offset, the faulting process id, the Report Id, and — the field most often overlooked — the faulting application's START time as a raw FILETIME. That start time is a process-execution timestamp recovered from a log that nobody has to enable, which is why this channel is the fallback when process-creation auditing was never configured and Prefetch is disabled or absent. Event 1001, from the 'Windows Error Reporting' source, is the report raised for the same fault; it preserves the same identity in the report's problem-signature parameters and links to the report on disk by Report Id, so the attribution can survive even if the 1000 record has rotated out. Microsoft's own guidance pairs the two ids when diagnosing repeated crashes. Read the module name with care: a system module such as ntdll.dll or kernelbase.dll is the usual bearer of a fault raised by someone else's code.",
    mitre_techniques: &["T1203", "T1055", "T1562.001"],
    fields: EVTX_APPLICATION_CRASH_FIELDS,
    retention: Some("Application.evtx is a rolling channel sized by policy and written by every application on the host"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_application", "wer_report_queue", "windows_minidump", "evtx_system"],
    sources: &[
        // Microsoft — the crash-troubleshooting guidance that reproduces a full 1000 record
        // (source name, faulting application/module fields, exception code, fault offset,
        // faulting process id, faulting application start time, Report Id) and pairs it with 1001:
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-application-service-crashing-behavior",
        // Microsoft — Windows Error Reporting: what the 1001 report is and what it retains:
        "https://learn.microsoft.com/en-us/windows/win32/wer/windows-error-reporting",
        // Microsoft — WerReportSetParameter: the P1..P10 problem-signature parameters and the
        // fact that their meaning is set per report by the reporting code:
        "https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-werreportsetparameter",
        // Microsoft — Collecting user-mode dumps: the LocalDumps configuration that decides
        // whether a dump for this crash was also written to disk:
        "https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "A crash proves the binary RAN; it says nothing about who started it or why it failed — most 1000 records are ordinary software defects",
        "Event id 1000 is not unique in the Application channel: other sources write it too, so match on the source name as well",
        "The faulting module is usually a widely used system DLL; treating it as the malicious component is the standard misreading of this record",
        "The report's problem-signature parameters are positional and their meaning is defined by the reporting code, so decoding them without the report type invents field names",
        "Every application on the host writes to this channel, so its retained window can be shorter than the Security log's — read the channel's configured size and its earliest record rather than assuming the crash is still there",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; a chatty application can rotate the crash record out within hours",
};

/// Field schema for the PowerShell 7 (PowerShell Core) operational channel.
///
/// The channel is `PowerShellCore/Operational`, which on disk is
/// `PowerShellCore%4Operational.evtx` — the `%4` is how the event log escapes
/// the `/` in a channel name. A collector configured with a literal space or
/// slash in that filename matches nothing and returns silently.
///
/// Source: <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows>
pub(crate) static EVTX_POWERSHELL_CORE_OPERATIONAL_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "4104 (0x1008) is the script-block logging record Microsoft documents for this channel — the executed script text, in PowerShell 7's own log rather than Windows PowerShell's",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the script block was processed. PowerShell 7 runs side by side with Windows PowerShell 5.1, so build a single timeline across both channels before concluding what ran when",
        is_uid_component: true,
    },
    FieldSchema {
        name: "script_block_text",
        value_type: ValueType::Text,
        description: "The content of the processed script block — the payload itself, including text that was decoded or generated at run time and therefore never existed on disk",
        is_uid_component: false,
    },
    FieldSchema {
        name: "script_block_id",
        value_type: ValueType::Guid,
        description: "Identifier shared by the fragments of one script block, with the message-number pair that orders them; reassemble on this before reading a long payload, or the text will be read out of order",
        is_uid_component: false,
    },
    FieldSchema {
        name: "path",
        value_type: ValueType::Text,
        description: "Script path when the block came from a file, empty when it was entered or generated in memory — an empty path is itself the observation that the code never touched the filesystem",
        is_uid_component: false,
    },
];

/// PowerShell 7 / PowerShell Core operational channel — the second PowerShell
/// log a modern host can have.
///
/// PowerShell 7 installs alongside Windows PowerShell 5.1 and logs to its OWN
/// channel under its OWN policy. Two consequences an examiner has to hold:
/// script-block logging enabled for 5.1 does nothing for 7, and on Windows the
/// provider has to be REGISTERED before any event can be written at all — so
/// an empty channel may mean the provider was never registered, not that
/// PowerShell 7 was never used.
///
/// Source: <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows>
pub(crate) static EVTX_POWERSHELL_CORE_OPERATIONAL: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_powershell_core_operational",
    name: "PowerShell 7 (PowerShellCore) Operational Log",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\PowerShellCore%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Microsoft documents PowerShell 7's logging as its own event log, named PowerShellCore (ETW provider {f90714a8-5509-434a-bf6d-b1624c8a19a2}), with script-block logging writing event id 4104 to PowerShellCore/Operational — separate from the Windows PowerShell channels an examiner normally opens. Three facts follow, and each one has produced a wrong 'no PowerShell activity' conclusion. First, PowerShell 7 installs SIDE BY SIDE with Windows PowerShell 5.1 rather than replacing it, so a host can have two engines and two logs, and only reviewing both gives the full picture. Second, the policy is separate: PowerShell 7's script-block logging is enabled under its own Group Policy node and its own registry path (HKLM\\Software\\Policies\\Microsoft\\PowerShellCore\\ScriptBlockLogging), so an organisation that enabled logging for Windows PowerShell has enabled nothing here. Third — and this one has no counterpart in 5.1 — Windows requires PowerShell 7's event provider to be REGISTERED before events can be written at all, via the RegisterManifest.ps1 script shipped in the install directory; on a host where that was never run, the channel is empty no matter what was executed. The channel name contains a slash, which the event log stores as the %4 escape: the file is PowerShellCore%4Operational.evtx, and a collection rule written with a literal space or slash matches no file and reports nothing.",
    mitre_techniques: &["T1059.001", "T1562.002"],
    fields: EVTX_POWERSHELL_CORE_OPERATIONAL_FIELDS,
    retention: Some("Separate channel with its own size limit; absent entirely on hosts where PowerShell 7 was never installed"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_powershell", "evtx_powershell_classic", "powershell_history"],
    sources: &[
        // Microsoft — about_Logging_Windows (PowerShell 7): the PowerShellCore log name and
        // provider GUID, the 4104 record on PowerShellCore/Operational, the mandatory provider
        // registration via RegisterManifest.ps1, and the separate PowerShellCore policy node:
        "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "An empty or missing channel is not evidence that PowerShell 7 was unused: the provider must be registered on Windows before any event is written, and script-block logging must be enabled under the separate PowerShellCore policy",
        "Enabling script-block logging for Windows PowerShell 5.1 does not cover PowerShell 7 — the two engines read different policy paths",
        "A dual-engine host needs BOTH this channel and the Windows PowerShell channels reviewed before any statement about what was run",
        "Script-block records can contain credentials and other sensitive data supplied to a script; handle the extracted text accordingly",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; script-block logging is verbose and rotates its own channel quickly",
};

/// Field schema for auto-archived event logs (`Archive-<LogName>-*.evtx`) and
/// the per-log retention values that decide whether they exist.
///
/// The archive behaviour is a pair of registry values, not one:
/// `AutoBackupLogFiles` only takes effect when `Retention` says never
/// overwrite. Reading the flag alone reports archiving on a host that does not
/// archive.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1105>
pub(crate) static EVTX_LOG_AUTO_ARCHIVE_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "archive_path",
        value_type: ValueType::Text,
        description: "Full path of an archived log, in the form %SystemRoot%\\System32\\winevt\\Logs\\Archive-<LogName>-YYYY-MM-DD-HH-MM-SS-mmm.evtx. The embedded timestamp is when the archive was cut, so the file name alone orders the host's log history",
        is_uid_component: true,
    },
    FieldSchema {
        name: "source_channel",
        value_type: ValueType::Text,
        description: "The channel the archive came from, taken from the <LogName> component (Archive-Security-*, Archive-System-*, Archive-Application-*). Each archive holds records OLDER than the live channel — the pre-rotation history a live-log-only collection misses entirely",
        is_uid_component: true,
    },
    FieldSchema {
        name: "auto_backup_log_files",
        value_type: ValueType::UnsignedInt,
        description: "AutoBackupLogFiles (REG_DWORD) under the log's Eventlog key — 1 asks the service to save the log when it fills. Default 0. It is honoured only when Retention is -1 (0xFFFFFFFF); set alone it is ignored, so read the pair, never this value by itself. \
                      ONE DOCUMENTED EXCEPTION, and it is a Microsoft carve-out rather than a misreading: the same Eventlog Key page records that on Windows Server 2003, Retention can be set to -1 (0xFFFFFFFF) OR 1 (0x00000001) for AutoBackupLogFiles to work, other values being ignored. The -1-only rule above is stated for this descriptor's Win7Plus scope; a Server 2003 host showing Retention = 1 alongside AutoBackupLogFiles = 1 was configured for archiving on that platform, so do not read it as a misconfiguration that produced no archives",
        is_uid_component: false,
    },
    FieldSchema {
        name: "retention",
        value_type: ValueType::UnsignedInt,
        description: "Retention (REG_DWORD) — 0, the default, means records are always overwritten (the ordinary circular behaviour); 0xFFFFFFFF or any non-zero value means records are never overwritten and new events are discarded once the log is full until it is cleared. This value decides whether the host keeps history or drops it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "max_size",
        value_type: ValueType::UnsignedInt,
        description: "MaxSize (REG_DWORD, bytes) — the size at which the log fills, and therefore how much history one archive covers. Compare it against the observed record rate to judge how far back the live channel can possibly reach",
        is_uid_component: false,
    },
    FieldSchema {
        name: "file",
        value_type: ValueType::Text,
        description: "File (REG_SZ/REG_EXPAND_SZ) — the fully qualified path of the log, optional and defaulting to the winevt\\Logs directory. A non-default value RELOCATES the evidence, so an examiner who collects only the default directory silently misses the log; it is equally an anti-forensic lever worth checking",
        is_uid_component: false,
    },
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "In the Security channel itself: 1105 records that the log filled and a new file was created, naming the BackupPath of the archive just written; 1104 records that the log is full under the do-not-overwrite setting. Both are written by the Eventlog provider. \
                      The SAME provider writes two further Security records that mark a hole in the audit trail rather than an archive, and Microsoft documents neither: 1101 \"Audit events have been dropped by the transport.\" (Level 2 = win:Error, Task 101 = 'Event processing', Version 0, payload UserData/AuditEventsDropped/Reason, a single win:UInt8) and 1106 \"Events have been dropped by the event logging service.\" (payload UserData/AuditFailure/Reason). The transport in 1101 is ETW, NOT a network: the same provider's event 103 binds the same Reason field to a valueMap named DroppedEventReasons whose keys 0x20/0x21/0x22 are Microsoft's documented ETW RT_LostEvent types 32/33/34. Producer-side loss has its own documented event, 4612, which reports a COUNT of discarded messages where 1101 reports none. Undocumented by Microsoft; read from the compiled Microsoft-Windows-Eventlog manifest, dumped independently by two projects using different methods from real installs spanning Windows 7 SP1 (7601) to build 18990, and corroborated by strings in the shipping wevtsvc.dll and lsaadt.dll",
        is_uid_component: false,
    },
    FieldSchema {
        name: "dropped_events_reason",
        value_type: ValueType::UnsignedInt,
        description: "The Reason payload of 1101 (UserData/AuditEventsDropped/Reason) and 1106 (UserData/AuditFailure/Reason) — a single win:UInt8. Unlike the sibling event 103, 1101's Reason carries NO valueMap in any manifest checked from build 7600 to 18990, so the viewer prints the raw integer and no OS-side string exists for it; every published real-world 1101 located carries 0, which falls outside the enumerated DroppedEventReasons set (0x20 no free buffers, 0x21 a real-time consumer could not catch up, 0x22 the real-time backing file was corrupt after an improper shutdown). Carry the value verbatim and do not read 0 as any of those three causes",
        is_uid_component: false,
    },
];

/// Auto-archived Windows event logs — the pre-rotation history most collections
/// never take.
///
/// When a log is configured to archive rather than overwrite, Windows writes
/// `Archive-<LogName>-<timestamp>.evtx` beside the live log and does not prune
/// it. That directly answers the "the Security log only reaches back two days"
/// problem — but only for an examiner who knows to look, because nothing in
/// the live channel's own name suggests the older files exist.
///
/// The descriptor also carries the Eventlog provider's other Security-channel
/// records about the same investigative question — whether the audit trail has
/// a hole and why. 1104 (log full) and 1105 (archived) are documented; 1101
/// (audit events dropped by the ETW transport) and 1106 (dropped by the event
/// logging service) are not, and their entries say so and name the shipped
/// Microsoft artefacts they were read from.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1105>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/etw/rt-lostevent>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4612>
pub(crate) static EVTX_LOG_AUTO_ARCHIVE: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_log_auto_archive",
    name: "Auto-Archived Event Logs (Archive-<LogName>-*.evtx)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Archive-*.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Where a log is set to archive when full, the event log service writes the filled log out as %SystemRoot%\\System32\\winevt\\Logs\\Archive-<LogName>-<YYYY-MM-DD-HH-MM-SS-mmm>.evtx and starts a new live file; Microsoft's own 1105 sample shows exactly that BackupPath. The archives are ordinary EVTX files, they are not pruned, and they hold the records the live channel has already rotated past — so on a host configured this way the answer to 'the Security log only covers the last two days' is that the rest is sitting in the same directory under a different name. Three registry values under each log's Eventlog key decide the behaviour and are readable from an offline SYSTEM hive: Retention (0 = always overwrite, the default; 0xFFFFFFFF = never overwrite), AutoBackupLogFiles (1 = save the log when full, default 0, and honoured ONLY when Retention is -1), and MaxSize (the fill threshold, so how much history each archive covers). The same key's File value can relocate a log away from winevt\\Logs entirely — an evidence-location question on any host, and an anti-forensics check on a suspect one. Two Security records mark the events themselves: 1105 when the log filled and was archived (naming the new file), and 1104 when the log filled under do-not-overwrite, after which new events are DISCARDED until someone clears it — a silent blind spot that looks identical to inactivity. The same Eventlog provider marks a second kind of gap, one that leaves no archive and no tamper artefact at all: Security 1101, 'Audit events have been dropped by the transport.', written when audit records were generated and never reached the Security log. Microsoft does not document it — the event-1101 reference page 404s and the Other Events page lists only 1100, 1102, 1104, 1105 and 1108 — so what follows is read from the provider's own compiled manifest (dumped independently by two projects from real installs, Windows 7 SP1 through build 18990) and from strings in the shipping wevtsvc.dll and lsaadt.dll. The transport is ETW's real-time session rather than a network: the provider's event 103 binds the same Reason field to a DroppedEventReasons map whose keys 0x20/0x21/0x22 are Microsoft's documented ETW RT_LostEvent types 32/33/34, and NEITHER forwarding provider defines a 1101 at all (Microsoft-Windows-Forwarding carries only 100-107, Microsoft-Windows-EventCollector only 1-6, 501 and 502, and the WEF drop event is 502). Windows itself treats the event as an audit failure: lsaadt.dll carries a literal subscription to 1101, 1104 and 1106 from Microsoft-Windows-Eventlog beside CrashOnAuditFail and LsapAdtInitializeCrashOnAuditFail, which are exactly the three conditions LSA's crash-on-audit-fail policy watches. Benign drivers dominate and are excluded first — audit volume outrunning the consumer, and the dirty-shutdown case at the following boot — while the adversarial reading is log starvation, flooding a host with auditable activity so genuine records fall off the transport. Either way the consequence is the same as the 1104 case and it is the reason the event is recorded here: across the window a 1101 marks, 'there is no 4624 for that account' is not evidence of absence.",
    mitre_techniques: &["T1070.001", "T1562.002"],
    fields: EVTX_LOG_AUTO_ARCHIVE_FIELDS,
    retention: Some("Archived files are not pruned by the event log service; they persist until deleted"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_security", "evtx_system", "evtx_application"],
    sources: &[
        // Microsoft — Eventlog Key: the File, MaxSize, Retention and AutoBackupLogFiles values,
        // their defaults, and the rule that auto-backup applies only when Retention is -1:
        "https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key",
        // Microsoft — 1105: the log filled and a new file was created, with the `Archive-<Log>-`
        // <timestamp>.evtx BackupPath in the sample record:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1105",
        // Microsoft — 1104: the security log is now full, the do-not-overwrite condition under
        // which subsequent events are discarded:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1104",
        // Microsoft — wevtutil: reads and sets a channel's log path, size and retention mode
        // on a live host:
        "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil",
        // Microsoft — ETW RT_LostEvent: EventType 32/33/34 = RTLostEvent / RTLostBuffer /
        // RTLostFile, the three causes the Eventlog provider's DroppedEventReasons map mirrors at
        // 0x20/0x21/0x22, and the basis for reading 1101's "transport" as ETW rather than a network:
        "https://learn.microsoft.com/en-us/windows/win32/etw/rt-lostevent",
        // Microsoft — 4612, the producer-side audit-loss sibling and the only audit-loss event
        // Microsoft documents; it reports a COUNT of discarded messages where 1101 reports none:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4612",
        // Microsoft — the Other Events reference, cited for what it does NOT contain: 1100, 1102,
        // 1104, 1105 and 1108 only, which is the measured basis for calling 1101 undocumented:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/other-events",
        // Microsoft — winmeta.xml (Windows SDK, mirrored in microsoft/perfview): win:AuditSuccess
        // 0x0020000000000000 and win:AuditFailure 0x0010000000000000, decoding 1101's Keywords:
        "https://github.com/microsoft/perfview/blob/main/src/related/EventRegister/winmeta.xml",
        // Compiled Microsoft-Windows-Eventlog manifest, dump A — per-build from real installs;
        // gives 1101's Security channel, Error level, "Event processing" task and message string,
        // and shows neither forwarding provider defining a 1101:
        "https://github.com/nasbench/EVTX-ETW-Resources",
        // Compiled Microsoft-Windows-Eventlog manifest, dump B — independent author, independent
        // (TDH) method; gives 1101's template and the DroppedEventReasons valueMap that 103 uses:
        "https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-Eventlog.xml",
        // lsaadt.dll strings (build 10.0.22622.601) — LSA's literal XPath subscription to 1101,
        // 1104 and 1106 from Microsoft-Windows-Eventlog, beside CrashOnAuditFail:
        "https://github.com/WinDLLsExports/10_0_22622_601/blob/main/C/Windows/System32/lsaadt.dll.strings",
        // MITRE Engenuity Center for Threat-Informed Defense — an independent institutional
        // mapping of 1101 to DS0013 Sensor Health / Host Status:
        "https://github.com/center-for-threat-informed-defense/sensor-mappings-to-attack",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Archives exist only where the host was configured for them: AutoBackupLogFiles set to 1 AND Retention set to never-overwrite. Either alone produces no archive",
        "The 'Retention must be 0xFFFFFFFF' rule is stated for this descriptor's Win7Plus scope. Microsoft documents a Server 2003 carve-out on the same page — there, Retention could be -1 (0xFFFFFFFF) OR 1 (0x00000001) for AutoBackupLogFiles to work — so on a Server 2003 image Retention = 1 with AutoBackupLogFiles = 1 is a working archive configuration, not a broken one",
        "Absence of Archive-*.evtx is a configuration fact, never evidence that the missing period was quiet",
        "The File value can move a log out of winevt\\Logs, so a collection scoped to the default directory can miss both the live log and its archives",
        "A host in the 1104 state is DISCARDING new events while the log stays full — the resulting gap looks exactly like inactivity and is the opposite of it",
        "Archived files are ordinary EVTX and can be deleted like any file; their timestamps and the 1105 records should be cross-checked for gaps",
        "Security 1101 carries NO count of what was lost, unlike the documented 4612 which reports a 'Number of audit messages discarded'. It DATES a gap and cannot SIZE it, so the evidence it supplies is probative rather than definitive and a single 1101 is not evidence of a small gap",
        "1101's Keywords is 0x4020000000000000, which per Microsoft's winmeta.xml is win:AuditSuccess (0x0020000000000000) OR'd with a provider-defined bit at 0x4000000000000000 — so a viewer renders it as 'Audit Success' while its Level is Error. A Security-log filter on 'Audit Failure' misses it entirely; filter on Level = Error to catch it beside 1104",
        "1101 is NOT a Windows Event Forwarding artefact, and reading it as one inverts what it says about the host: Microsoft-Windows-Forwarding defines only events 100-107, Microsoft-Windows-EventCollector only 1-6, 501 and 502, and the forwarding drop event is 502 in that provider's Operational channel",
        "Event encyclopedias reproduce 1101 with a trailing sentence, 'The real time backup file was corrupt due to improper shutdown.' That string is the DroppedEventReasons 0x22 map entry belonging to the SIBLING event 103, not to 1101, and it is echoed downstream by several sites; the dirty-shutdown association may hold empirically, but the quoted message text is not what Windows emits. Neighbouring secondary claims are wrong outright — 1101 is not the successor of Windows 2003 event 566 (the pre-Vista audit-loss event is 516, whose successor is the documented 4612), its task is 'Event processing' rather than a service-shutdown category, and its Level is Error rather than Warning",
        "No audit subcategory is established as gating or attributing 1101 — it is written by the event log service rather than the audit policy engine, and Microsoft's Other Events reference, which is the Other System Events documentation, omits it. Treat any subcategory attribution as unestablished rather than merely wrong",
        "SigmaHQ carries no rule for Security 1101 (control: 30 of its files match 1102), so this signal appears only where it was collected deliberately. Absence of an alert is not absence of the condition",
        "Microsoft-Windows-Winlogon's manifest defines a TASK numbered 1101 (WinSqmUserLogin) and no EVENT 1101 — a survey that greps provider metadata for the bare string will hit it",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Written once when a log fills and never pruned by the service; persists until explicitly deleted",
};

/// Field schema for target-side remote-execution host lineage.
///
/// A 4624 Logon Type 3 looks the same whichever remote-execution channel
/// produced it. The process that hosts the payload does not: WinRM-based
/// PowerShell remoting runs it under the PowerShell host process, and a WMI
/// provider call runs under the WMI provider host. Naming the host process is
/// what turns "something authenticated over the network" into "this channel
/// was used".
///
/// Source: <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/powershell-remoting-faq>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wmisdk/provider-hosting-and-security>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer>
pub(crate) static EVTX_REMOTE_EXECUTION_HOST_LINEAGE_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "host_process_name",
        value_type: ValueType::Text,
        description: "The process hosting the remotely requested work. Wsmprovhost.exe is the PowerShell host process that WS-Management starts on the remote computer for a fan-out PowerShell remoting session. Wmiprvse.exe is the WMI provider host, the process providers are loaded into and the parent of work performed through them. Scrcons.exe is the server for ActiveScriptEventConsumer, so it appears when a WMI subscription payload fires rather than when a user connects",
        is_uid_component: true,
    },
    FieldSchema {
        name: "child_process_name",
        value_type: ValueType::Text,
        description: "What the host process started. This is the payload and it is the thing worth hashing and timelining; the host process only says which channel delivered it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "parent_chain",
        value_type: ValueType::Text,
        description: "The ancestry between the payload and the host process. Do not assume it is one link: a channel that starts a command interpreter first leaves the interpreter as the payload's immediate parent, so a rule matching only the direct parent misses the case. Walk ancestors, not the parent field",
        is_uid_component: false,
    },
    FieldSchema {
        name: "logon_id",
        value_type: ValueType::Text,
        description: "Logon ID of the session the host process runs under — the join from this process lineage back to the 4624 that authenticated it, and therefore to the source address and account",
        is_uid_component: false,
    },
    FieldSchema {
        name: "process_id",
        value_type: ValueType::UnsignedInt,
        description: "PID of the host process, for joining process-creation records, handle tables and a memory image of the same moment",
        is_uid_component: false,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the host process started. Compare it with the session's 4624 and with the channel's own log (WinRM or WMI-Activity) to confirm the three views describe one event",
        is_uid_component: false,
    },
];

/// Target-side process lineage that names WHICH remote-execution channel was
/// used.
///
/// The catalog already covers the authentication side and the channel logs.
/// This is the third view: on the destination host, the host process under
/// which remotely requested work executes. It is what separates PowerShell
/// remoting from a WMI method call when both show up as an otherwise identical
/// network logon.
///
/// Source: <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/powershell-remoting-faq>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wmisdk/provider-hosting-and-security>
pub(crate) static EVTX_REMOTE_EXECUTION_HOST_LINEAGE: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_remote_execution_host_lineage",
    name: "Remote-Execution Host Process Lineage (target side)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Read against process-creation records on the host that was reached. A network logon tells an examiner that an account authenticated; it does not say through which channel, because every remote-execution mechanism produces the same Logon Type 3. The host process does say. Microsoft documents that for fan-out PowerShell remoting, WS-Management starts the PowerShell host process Wsmprovhost.exe on the remote computer — so a payload whose ancestry runs back to Wsmprovhost.exe arrived over WinRM. WMI providers are loaded into the WMI provider host Wmiprvse.exe, so work performed through a WMI provider is parented there rather than under the service that authenticated the caller. A WMI permanent subscription with an ActiveScriptEventConsumer runs its body in Scrcons.exe, which is a persistence firing rather than an interactive connection, and dates the subscription's execution even after the consumer object is gone. DCOM-based activation is brokered by the RPC/DCOM service (RpcSs) that Microsoft describes as coordinating requests from other services using RPC or DCOM over port 135, so a DCOM-launched server is parented under the service host running it and not under the caller. Two traps: match ANCESTORS rather than the immediate parent, because a channel that starts a command interpreter first leaves that interpreter as the payload's direct parent; and remember that PowerShell remoting over SSH does not use WinRM at all, so it produces no Wsmprovhost.exe and the lineage runs back to the SSH daemon instead.",
    mitre_techniques: &["T1021.006", "T1047", "T1021.003", "T1059.001", "T1546.003"],
    fields: EVTX_REMOTE_EXECUTION_HOST_LINEAGE_FIELDS,
    retention: Some("Derived from process-creation records and live process state; bounded by the Security channel's rotation or by the memory image"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "evtx_security",
        "evtx_winrm",
        "evtx_wmi_activity",
        "evtx_security_explicit_credentials",
        "wmi_subscriptions",
    ],
    sources: &[
        // Microsoft — PowerShell Remoting FAQ: WS-Management starts the PowerShell host process
        // Wsmprovhost.exe on the remote computer for fan-out remoting, while the fan-in (IIS)
        // configuration runs all sessions in one host process instead:
        "https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/powershell-remoting-faq",
        // Microsoft — PowerShell remoting over SSH: the transport that does NOT use WinRM, and
        // therefore does not produce the WinRM host process:
        "https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell",
        // Microsoft — Provider Hosting and Security: providers are loaded into Wmiprvse.exe:
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/provider-hosting-and-security",
        // Microsoft — ActiveScriptEventConsumer: Scrcons.exe is the class's server, the process
        // a subscription payload executes in:
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer",
        // Microsoft — winrs: the Windows Remote Shell client that runs a command on a remote
        // host over WS-Management:
        "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/winrs",
        // Microsoft — service and port reference: the RPC service (RpcSs) coordinates requests
        // from services using RPC or DCOM, on port 135:
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "This lineage exists only where process creation was recorded (audit policy or an endpoint agent) or where a memory image was taken — without one of those there is nothing to read",
        "Match ancestors, not the immediate parent: a channel that launches a command interpreter first leaves the interpreter as the payload's direct parent, and a parent-only filter misses the whole class",
        "The host processes are legitimate Windows binaries that run during ordinary administration; their presence is a channel identification, never a finding on its own",
        "Microsoft documents a fan-in remoting configuration in which all PowerShell sessions share one host process rather than one process per session — counting host processes does not count sessions",
        "PowerShell remoting over SSH bypasses WinRM entirely, so absence of the WinRM host process does not rule out PowerShell remoting",
        "Microsoft's published reference does not name a target-side host binary for the winrs client, so establish that process name on the host under examination rather than assuming one",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Live process ancestry is lost on process exit or reboot; only the recorded process-creation events or a memory image preserve it",
};
