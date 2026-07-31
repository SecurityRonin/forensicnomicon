//! Event ID enrichment module.
//!
//! Provides a static table of Windows Event IDs with forensic descriptions,
//! MITRE ATT&CK technique mappings, and catalog artifact associations.

/// Enrichment entry for a Windows Event ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EventIdEntry {
    /// Windows Event ID.
    pub event_id: u32,
    /// Log channel (e.g. "Security", "System", "Application").
    pub channel: &'static str,
    /// Short description of what this event means forensically.
    pub description: &'static str,
    /// MITRE ATT&CK technique IDs associated with this event.
    pub mitre_techniques: &'static [&'static str],
    /// Catalog artifact IDs that contain or produce this event.
    pub artifact_ids: &'static [&'static str],
    /// Triage relevance: is this a high-value event to look for?
    pub high_value: bool,
    /// Collection/interpretation caveats specific to this event ID (empty when none).
    pub caveats: &'static str,
}

/// Static table of well-known Windows Event IDs with forensic enrichment.
pub static EVENT_ID_TABLE: &[EventIdEntry] = &[
    EventIdEntry {
        event_id: 104,
        channel: "System",
        description: "Event log cleared (provider Microsoft-Windows-Eventlog, LogFileCleared) — \
                      System records the clearing of ANY channel here (the message names the cleared \
                      {Channel}); Security additionally records its own clearing in the Security channel \
                      itself via event 1102",
        mitre_techniques: &["T1070.001"],
        artifact_ids: &["evtx_system"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 1102,
        channel: "Security",
        description: "The audit log was cleared — recorded in the Security log itself (with the \
                      SubjectUserSid/SubjectLogonId of the account that cleared it). Unlike other \
                      channels, whose clearing is recorded by System event 104, Security records its \
                      own clearing here via 1102",
        mitre_techniques: &["T1070.001"],
        artifact_ids: &["evtx_security"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4624,
        channel: "Security",
        description: "Successful logon",
        mitre_techniques: &["T1078"],
        artifact_ids: &["evtx_security"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4625,
        channel: "Security",
        description: "Failed logon — brute force indicator",
        mitre_techniques: &["T1110"],
        artifact_ids: &["evtx_security"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4648,
        channel: "Security",
        description: "Logon with explicit credentials",
        mitre_techniques: &["T1550.002"],
        artifact_ids: &["evtx_security"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4663,
        channel: "Security",
        description: "Object access attempt",
        mitre_techniques: &["T1005"],
        artifact_ids: &["evtx_security"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4688,
        channel: "Security",
        description: "Process creation",
        mitre_techniques: &["T1059"],
        artifact_ids: &["evtx_security"],
        high_value: true,
        caveats: "Two independent GPO toggles gate this event. (1) The event itself is OFF by \
                  default: it requires the 'Audit Process Creation' policy (Advanced Audit \
                  Configuration > Detailed Tracking), default Not Configured — absence of 4688 does \
                  not prove absence of process execution, only that auditing was disabled. (2) The \
                  ProcessCommandLine field is a SECOND, separate toggle: 'Include command line in \
                  process creation events' (Administrative Templates\\System\\Audit Process Creation), \
                  default Not Configured, effective only when Audit Process Creation is already \
                  enabled; when on it writes each process's full command line in plaintext (which can \
                  itself leak secrets passed on the command line)",
    },
    EventIdEntry {
        event_id: 4698,
        channel: "Security",
        description: "Scheduled task created",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_security", "scheduled_tasks_dir"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4702,
        channel: "Security",
        description: "Scheduled task updated",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_security"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4720,
        channel: "Security",
        description: "User account created",
        mitre_techniques: &["T1136.001"],
        artifact_ids: &["evtx_security", "sam_users"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4732,
        channel: "Security",
        description: "Member added to security-enabled local group",
        mitre_techniques: &["T1098"],
        artifact_ids: &["evtx_security"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4768,
        channel: "Security",
        description: "Kerberos TGT requested",
        mitre_techniques: &["T1558.003"],
        artifact_ids: &["evtx_security"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4769,
        channel: "Security",
        description: "Kerberos service ticket requested",
        mitre_techniques: &["T1558.003"],
        artifact_ids: &["evtx_security"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4771,
        channel: "Security",
        description: "Kerberos pre-authentication failed",
        mitre_techniques: &["T1110"],
        artifact_ids: &["evtx_security"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4776,
        channel: "Security",
        description: "NTLM authentication",
        mitre_techniques: &["T1550.002"],
        artifact_ids: &["evtx_security"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 7045,
        channel: "System",
        description: "Service installed",
        mitre_techniques: &["T1543.003"],
        artifact_ids: &["evtx_system"],
        high_value: true,
        caveats: "",
    },
    // ── 13Cubed IWE additions ─────────────────────────────────────────────────
    // Security — logon / privilege / account lifecycle
    EventIdEntry {
        event_id: 4634,
        channel: "Security",
        description: "Logoff (system-generated)",
        mitre_techniques: &[],
        artifact_ids: &["evtx_security"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4647,
        channel: "Security",
        description: "User-initiated logoff",
        mitre_techniques: &[],
        artifact_ids: &["evtx_security"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4672,
        channel: "Security",
        description: "Special privileges assigned to new logon (admin-equivalent)",
        mitre_techniques: &["T1078"],
        artifact_ids: &["evtx_security"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4722,
        channel: "Security",
        description: "User account enabled",
        mitre_techniques: &["T1098"],
        artifact_ids: &["evtx_security"],
        high_value: true,
        caveats: "",
    },
    // RDP / TerminalServices
    EventIdEntry {
        event_id: 21,
        channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        description: "RDP session logon succeeded",
        mitre_techniques: &["T1021.001"],
        artifact_ids: &["evtx_rdp_session", "evtx_terminal_services"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 22,
        channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        description: "RDP shell (session) start",
        mitre_techniques: &["T1021.001"],
        artifact_ids: &["evtx_rdp_session", "evtx_terminal_services"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 1149,
        channel: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        description: "RDP network connection established (label 'auth succeeded' is misleading — \
                      precedes credential validation; corroborate with 21/22 or 4624 Type 10)",
        mitre_techniques: &["T1021.001"],
        artifact_ids: &["evtx_rdp_inbound", "evtx_terminal_services"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 1029,
        channel: "Microsoft-Windows-TerminalServices-RDPClient/Operational",
        description: "RDP client: Base64(SHA-256(UTF-16LE(username))) of the connecting username, logged on the SOURCE host (Win10+); correlation aid, reversible via a username wordlist",
        mitre_techniques: &["T1021.001"],
        artifact_ids: &["evtx_rdp_client", "evtx_terminal_services"],
        high_value: false,
        caveats: "",
    },
    // Task Scheduler operational
    EventIdEntry {
        event_id: 106,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task registered (created)",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler", "scheduled_tasks_dir"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 140,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task updated",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 141,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task deleted",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 200,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task action started",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 201,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task action completed",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler"],
        high_value: false,
        caveats: "",
    },
    // PowerShell
    EventIdEntry {
        event_id: 4103,
        channel: "Microsoft-Windows-PowerShell/Operational",
        description: "PowerShell module logging",
        mitre_techniques: &["T1059.001"],
        artifact_ids: &["evtx_powershell"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4104,
        channel: "Microsoft-Windows-PowerShell/Operational",
        description: "PowerShell script block logging — captures full script content. PowerShell v5+ \
                      auto-logs script blocks whose text matches its built-in suspicious-content \
                      signature list at WARNING level (LevelDisplayName='Warning') even when Script \
                      Block Logging is NOT configured via policy — a record-of-last-resort that yields \
                      free evidence on unconfigured hosts. Ordinary (fully-configured) 4104 logs at \
                      Verbose (Level 5). Triage tip: filter 4104 on Level=Warning to surface the flagged \
                      subset; dynamically generated / Invoke-Expression'd code emits its own 4104",
        mitre_techniques: &["T1059.001"],
        artifact_ids: &["evtx_powershell"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 400,
        channel: "Windows PowerShell",
        description: "PowerShell engine/session start (classic log)",
        mitre_techniques: &["T1059.001"],
        artifact_ids: &["evtx_powershell_classic"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 600,
        channel: "Windows PowerShell",
        description: "PowerShell provider start/stop (classic log)",
        mitre_techniques: &["T1059.001"],
        artifact_ids: &["evtx_powershell_classic"],
        high_value: false,
        caveats: "",
    },
    // System — services
    EventIdEntry {
        event_id: 7034,
        channel: "System",
        description: "Service crashed unexpectedly",
        mitre_techniques: &["T1543.003"],
        artifact_ids: &["evtx_system"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 7036,
        channel: "System",
        description: "Service started/stopped",
        mitre_techniques: &["T1543.003"],
        artifact_ids: &["evtx_system"],
        high_value: false,
        caveats: "",
    },
    // Defender
    EventIdEntry {
        event_id: 1116,
        channel: "Microsoft-Windows-Windows Defender/Operational",
        description: "Microsoft Defender detected malware",
        mitre_techniques: &["T1059"],
        artifact_ids: &["evtx_defender"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 1117,
        channel: "Microsoft-Windows-Windows Defender/Operational",
        description: "Microsoft Defender took action (remediation)",
        mitre_techniques: &[],
        artifact_ids: &["evtx_defender"],
        high_value: false,
        caveats: "",
    },
    // ESENT / NTDS.dit (Application log) — unusual NTDS location ⇒ credential theft
    EventIdEntry {
        event_id: 216,
        channel: "Application",
        description: "ESENT: a database location change was detected — embeds the from->to paths \
                      (e.g. C:\\Windows\\NTDS\\ntds.dit -> a HarddiskVolumeShadowCopyN device path). \
                      Fires routinely during VSS-based backups, so low-fidelity alone — a shadow-copy \
                      device path is expected/benign; corroborate with 325 to an unusual path",
        mitre_techniques: &["T1003.003"],
        artifact_ids: &["evtx_application"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 325,
        channel: "Application",
        description: "ESENT: the database engine created a new database — records the full DB path. \
                      ntdsutil IFM 'create full <path>' writes a fresh (defragmented) ntds.dit copy, so \
                      a 325 whose path is OUTSIDE the standard %SystemRoot%\\NTDS\\ — especially \
                      world-writable staging (C:\\Users\\Public, C:\\ProgramData, C:\\Windows\\Temp, \
                      C:\\PerfLogs) — is strongly consistent with credential-theft staging. Correlate \
                      with a following 327 (detach) on the same path and an ntdsutil.exe process-create \
                      (4688 / Sysmon 1)",
        mitre_techniques: &["T1003.003"],
        artifact_ids: &["evtx_application"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 326,
        channel: "Application",
        description: "ESENT: database attached",
        mitre_techniques: &["T1003.003"],
        artifact_ids: &["evtx_application"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 327,
        channel: "Application",
        description: "ESENT: database detached",
        mitre_techniques: &["T1003.003"],
        artifact_ids: &["evtx_application"],
        high_value: false,
        caveats: "",
    },
    // ── Lateral movement / discovery / service-install / network telemetry ──
    // Verified against Microsoft Learn Security-auditing docs + Ultimate Windows
    // Security encyclopedia (never 13cubed).
    EventIdEntry {
        event_id: 5140,
        channel: "Security",
        description: "A network share object was accessed (records the share connection, e.g. C$/ADMIN$/IPC$; does not list the individual files)",
        mitre_techniques: &["T1021.002"],
        artifact_ids: &["evtx_security"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 5145,
        channel: "Security",
        description: "Detailed File Share: a network share object was checked for desired access, logging the accessed file/relative path (very high volume)",
        mitre_techniques: &["T1021.002"],
        artifact_ids: &["evtx_security"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4798,
        channel: "Security",
        description: "A user's local group membership was enumerated (common during host reconnaissance)",
        mitre_techniques: &["T1069.001", "T1087.001"],
        artifact_ids: &["evtx_security"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4799,
        channel: "Security",
        description: "A security-enabled local group membership was enumerated (recon tell of net localgroup / BloodHound-class enumeration)",
        mitre_techniques: &["T1069.001", "T1087.001"],
        artifact_ids: &["evtx_security"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4778,
        channel: "Security",
        description: "A session was reconnected to a window station (RDP reconnect; records only reconnects, not new connections)",
        mitre_techniques: &["T1021.001"],
        artifact_ids: &["evtx_security", "evtx_terminal_services"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4779,
        channel: "Security",
        description: "A session was disconnected from a window station (RDP/console disconnect)",
        mitre_techniques: &["T1021.001"],
        artifact_ids: &["evtx_security", "evtx_terminal_services"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 4697,
        channel: "Security",
        description: "A service was installed in the system (Security log; requires audit policy — complements System-log 7045; inspect the service binary path)",
        mitre_techniques: &["T1543.003"],
        artifact_ids: &["evtx_security", "services_hklm"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 5156,
        channel: "Security",
        description: "The Windows Filtering Platform permitted a connection (source/destination IP+port, PID, protocol); enables process-to-network correlation when Sysmon is absent (very high volume)",
        mitre_techniques: &[],
        artifact_ids: &["evtx_security"],
        high_value: false,
        caveats: "",
    },
    // --- Sysmon (Microsoft-Windows-Sysmon/Operational) --------------------------
    // Operation codes and meanings per the authoritative Sysinternals Sysmon
    // schema (learn.microsoft.com/sysinternals/downloads/sysmon). Gap surfaced by
    // the dfir-scripts.github.io diff; verified against the Sysinternals docs.
    // ATT&CK mappings are the forensic interpretation (the technique the event is
    // evidence of), left empty for pure-visibility events. EIDs 21 and 22 share
    // their numbers with the TerminalServices RDP channel; the table is keyed by
    // (channel, event_id), so both meanings coexist — see event_entry_on.
    EventIdEntry {
        event_id: 1,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Process creation — full command line, process/parent hashes, parent image, and integrity level for every new process; the primary Sysmon execution-visibility event",
        mitre_techniques: &[],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 2,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "A process changed a file creation time (timestomp) — backdating a file's creation time to blend a dropped file into older activity",
        mitre_techniques: &["T1070.006"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 3,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Network connection — process-to-network correlation: source and destination IP/port, protocol, and the initiating process image and PID",
        mitre_techniques: &[],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "High volume; typically scoped to specific processes/ports in config",
    },
    EventIdEntry {
        event_id: 5,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Process terminated — process end time; pairs with EID 1 to bound a process lifetime for timeline reconstruction",
        mitre_techniques: &[],
        artifact_ids: &["evtx_sysmon"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 6,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Driver loaded — signature status and hashes of a loaded kernel-mode driver; unsigned or known-vulnerable drivers indicate rootkits or bring-your-own-vulnerable-driver (BYOVD)",
        mitre_techniques: &["T1014"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 7,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Image loaded — a module/DLL was loaded into a process (signature + hashes); surfaces DLL side-loading and unsigned-module injection",
        mitre_techniques: &["T1574.002"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "Very high volume — usually scoped by config to specific images/paths",
    },
    EventIdEntry {
        event_id: 8,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "CreateRemoteThread — a process created a thread in another process's address space; a classic code-injection primitive",
        mitre_techniques: &["T1055"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 9,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "RawAccessRead — a process read a volume directly via the \\\\.\\ device path, bypassing the filesystem (used to extract locked files such as NTDS.dit / SAM, or to scrape $MFT / $UsnJrnl)",
        mitre_techniques: &["T1006"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 10,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Process accessed — a process opened a handle to another process (ProcessAccess); LSASS access with credential-read access masks indicates credential dumping",
        mitre_techniques: &["T1003.001"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 11,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "File created — a new file was created (path, initiating process, creation time); surfaces dropped payloads, staged archives, and tool output",
        mitre_techniques: &[],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 12,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Registry object added or deleted (RegistryEvent) — creation or deletion of a registry key or value",
        mitre_techniques: &["T1112"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 13,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Registry value set (RegistryEvent) — the new data written to a registry value; captures persistence and configuration tampering (Run keys, service ImagePath, etc.)",
        mitre_techniques: &["T1112"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 14,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Registry key or value renamed (RegistryEvent)",
        mitre_techniques: &["T1112"],
        artifact_ids: &["evtx_sysmon"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 15,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "File stream created with an alternate data stream hash (FileCreateStreamHash) — captures Zone.Identifier mark-of-the-web and payloads hidden in NTFS alternate data streams",
        mitre_techniques: &["T1564.004"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 16,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Sysmon configuration state changed — the running Sysmon configuration was updated; an attacker altering config can blind the sensor (defense evasion)",
        mitre_techniques: &["T1562.001"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 17,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Named pipe created (PipeEvent) — pipe name and creating process; C2 frameworks (e.g. Cobalt Strike default pipe names) and lateral-movement tooling create characteristic pipes",
        mitre_techniques: &[],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 18,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Named pipe connected (PipeEvent) — a client connected to a named pipe; pairs with EID 17 for pipe-based IPC and SMB named-pipe lateral movement",
        mitre_techniques: &[],
        artifact_ids: &["evtx_sysmon"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 19,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "WMI event filter registered (WmiEvent, WmiEventFilter) — the trigger half of a WMI permanent event subscription, a fileless persistence mechanism",
        mitre_techniques: &["T1546.003"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 20,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "WMI event consumer registered (WmiEvent, WmiEventConsumer) — the payload half of a WMI permanent event subscription (commonly CommandLine/ActiveScript consumers)",
        mitre_techniques: &["T1546.003"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 21,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "WMI consumer bound to a filter (WmiEvent, WmiEventConsumerToFilter) — logs the consumer name and filter path; the binding is what arms a WMI permanent event subscription, so it completes the pair recorded by EIDs 19 and 20",
        mitre_techniques: &["T1546.003"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "Shares its number with RDP session logon on the TerminalServices-LocalSessionManager/Operational channel — resolve by (channel, id)",
    },
    EventIdEntry {
        event_id: 22,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "DNS query (DnsQuery) — the queried name, the results, and the process that asked; recorded whether the query succeeded or failed, cached or not, so it maps C2 and staging domains back to a PID",
        mitre_techniques: &[],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "Telemetry added for Windows 8.1 — not available on Windows 7 and earlier. Shares its number with RDP session disconnect on the TerminalServices-LocalSessionManager/Operational channel — resolve by (channel, id)",
    },
    EventIdEntry {
        event_id: 23,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "File deleted and archived (FileDelete) — Sysmon captured the deleted file's contents to its archive directory before removal; recovers anti-forensically deleted artifacts",
        mitre_techniques: &["T1070.004"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 24,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Clipboard content changed (ClipboardChange) — new clipboard text captured to the Sysmon archive; can surface copied credentials, commands, or crypto addresses",
        mitre_techniques: &[],
        artifact_ids: &["evtx_sysmon"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 25,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Process image tampering (ProcessTampering) — the on-disk image no longer matches the mapped/running image; process hollowing, herpaderping, or doppelgänging",
        mitre_techniques: &["T1055.012"],
        artifact_ids: &["evtx_sysmon"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 26,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "File delete logged (FileDeleteDetected) — a file deletion was recorded without archiving its content (a lighter-weight companion to EID 23)",
        mitre_techniques: &["T1070.004"],
        artifact_ids: &["evtx_sysmon"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 27,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Executable creation blocked (FileBlockExecutable) — Sysmon prevented an executable image from being written to disk (block-mode configuration)",
        mitre_techniques: &[],
        artifact_ids: &["evtx_sysmon"],
        high_value: false,
        caveats: "Only emitted when FileBlockExecutable is configured (Sysmon 13.30+)",
    },
    EventIdEntry {
        event_id: 28,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "File shredding blocked (FileBlockShredding) — Sysmon prevented an anti-forensic file-shredding overwrite (block-mode configuration)",
        mitre_techniques: &[],
        artifact_ids: &["evtx_sysmon"],
        high_value: false,
        caveats: "Only emitted when FileBlockShredding is configured (Sysmon 14.0+)",
    },
    EventIdEntry {
        event_id: 29,
        channel: "Microsoft-Windows-Sysmon/Operational",
        description: "Executable file detected on creation (FileExecutableDetected) — a PE/executable was written to disk (hash + path), without blocking",
        mitre_techniques: &[],
        artifact_ids: &["evtx_sysmon"],
        high_value: false,
        caveats: "Only emitted when FileExecutableDetected is configured (Sysmon 14.0+)",
    },
    // --- BITS client (Microsoft-Windows-Bits-Client/Operational) ----------------
    // Meanings are Microsoft's own message templates and EventData field names,
    // taken from the provider manifest shipped in qmgr.dll (provider
    // Microsoft-Windows-Bits-Client, GUID {EF1CC15B-46C1-414E-BB95-E76B077BD51E}).
    // Source: https://github.com/nasbench/EVTX-ETW-Resources (ETWProvidersManifests
    // .../WEPExplorer/Microsoft-Windows-Bits-Client.xml — a mechanical dump of the
    // OS binary's manifest). Lineage checked against Microsoft Learn, which
    // publishes 16404 (EVT_SERVICE_FAILED) with the same message string the dump
    // carries, so the dump reproduces Microsoft's strings rather than a
    // third-party paraphrase:
    // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc734722(v=ws.10)
    // ATT&CK is left to the events that carry the abuse observables — who created
    // the job, what URL, what local path; the pure lifecycle/status events get
    // none. EIDs 3 and 5 share their numbers with Sysmon, hence the (channel, id) key.
    EventIdEntry {
        event_id: 3,
        channel: "Microsoft-Windows-Bits-Client/Operational",
        description: "The BITS service created a new job — transfer job name, Job ID (GUID), owner and, from manifest version 2, the creating Process Path and Process ID; that process path is what ties a background download to the tool that requested it",
        mitre_techniques: &["T1197"],
        artifact_ids: &["evtx_bits_client"],
        high_value: true,
        caveats: "Older manifest versions carry only the job name and owner — Process Path and Process ID were added in version 2. Shares its number with Sysmon network connection — resolve by (channel, id)",
    },
    EventIdEntry {
        event_id: 4,
        channel: "Microsoft-Windows-Bits-Client/Operational",
        description: "The transfer job is complete — user, transfer job name, Job ID, owner and file count (manifest version 1 adds bytes transferred, and bytes sourced from a peer); the clean end of a BITS job",
        mitre_techniques: &[],
        artifact_ids: &["evtx_bits_client"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 5,
        channel: "Microsoft-Windows-Bits-Client/Operational",
        description: "Job cancelled — user, job name, Job ID, owner and file count for a job removed before it completed (bitsadmin /cancel, Remove-BitsTransfer, or the owning client dropping it)",
        mitre_techniques: &[],
        artifact_ids: &["evtx_bits_client"],
        high_value: false,
        caveats: "Shares its number with Sysmon process terminated — resolve by (channel, id)",
    },
    EventIdEntry {
        event_id: 16403,
        channel: "Microsoft-Windows-Bits-Client/Operational",
        description: "BITS job file parameters — RemoteName (the source URL) and LocalName (the local destination path), alongside user, job title, Job ID, owner, file count and process ID; the one event that says what a job fetched and where it landed",
        mitre_techniques: &["T1197"],
        artifact_ids: &["evtx_bits_client"],
        high_value: true,
        caveats: "The provider manifest carries no message string for this ID, only a template — Event Viewer renders 'the description for Event ID 16403 cannot be found' and the evidence sits entirely in the EventData fields. Join to events 3/59/60/61 on the Job ID",
    },
    EventIdEntry {
        event_id: 59,
        channel: "Microsoft-Windows-Bits-Client/Operational",
        description: "BITS started the transfer job associated with a URL — job name, the URL, and the transfer/job GUIDs; the URL is the download destination an abused BITS job reaches out to",
        mitre_techniques: &["T1197"],
        artifact_ids: &["evtx_bits_client"],
        high_value: true,
        caveats: "Carries the URL but not the local path — pair with 16403 on the Job ID to learn where the file landed",
    },
    EventIdEntry {
        event_id: 60,
        channel: "Microsoft-Windows-Bits-Client/Operational",
        description: "BITS stopped transferring the job associated with a URL, with an hr status code — the same message text event 61 carries, logged here at Information level (61 is the Warning-level twin)",
        mitre_techniques: &[],
        artifact_ids: &["evtx_bits_client"],
        high_value: false,
        caveats: "The message template is byte-identical to 61; only the Level and the hr status code separate them",
    },
    EventIdEntry {
        event_id: 61,
        channel: "Microsoft-Windows-Bits-Client/Operational",
        description: "BITS stopped transferring the job associated with a URL, with an hr status code — the same message text as event 60, logged here at Warning level, which is what marks the stop as an error or transient failure rather than a clean one",
        mitre_techniques: &[],
        artifact_ids: &["evtx_bits_client"],
        high_value: false,
        caveats: "Warning level and the hr code are the only discriminators against 60. BITS retries transient failures, so a 61 followed by a 59 is a retry of the same job, not a new one",
    },
    // --- Microsoft Defender Antivirus (Microsoft-Windows-Windows Defender/Operational) ---
    // Verified against Microsoft Learn (defender-endpoint/troubleshoot-microsoft-defender-antivirus):
    // symbolic name + message per event. The 5001/5007/5010/5012 "disabled/changed"
    // events are prime defense-evasion (T1562.001) indicators.
    EventIdEntry {
        event_id: 1006,
        channel: "Microsoft-Windows-Windows Defender/Operational",
        description: "Microsoft Defender Antivirus found malware or other potentially unwanted software (threat name, severity, file path, detection source) — MALWAREPROTECTION_MALWARE_DETECTED",
        mitre_techniques: &[],
        artifact_ids: &["evtx_defender_operational"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 1015,
        channel: "Microsoft-Windows-Windows Defender/Operational",
        description: "Microsoft Defender Antivirus detected suspicious behavior (behavior/heuristic-based detection) — MALWAREPROTECTION_BEHAVIOR_DETECTED",
        mitre_techniques: &[],
        artifact_ids: &["evtx_defender_operational"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 5001,
        channel: "Microsoft-Windows-Windows Defender/Operational",
        description: "Microsoft Defender Antivirus real-time protection was disabled — defense evasion (MALWAREPROTECTION_RTP_DISABLED)",
        mitre_techniques: &["T1562.001"],
        artifact_ids: &["evtx_defender_operational"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 5007,
        channel: "Microsoft-Windows-Windows Defender/Operational",
        description: "Microsoft Defender Antivirus configuration changed (old value -> new value) — may indicate an attacker weakening AV, e.g. adding scan exclusions (MALWAREPROTECTION_CONFIG_CHANGED)",
        mitre_techniques: &["T1562.001"],
        artifact_ids: &["evtx_defender_operational"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 5010,
        channel: "Microsoft-Windows-Windows Defender/Operational",
        description: "Microsoft Defender Antivirus scanning for malware and spyware was disabled — defense evasion (MALWAREPROTECTION_ANTISPYWARE_DISABLED)",
        mitre_techniques: &["T1562.001"],
        artifact_ids: &["evtx_defender_operational"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 5012,
        channel: "Microsoft-Windows-Windows Defender/Operational",
        description: "Microsoft Defender Antivirus scanning for viruses was disabled — defense evasion (MALWAREPROTECTION_ANTIVIRUS_DISABLED)",
        mitre_techniques: &["T1562.001"],
        artifact_ids: &["evtx_defender_operational"],
        high_value: true,
        caveats: "",
    },
    // --- System channel: service control + shutdown/power (Microsoft provider docs) ---
    EventIdEntry {
        event_id: 7031,
        channel: "System",
        description: "A service terminated unexpectedly (service name, crash count, recovery action) — can indicate a killed security/EDR service or an unstable implant",
        mitre_techniques: &[],
        artifact_ids: &["evtx_system"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 7040,
        channel: "System",
        description: "The start type of a service was changed (e.g. Automatic -> Disabled, or Disabled -> Automatic) — persistence enablement, or defense evasion when a security service is disabled",
        mitre_techniques: &["T1543.003"],
        artifact_ids: &["evtx_system"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 7009,
        channel: "System",
        description: "A timeout was reached while waiting for a service to connect/start — service start failure",
        mitre_techniques: &[],
        artifact_ids: &["evtx_system"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 1074,
        channel: "System",
        description: "System shutdown or restart was initiated — records the initiating process, user, and reason code; the who/why of a reboot",
        mitre_techniques: &[],
        artifact_ids: &["evtx_system"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 6005,
        channel: "System",
        description: "The Event Log service was started — a system boot marker (logging came up)",
        mitre_techniques: &[],
        artifact_ids: &["evtx_system"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 6006,
        channel: "System",
        description: "The Event Log service was stopped — a clean-shutdown marker (logging went down in an orderly stop)",
        mitre_techniques: &[],
        artifact_ids: &["evtx_system"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 6008,
        channel: "System",
        description: "The previous system shutdown was unexpected (dirty shutdown) — power loss, crash, or forced power-off; can accompany anti-forensic activity or a bugcheck",
        mitre_techniques: &[],
        artifact_ids: &["evtx_system"],
        high_value: true,
        caveats: "",
    },
    EventIdEntry {
        event_id: 6013,
        channel: "System",
        description: "System uptime in seconds (logged at boot / periodically) — helps bound boot windows in a timeline",
        mitre_techniques: &[],
        artifact_ids: &["evtx_system"],
        high_value: false,
        caveats: "",
    },
    EventIdEntry {
        event_id: 41,
        channel: "System",
        description: "Kernel-Power: the system rebooted without cleanly shutting down first — an unexpected/dirty reboot (power loss, bugcheck, or hard reset)",
        mitre_techniques: &[],
        artifact_ids: &["evtx_system"],
        high_value: true,
        caveats: "Provider Microsoft-Windows-Kernel-Power on the System channel",
    },
];

/// Look up enrichment for an event ID, ignoring the channel.
///
/// The table's real key is `(channel, event_id)`: the same number means
/// different things on different channels — 21 is a Sysmon
/// `WmiEventConsumerToFilter` binding *and* an RDP session logon, 3 is a Sysmon
/// network connection *and* a BITS job creation. This function returns the
/// **first** entry in table order that carries the number, which is only the
/// entry the caller meant when the id happens to be unique.
///
/// Use [`event_entry_on`] whenever the channel is known — that is the
/// unambiguous lookup — and [`events_for_id`] to see every channel that defines
/// the number. This function is kept for callers who genuinely have nothing but
/// a number, and its first-match behaviour is deliberate rather than incidental.
pub fn event_entry(event_id: u32) -> Option<&'static EventIdEntry> {
    EVENT_ID_TABLE.iter().find(|e| e.event_id == event_id)
}

/// Look up enrichment for an event ID **on a specific channel** — the
/// unambiguous lookup, and the one to reach for whenever the record being
/// enriched carries its channel (every EVTX record does).
///
/// `channel` is compared case-insensitively (ASCII), because Windows channel
/// names are case-insensitive and tools round-trip them in varying case. There
/// is no numeric fallback: a channel that does not define the id yields `None`
/// rather than some other channel's meaning.
pub fn event_entry_on(channel: &str, event_id: u32) -> Option<&'static EventIdEntry> {
    EVENT_ID_TABLE
        .iter()
        .find(|e| e.event_id == event_id && e.channel.eq_ignore_ascii_case(channel))
}

/// Every entry that defines `event_id`, across all channels.
///
/// This is the honest answer when the channel is unknown: an id shared by two
/// channels yields both, so the caller can show the analyst the ambiguity
/// instead of silently picking one.
pub fn events_for_id(event_id: u32) -> impl Iterator<Item = &'static EventIdEntry> {
    EVENT_ID_TABLE
        .iter()
        .filter(move |e| e.event_id == event_id)
}

/// Look up all events associated with a catalog artifact.
pub fn events_for_artifact(artifact_id: &str) -> Vec<&'static EventIdEntry> {
    EVENT_ID_TABLE
        .iter()
        .filter(|e| e.artifact_ids.contains(&artifact_id))
        .collect()
}

/// Return all high-value event IDs.
pub fn high_value_events() -> Vec<&'static EventIdEntry> {
    EVENT_ID_TABLE.iter().filter(|e| e.high_value).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_nonempty() {
        assert!(!EVENT_ID_TABLE.is_empty());
    }

    #[test]
    fn logon_event_4624_exists() {
        let e = event_entry(4624).expect("Event 4624 (logon) should exist");
        assert_eq!(e.channel, "Security");
        assert!(e.high_value);
    }

    #[test]
    fn process_creation_4688_exists() {
        let e = event_entry(4688).expect("Event 4688 (process creation) should exist");
        assert!(!e.mitre_techniques.is_empty());
    }

    /// EID 1029 (RDP client username hash) is Base64(SHA-256(UTF-16LE(username)))
    /// on the TerminalServices-RDPClient/Operational channel (provider
    /// ClientActiveXCore), logged on the SOURCE host. Win7/2008R2 used SHA1 but
    /// do not log 1029. Sources: nullsec.us (Event ID 1029 Hashes), Aon/Stroz
    /// Friedberg (Variations in Logging for Event ID 1029), EricZimmerman evtx maps.
    #[test]
    fn event_1029_username_hash_is_sha256_on_rdpclient_channel() {
        let e = event_entry(1029).expect("Event 1029 should exist");
        assert_eq!(
            e.channel, "Microsoft-Windows-TerminalServices-RDPClient/Operational",
            "1029 username-hash artifact is on the RDPClient/Operational channel, not RdpCoreTS"
        );
        assert!(
            e.description.contains("SHA-256") || e.description.contains("SHA256"),
            "1029 hash is SHA-256, not SHA1: got {:?}",
            e.description
        );
        assert!(
            !e.description.contains("SHA1") && !e.description.contains("SHA-1"),
            "1029 description must not claim SHA1: got {:?}",
            e.description
        );
    }

    /// ESENT 216/325 are the ntdsutil-IFM-dump discriminators, but 216 alone is benign
    /// VSS-backup noise (low_value) while 325's out-of-standard DB path is the high-value
    /// signal. Source: MS esent-event-327-326; ntdsutil ifm ref; Cyberis; SigmaHQ.
    #[test]
    fn esent_216_is_low_fidelity_325_flags_ifm_staging() {
        let e216 = event_entry(216).expect("Event 216 should exist");
        assert!(
            !e216.high_value,
            "ESENT 216 fires on every VSS backup — it is corroboration, not a standalone red flag"
        );
        assert!(
            e216.description.contains("VSS") || e216.description.contains("backup"),
            "216 description must note the benign VSS-backup baseline: got {:?}",
            e216.description
        );
        let e325 = event_entry(325).expect("Event 325 should exist");
        assert!(
            e325.description.contains("IFM") || e325.description.contains("create full"),
            "325 must name the ntdsutil IFM 'create full' dump path: got {:?}",
            e325.description
        );
        assert!(
            e325.description.contains("PerfLogs") || e325.description.contains("staging"),
            "325 must flag world-writable staging as the discriminator: got {:?}",
            e325.description
        );
    }

    /// Event 4688 process-creation carries two GPO-gated collection caveats: the event is
    /// off by default (Audit Process Creation) and the command-line field is a second,
    /// separate toggle. Source: MS event-4688 + command-line-process-auditing docs.
    #[test]
    fn event_4688_documents_gpo_toggles() {
        let e = event_entry(4688).expect("4688 exists");
        assert!(
            e.caveats.contains("Audit Process Creation"),
            "4688 must caveat that the event is off by default (Audit Process Creation)"
        );
        assert!(
            e.caveats.contains("command line"),
            "4688 must caveat that ProcessCommandLine is a second, separate GPO toggle"
        );
    }

    /// Log-clearing (104 System / 1102 Security) cross-log semantics and 4104 PowerShell
    /// auto-suspicious Warning logging. Sources: nasbench eventlog manifest; MS event-1102;
    /// MS PowerShell CompiledScriptBlock.cs / "PowerShell the Blue Team" devblog.
    #[test]
    fn log_clearing_and_ps_scriptblock_semantics() {
        let e104 = event_entry(104).expect("104 exists");
        assert!(
            e104.description.contains("1102"),
            "104 should cross-reference Security's own 1102 self-log: got {:?}",
            e104.description
        );
        let e1102 = event_entry(1102).expect("1102 exists");
        assert!(
            !e1102.description.contains("exception to the 104 pattern"),
            "1102 must not assert the unverified exclusivity claim"
        );
        let e4104 = event_entry(4104).expect("4104 exists");
        assert!(
            e4104.description.contains("Warning"),
            "4104 must document the auto-suspicious Warning-level record-of-last-resort"
        );
        assert!(
            !e4104.description.contains("Informational")
                && !e4104.description.contains("(decoded)"),
            "4104: Level 5 is Verbose not Informational, and drop the blanket (decoded) claim"
        );
    }

    /// Lateral-movement / discovery / service-install / network-telemetry events
    /// surfaced by the IWE reconciliation. Verified against Microsoft Learn
    /// Security-auditing docs + the Ultimate Windows Security encyclopedia — never
    /// 13cubed. (id, channel, a keyword the description must contain)
    const NEW_SECURITY_EVENTS: &[(u32, &str, &str)] = &[
        (5140, "Security", "share"),              // network share accessed
        (5145, "Security", "share"),              // detailed file share
        (4798, "Security", "local group"),        // user's local group membership enumerated
        (4799, "Security", "local group"),        // security-enabled local group enumerated
        (4778, "Security", "reconnect"),          // session reconnected to a window station
        (4779, "Security", "disconnect"),         // session disconnected from a window station
        (4697, "Security", "service"), // service installed (Security log; cf. 7045 in System)
        (5156, "Security", "filtering platform"), // WFP permitted a connection
    ];

    #[test]
    fn new_security_events_present_with_correct_channel() {
        for &(id, channel, desc_kw) in NEW_SECURITY_EVENTS {
            let e = event_entry(id)
                .unwrap_or_else(|| panic!("Event {id} must be present in EVENT_ID_TABLE"));
            assert_eq!(e.channel, channel, "Event {id} channel mismatch");
            assert!(
                e.description.to_lowercase().contains(desc_kw),
                "Event {id} description should mention {desc_kw:?}: got {:?}",
                e.description
            );
        }
    }

    #[test]
    fn unknown_event_returns_none() {
        assert!(event_entry(99999).is_none());
    }

    #[test]
    fn evtx_security_has_events() {
        let events = events_for_artifact("evtx_security");
        assert!(
            !events.is_empty(),
            "evtx_security should have event associations"
        );
    }

    #[test]
    fn high_value_events_nonempty() {
        let hv = high_value_events();
        assert!(hv.len() >= 5);
        assert!(hv.iter().all(|e| e.high_value));
    }

    /// 13Cubed IWE course-taught Event IDs that must be present in the table,
    /// each with the channel the course assigns. (id, channel)
    const IWE_REQUIRED: &[(u32, &str)] = &[
        // Security — logon / privilege / account lifecycle
        (4634, "Security"),
        (4647, "Security"),
        (4672, "Security"),
        (4722, "Security"),
        // RDP / TerminalServices
        (
            21,
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        ),
        (
            22,
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        ),
        (
            1149,
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        ),
        (
            1029,
            "Microsoft-Windows-TerminalServices-RDPClient/Operational",
        ),
        // Task Scheduler operational
        (106, "Microsoft-Windows-TaskScheduler/Operational"),
        (140, "Microsoft-Windows-TaskScheduler/Operational"),
        (141, "Microsoft-Windows-TaskScheduler/Operational"),
        (200, "Microsoft-Windows-TaskScheduler/Operational"),
        (201, "Microsoft-Windows-TaskScheduler/Operational"),
        // PowerShell
        (4103, "Microsoft-Windows-PowerShell/Operational"),
        (4104, "Microsoft-Windows-PowerShell/Operational"),
        (400, "Windows PowerShell"),
        (600, "Windows PowerShell"),
        // System — services
        (7034, "System"),
        (7036, "System"),
        // Defender
        (1116, "Microsoft-Windows-Windows Defender/Operational"),
        (1117, "Microsoft-Windows-Windows Defender/Operational"),
        // ESENT / NTDS (Application log)
        (216, "Application"),
        (325, "Application"),
        (326, "Application"),
        (327, "Application"),
    ];

    #[test]
    fn iwe_course_event_ids_present() {
        for &(id, channel) in IWE_REQUIRED {
            // Channel-qualified: 21 and 22 are shared with Sysmon, so a numeric
            // lookup would assert against whichever entry the table lists first.
            let e = event_entry_on(channel, id).unwrap_or_else(|| {
                panic!("IWE Event ID {id} missing from EVENT_ID_TABLE on channel {channel:?}")
            });
            assert_eq!(
                e.channel, channel,
                "Event {id} channel mismatch: got {:?}, want {channel:?}",
                e.channel
            );
            assert!(
                !e.description.is_empty(),
                "Event {id} must carry a description"
            );
        }
    }

    #[test]
    fn powershell_scriptblock_4104_is_high_value() {
        let e = event_entry(4104).expect("Event 4104 (script block logging) should exist");
        assert!(e.high_value, "4104 (decoded script content) is high-value");
        assert!(e.mitre_techniques.contains(&"T1059.001"));
    }

    /// `(channel, event_id)` is the real key of this table — the numeric id
    /// alone is not unique across channels (Sysmon and the TerminalServices RDP
    /// channels both define 21 and 22). Two entries sharing a pair would make
    /// [`event_entry_on`] silently return whichever came first, which is a wrong
    /// forensic meaning rather than an error. This is the structural guard that
    /// keeps that impossible.
    #[test]
    fn channel_event_id_pairs_are_unique() {
        let mut seen: std::collections::HashSet<(&str, u32)> = std::collections::HashSet::new();
        for e in EVENT_ID_TABLE {
            assert!(
                seen.insert((e.channel, e.event_id)),
                "duplicate (channel, event_id) key: ({:?}, {})",
                e.channel,
                e.event_id
            );
        }
    }

    /// The channel-qualified lookup must actually filter on the channel, not
    /// fall back to a numeric match — otherwise it is `event_entry` with extra
    /// steps and inherits the first-match-wins defect.
    #[test]
    fn event_entry_on_requires_the_channel_to_match() {
        let e = event_entry_on("Security", 4624).expect("4624 is on Security");
        assert_eq!(e.event_id, 4624);
        assert_eq!(e.channel, "Security");
        assert!(
            event_entry_on("System", 4624).is_none(),
            "4624 is not on the System channel — a numeric fallback would wrongly return it"
        );
    }

    /// Windows channel names are matched case-insensitively: an analyst pasting
    /// a channel out of a tool that lowercased it still gets the entry.
    #[test]
    fn event_entry_on_ignores_channel_case() {
        let e = event_entry_on("microsoft-windows-sysmon/OPERATIONAL", 1)
            .expect("Sysmon 1 resolves regardless of channel case");
        assert_eq!(e.event_id, 1);
        assert_eq!(e.channel, "Microsoft-Windows-Sysmon/Operational");
    }

    /// `events_for_id` is the honest answer when the channel is unknown: every
    /// entry that defines the id, not just the first one in table order.
    #[test]
    fn events_for_id_yields_every_channel_defining_the_id() {
        let all: Vec<_> = events_for_id(4624).collect();
        assert_eq!(all.len(), 1, "4624 is defined on exactly one channel");
        assert_eq!(all[0].channel, "Security");
        assert_eq!(
            events_for_id(99999).count(),
            0,
            "an unknown id yields no entries"
        );
        assert_eq!(
            events_for_id(4688).count(),
            EVENT_ID_TABLE.iter().filter(|e| e.event_id == 4688).count(),
            "events_for_id must agree with a direct scan of the table"
        );
    }

    #[test]
    fn all_artifact_ids_valid() {
        use crate::catalog::CATALOG;
        let ids: std::collections::HashSet<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for entry in EVENT_ID_TABLE {
            for aid in entry.artifact_ids {
                assert!(
                    ids.contains(aid),
                    "Unknown artifact_id {} in event {}",
                    aid,
                    entry.event_id
                );
            }
        }
    }

    /// Sysmon (Microsoft-Windows-Sysmon/Operational) operation codes. The event
    /// IDs and their meanings are the authoritative Sysmon schema (Microsoft
    /// Sysinternals — learn.microsoft.com/sysinternals/downloads/sysmon and the
    /// `sysmon -s` config schema); dfir-scripts.github.io only surfaced the gap.
    /// (id, keyword the description must contain, lowercased)
    const SYSMON_EVENTS: &[(u32, &str)] = &[
        (1, "process creation"),
        (2, "creation time"),
        (3, "network connection"),
        (5, "process terminated"),
        (6, "driver loaded"),
        (7, "image loaded"),
        (8, "createremotethread"),
        (9, "rawaccessread"),
        (10, "process accessed"),
        (11, "file created"),
        (12, "registry object"),
        (13, "registry value"),
        (14, "renamed"),
        (15, "alternate data stream"),
        (16, "configuration"),
        (17, "named pipe created"),
        (18, "named pipe connected"),
        (19, "wmi event filter"),
        (20, "wmi event consumer"),
        (21, "wmieventconsumertofilter"),
        (22, "dns query"),
        (23, "archived"),
        (24, "clipboard"),
        (25, "tampering"),
        (26, "logged"),
        (27, "blocked"),
        (28, "shredding"),
        (29, "executable file detected"),
    ];

    const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

    #[test]
    fn sysmon_events_present_on_operational_channel() {
        for &(id, kw) in SYSMON_EVENTS {
            let e = event_entry_on(SYSMON_CHANNEL, id)
                .unwrap_or_else(|| panic!("Sysmon Event {id} must be present in EVENT_ID_TABLE"));
            assert_eq!(
                e.channel, SYSMON_CHANNEL,
                "Sysmon Event {id} must be on the Sysmon/Operational channel"
            );
            assert!(
                e.description.to_lowercase().contains(kw),
                "Sysmon Event {id} description should contain {kw:?}: got {:?}",
                e.description
            );
            assert!(
                e.artifact_ids.contains(&"evtx_sysmon"),
                "Sysmon Event {id} should associate the evtx_sysmon artifact"
            );
        }
    }

    /// The collision this table's key change exists for, demonstrated on real
    /// entries rather than argued: 21 and 22 are Sysmon `WmiEventConsumerToFilter`
    /// and `DnsQuery` *and* TerminalServices RDP session logon/disconnect. Ask
    /// for a number alone and you get whichever entry the table lists first —
    /// here the RDP one — which is a wrong forensic meaning, not an error. Only
    /// the channel-qualified lookup answers the question the analyst asked.
    #[test]
    fn sysmon_21_22_collide_with_rdp_and_only_the_channel_separates_them() {
        const RDP: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
        for id in [21u32, 22] {
            assert_eq!(
                events_for_id(id).count(),
                2,
                "event {id} is defined on both the Sysmon and the RDP channel"
            );
            let sysmon = event_entry_on(SYSMON_CHANNEL, id)
                .unwrap_or_else(|| panic!("Sysmon {id} must be reachable by channel"));
            let rdp = event_entry_on(RDP, id)
                .unwrap_or_else(|| panic!("RDP {id} must still be reachable by channel"));
            assert_ne!(
                sysmon.description, rdp.description,
                "the two {id} entries carry different forensic meanings"
            );
            assert_eq!(
                event_entry(id).map(|e| e.channel),
                Some(RDP),
                "event_entry({id}) is channel-blind and returns the first table entry — \
                 documented, and exactly why event_entry_on exists"
            );
        }
    }

    /// BITS-Client job lifecycle. Meanings are the message strings and templates
    /// in Microsoft's own provider manifest (`qmgr.dll`, provider
    /// Microsoft-Windows-Bits-Client, GUID {EF1CC15B-46C1-414E-BB95-E76B077BD51E}),
    /// as dumped in nasbench/EVTX-ETW-Resources. Cross-checked against Microsoft
    /// Learn, which publishes 16404 (EVT_SERVICE_FAILED) with the same message
    /// text the dump carries — so the dump reproduces Microsoft's own strings.
    /// (id, keyword the description must contain, lowercased)
    const BITS_EVENTS: &[(u32, &str)] = &[
        (3, "created a new job"),
        (4, "transfer job is complete"),
        (5, "job cancelled"),
        (16403, "remotename"),
        (59, "started"),
        (60, "stopped transferring"),
        (61, "stopped transferring"),
    ];

    const BITS_CHANNEL: &str = "Microsoft-Windows-Bits-Client/Operational";

    #[test]
    fn bits_client_events_present_on_operational_channel() {
        for &(id, kw) in BITS_EVENTS {
            let e = event_entry_on(BITS_CHANNEL, id)
                .unwrap_or_else(|| panic!("BITS Event {id} must be present in EVENT_ID_TABLE"));
            assert_eq!(e.channel, BITS_CHANNEL, "BITS Event {id} channel mismatch");
            assert!(
                e.description.to_lowercase().contains(kw),
                "BITS Event {id} description should contain {kw:?}: got {:?}",
                e.description
            );
            assert!(
                e.artifact_ids.contains(&"evtx_bits_client"),
                "BITS Event {id} should associate the evtx_bits_client artifact"
            );
        }
    }

    /// BITS 3 and 5 sit on the numeric slots Sysmon already owns — the same
    /// collision class as 21/22, and the reason these entries could not land
    /// under the old numeric-only key.
    #[test]
    fn bits_3_and_5_collide_with_sysmon_and_stay_separable() {
        for id in [3u32, 5] {
            assert_eq!(
                events_for_id(id).count(),
                2,
                "event {id} is defined on both the BITS and the Sysmon channel"
            );
            let bits = event_entry_on(BITS_CHANNEL, id)
                .unwrap_or_else(|| panic!("BITS {id} must be reachable by channel"));
            assert!(
                bits.description.to_lowercase().contains("bits")
                    || bits.description.to_lowercase().contains("job"),
                "BITS {id} must read as a BITS job event: got {:?}",
                bits.description
            );
        }
    }

    /// 60 and 61 share one message template verbatim ("BITS stopped transferring
    /// the %2 transfer job that is associated with the %4 URL. The status code is
    /// %6."). What separates them is the manifest's Level — 60 Information, 61
    /// Warning — plus the `hr` status code, so a description that says "60 =
    /// completed, 61 = error" without naming the level is guesswork. Both
    /// descriptions must name their level.
    #[test]
    fn bits_60_and_61_are_separated_by_level_not_by_message() {
        let e60 = event_entry_on(BITS_CHANNEL, 60).expect("BITS 60 exists");
        let e61 = event_entry_on(BITS_CHANNEL, 61).expect("BITS 61 exists");
        assert!(
            e60.description.to_lowercase().contains("information"),
            "BITS 60 must name its Information level: got {:?}",
            e60.description
        );
        assert!(
            e61.description.to_lowercase().contains("warning"),
            "BITS 61 must name its Warning level: got {:?}",
            e61.description
        );
        assert!(
            e60.description.contains("61") && e61.description.contains("60"),
            "each must point at its twin — the message text alone cannot tell them apart"
        );
    }

    /// 16403 carries no `<Message>` element in the provider manifest at all, only
    /// a template. Event Viewer therefore renders "the description for Event ID
    /// 16403 cannot be found" and the evidence lives entirely in the EventData
    /// fields — RemoteName (source URL) and LocalName (local destination path).
    /// The entry must say so instead of inventing a message Microsoft never
    /// shipped.
    #[test]
    fn bits_16403_documents_its_absent_message_string() {
        let e = event_entry_on(BITS_CHANNEL, 16403).expect("BITS 16403 exists");
        let d = e.description.to_lowercase();
        assert!(
            d.contains("remotename") && d.contains("localname"),
            "16403's value is the RemoteName/LocalName pair: got {:?}",
            e.description
        );
        assert!(
            e.caveats.to_lowercase().contains("no message"),
            "16403 must caveat that the manifest defines no message string: got {:?}",
            e.caveats
        );
    }

    /// Additional event channels surfaced by the dfir-scripts.github.io diff and
    /// verified against Microsoft Learn:
    ///   - Microsoft-Windows-Windows Defender/Operational — Defender AV event IDs
    ///     (learn.microsoft.com/defender-endpoint/troubleshoot-microsoft-defender-antivirus):
    ///     1006 MALWARE_DETECTED, 1015 BEHAVIOR_DETECTED, 5001 RTP_DISABLED,
    ///     5007 CONFIG_CHANGED, 5010 ANTISPYWARE_DISABLED, 5012 ANTIVIRUS_DISABLED.
    ///   - System — service-control + shutdown/power events (Microsoft provider docs).
    ///
    /// (id, channel, keyword the description must contain, lowercased)
    const NEW_CHANNEL_EVENTS: &[(u32, &str, &str)] = &[
        (
            1006,
            "Microsoft-Windows-Windows Defender/Operational",
            "malware",
        ),
        (
            1015,
            "Microsoft-Windows-Windows Defender/Operational",
            "suspicious behavior",
        ),
        (
            5001,
            "Microsoft-Windows-Windows Defender/Operational",
            "real-time protection",
        ),
        (
            5007,
            "Microsoft-Windows-Windows Defender/Operational",
            "configuration changed",
        ),
        (
            5010,
            "Microsoft-Windows-Windows Defender/Operational",
            "scanning",
        ),
        (
            5012,
            "Microsoft-Windows-Windows Defender/Operational",
            "viruses",
        ),
        (7031, "System", "terminated unexpectedly"),
        (7040, "System", "start type"),
        (7009, "System", "timeout"),
        (1074, "System", "shutdown"),
        (6005, "System", "event log service was started"),
        (6006, "System", "event log service was stopped"),
        (6008, "System", "unexpected"),
        (6013, "System", "uptime"),
        (41, "System", "without cleanly"),
    ];

    #[test]
    fn new_channel_events_present_with_correct_channel() {
        for &(id, channel, kw) in NEW_CHANNEL_EVENTS {
            let e = event_entry(id)
                .unwrap_or_else(|| panic!("Event {id} must be present in EVENT_ID_TABLE"));
            assert_eq!(e.channel, channel, "Event {id} channel mismatch");
            assert!(
                e.description.to_lowercase().contains(kw),
                "Event {id} description should contain {kw:?}: got {:?}",
                e.description
            );
        }
    }

    /// Extract inline `<id>=<phrase>` claims from a descriptor `meaning`, e.g.
    /// `"(3=job created, 59=transfer started)"` -> `[(3, "job created"), …]`.
    /// Hand-parsed: the facade is zero-dependency, so no regex crate.
    fn inline_event_id_claims(meaning: &str) -> Vec<(u32, String)> {
        let bytes = meaning.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if !bytes[i].is_ascii_digit() {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            // Only a `<digits>=` run is a claim; anything else is prose.
            if i >= bytes.len() || bytes[i] != b'=' {
                continue;
            }
            let Ok(id) = meaning[start..i].parse::<u32>() else {
                continue;
            };
            i += 1; // skip '='
            let phrase_start = i;
            while i < bytes.len() && !matches!(bytes[i], b',' | b')' | b';') {
                i += 1;
            }
            out.push((id, meaning[phrase_start..i].trim().to_lowercase()));
        }
        out
    }

    /// `evtx_bits_client`'s prose must not contradict `EVENT_ID_TABLE`, which is
    /// the authoritative home for event-ID meanings.
    ///
    /// Regression guard for a real defect: the descriptor shipped
    /// "59=job created, 60=completed, 61=error" while Microsoft's BITS manifest
    /// (`qmgr.dll`) defines **3**=job created, **59**=transfer *started*, and
    /// 60/61 as the SAME "transfer stopped" event separated only by Level.
    ///
    /// Deliberately scoped to this descriptor rather than every `evtx_*` one:
    /// comparing prose to prose is not soundly automatable. A catalog-wide sweep
    /// flagged `evtx_defender`'s correct "1117=action taken" against the table's
    /// "took action" — a morphological variant, not a contradiction. A guard that
    /// fails on correct prose only teaches people to add exceptions, so the broad
    /// version was dropped on purpose.
    #[test]
    fn bits_client_prose_agrees_with_event_id_table() {
        use crate::catalog::CATALOG;

        // Words too generic to carry meaning in a comparison.
        const STOPWORDS: &[&str] = &[
            "the", "and", "for", "with", "from", "that", "this", "into", "when", "via", "its",
        ];

        let mut violations: Vec<String> = Vec::new();

        for d in CATALOG.list() {
            if d.id != "evtx_bits_client" {
                continue;
            }
            for (id, phrase) in inline_event_id_claims(d.meaning) {
                // Only ids the authoritative table actually defines can be checked.
                let authoritative: Vec<&str> = EVENT_ID_TABLE
                    .iter()
                    .filter(|e| e.event_id == id)
                    .map(|e| e.description)
                    .collect();
                if authoritative.is_empty() {
                    continue;
                }
                let keywords: Vec<&str> = phrase
                    .split_whitespace()
                    .filter(|w| w.len() >= 4 && !STOPWORDS.contains(w))
                    .collect();
                if keywords.is_empty() {
                    continue;
                }
                // The claim holds if SOME entry for that id supports every keyword.
                let supported = authoritative.iter().any(|desc| {
                    let lower = desc.to_lowercase();
                    keywords.iter().all(|kw| lower.contains(kw))
                });
                if !supported {
                    violations.push(format!(
                        "{}: claims {id}={phrase:?}, but EVENT_ID_TABLE says {:?}",
                        d.id, authoritative
                    ));
                }
            }
        }

        assert!(
            violations.is_empty(),
            "descriptor prose contradicts EVENT_ID_TABLE:\n  {}",
            violations.join("\n  ")
        );
    }
}
