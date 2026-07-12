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
    // evidence of), left empty for pure-visibility events. EIDs 21/22
    // (WmiEventConsumerToFilter, DNS) are omitted — they collide with the RDP
    // TerminalServices 21/22 in this event_id-keyed table (needs a (channel,id) key).
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

/// Look up enrichment for an event ID.
pub fn event_entry(event_id: u32) -> Option<&'static EventIdEntry> {
    EVENT_ID_TABLE.iter().find(|e| e.event_id == event_id)
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
            let e = event_entry(id)
                .unwrap_or_else(|| panic!("IWE Event ID {id} missing from EVENT_ID_TABLE"));
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
    /// Sysmon 21 (WmiEventConsumerToFilter) and 22 (DNS query) are intentionally
    /// omitted here: the table keys on numeric event_id alone and those two
    /// collide with the existing TerminalServices RDP 21/22 entries — holding
    /// both needs a (channel, id) key (tracked as follow-up). (id, keyword the
    /// description must contain, lowercased)
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
        (23, "archived"),
        (24, "clipboard"),
        (25, "tampering"),
        (26, "logged"),
        (27, "blocked"),
        (28, "shredding"),
        (29, "executable file detected"),
    ];

    #[test]
    fn sysmon_events_present_on_operational_channel() {
        for &(id, kw) in SYSMON_EVENTS {
            let e = event_entry(id)
                .unwrap_or_else(|| panic!("Sysmon Event {id} must be present in EVENT_ID_TABLE"));
            assert_eq!(
                e.channel, "Microsoft-Windows-Sysmon/Operational",
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

    /// Additional event channels surfaced by the dfir-scripts.github.io diff and
    /// verified against Microsoft Learn:
    ///   - Microsoft-Windows-Windows Defender/Operational — Defender AV event IDs
    ///     (learn.microsoft.com/defender-endpoint/troubleshoot-microsoft-defender-antivirus):
    ///     1006 MALWARE_DETECTED, 1015 BEHAVIOR_DETECTED, 5001 RTP_DISABLED,
    ///     5007 CONFIG_CHANGED, 5010 ANTISPYWARE_DISABLED, 5012 ANTIVIRUS_DISABLED.
    ///   - System — service-control + shutdown/power events (Microsoft provider docs).
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
}
