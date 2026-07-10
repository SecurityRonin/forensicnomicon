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
}
