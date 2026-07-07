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
}

/// Static table of well-known Windows Event IDs with forensic enrichment.
pub static EVENT_ID_TABLE: &[EventIdEntry] = &[
    EventIdEntry {
        event_id: 104,
        channel: "System",
        description: "System log cleared",
        mitre_techniques: &["T1070.001"],
        artifact_ids: &["evtx_system"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 1102,
        channel: "Security",
        description: "Audit log cleared",
        mitre_techniques: &["T1070.001"],
        artifact_ids: &["evtx_security"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 4624,
        channel: "Security",
        description: "Successful logon",
        mitre_techniques: &["T1078"],
        artifact_ids: &["evtx_security"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 4625,
        channel: "Security",
        description: "Failed logon — brute force indicator",
        mitre_techniques: &["T1110"],
        artifact_ids: &["evtx_security"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 4648,
        channel: "Security",
        description: "Logon with explicit credentials",
        mitre_techniques: &["T1550.002"],
        artifact_ids: &["evtx_security"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 4663,
        channel: "Security",
        description: "Object access attempt",
        mitre_techniques: &["T1005"],
        artifact_ids: &["evtx_security"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 4688,
        channel: "Security",
        description: "Process creation",
        mitre_techniques: &["T1059"],
        artifact_ids: &["evtx_security"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 4698,
        channel: "Security",
        description: "Scheduled task created",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_security", "scheduled_tasks_dir"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 4702,
        channel: "Security",
        description: "Scheduled task updated",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_security"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 4720,
        channel: "Security",
        description: "User account created",
        mitre_techniques: &["T1136.001"],
        artifact_ids: &["evtx_security", "sam_users"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 4732,
        channel: "Security",
        description: "Member added to security-enabled local group",
        mitre_techniques: &["T1098"],
        artifact_ids: &["evtx_security"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 4768,
        channel: "Security",
        description: "Kerberos TGT requested",
        mitre_techniques: &["T1558.003"],
        artifact_ids: &["evtx_security"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 4769,
        channel: "Security",
        description: "Kerberos service ticket requested",
        mitre_techniques: &["T1558.003"],
        artifact_ids: &["evtx_security"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 4771,
        channel: "Security",
        description: "Kerberos pre-authentication failed",
        mitre_techniques: &["T1110"],
        artifact_ids: &["evtx_security"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 4776,
        channel: "Security",
        description: "NTLM authentication",
        mitre_techniques: &["T1550.002"],
        artifact_ids: &["evtx_security"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 7045,
        channel: "System",
        description: "Service installed",
        mitre_techniques: &["T1543.003"],
        artifact_ids: &["evtx_system"],
        high_value: true,
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
    },
    EventIdEntry {
        event_id: 4647,
        channel: "Security",
        description: "User-initiated logoff",
        mitre_techniques: &[],
        artifact_ids: &["evtx_security"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 4672,
        channel: "Security",
        description: "Special privileges assigned to new logon (admin-equivalent)",
        mitre_techniques: &["T1078"],
        artifact_ids: &["evtx_security"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 4722,
        channel: "Security",
        description: "User account enabled",
        mitre_techniques: &["T1098"],
        artifact_ids: &["evtx_security"],
        high_value: true,
    },
    // RDP / TerminalServices
    EventIdEntry {
        event_id: 21,
        channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        description: "RDP session logon succeeded",
        mitre_techniques: &["T1021.001"],
        artifact_ids: &["evtx_rdp_session", "evtx_terminal_services"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 22,
        channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        description: "RDP shell (session) start",
        mitre_techniques: &["T1021.001"],
        artifact_ids: &["evtx_rdp_session", "evtx_terminal_services"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 1149,
        channel: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        description: "RDP network connection established (label 'auth succeeded' is misleading — \
                      precedes credential validation; corroborate with 21/22 or 4624 Type 10)",
        mitre_techniques: &["T1021.001"],
        artifact_ids: &["evtx_rdp_inbound", "evtx_terminal_services"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 1029,
        channel: "Microsoft-Windows-TerminalServices-RDPClient/Operational",
        description: "RDP client: Base64(SHA-256(UTF-16LE(username))) of the connecting username, logged on the SOURCE host (Win10+); correlation aid, reversible via a username wordlist",
        mitre_techniques: &["T1021.001"],
        artifact_ids: &["evtx_rdp_client", "evtx_terminal_services"],
        high_value: false,
    },
    // Task Scheduler operational
    EventIdEntry {
        event_id: 106,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task registered (created)",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler", "scheduled_tasks_dir"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 140,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task updated",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 141,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task deleted",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 200,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task action started",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 201,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task action completed",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler"],
        high_value: false,
    },
    // PowerShell
    EventIdEntry {
        event_id: 4103,
        channel: "Microsoft-Windows-PowerShell/Operational",
        description: "PowerShell module logging",
        mitre_techniques: &["T1059.001"],
        artifact_ids: &["evtx_powershell"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 4104,
        channel: "Microsoft-Windows-PowerShell/Operational",
        description: "PowerShell script block logging — captures full (decoded) script content",
        mitre_techniques: &["T1059.001"],
        artifact_ids: &["evtx_powershell"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 400,
        channel: "Windows PowerShell",
        description: "PowerShell engine/session start (classic log)",
        mitre_techniques: &["T1059.001"],
        artifact_ids: &["evtx_powershell_classic"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 600,
        channel: "Windows PowerShell",
        description: "PowerShell provider start/stop (classic log)",
        mitre_techniques: &["T1059.001"],
        artifact_ids: &["evtx_powershell_classic"],
        high_value: false,
    },
    // System — services
    EventIdEntry {
        event_id: 7034,
        channel: "System",
        description: "Service crashed unexpectedly",
        mitre_techniques: &["T1543.003"],
        artifact_ids: &["evtx_system"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 7036,
        channel: "System",
        description: "Service started/stopped",
        mitre_techniques: &["T1543.003"],
        artifact_ids: &["evtx_system"],
        high_value: false,
    },
    // Defender
    EventIdEntry {
        event_id: 1116,
        channel: "Microsoft-Windows-Windows Defender/Operational",
        description: "Microsoft Defender detected malware",
        mitre_techniques: &["T1059"],
        artifact_ids: &["evtx_defender"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 1117,
        channel: "Microsoft-Windows-Windows Defender/Operational",
        description: "Microsoft Defender took action (remediation)",
        mitre_techniques: &[],
        artifact_ids: &["evtx_defender"],
        high_value: false,
    },
    // ESENT / NTDS.dit (Application log) — unusual NTDS location ⇒ credential theft
    EventIdEntry {
        event_id: 216,
        channel: "Application",
        description: "ESENT: database location change detected (NTDS.dit move ⇒ red flag)",
        mitre_techniques: &["T1003.003"],
        artifact_ids: &["evtx_application"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 325,
        channel: "Application",
        description: "ESENT: database engine created a new database (NTDS.dit in unexpected \
                      location ⇒ red flag)",
        mitre_techniques: &["T1003.003"],
        artifact_ids: &["evtx_application"],
        high_value: true,
    },
    EventIdEntry {
        event_id: 326,
        channel: "Application",
        description: "ESENT: database attached",
        mitre_techniques: &["T1003.003"],
        artifact_ids: &["evtx_application"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 327,
        channel: "Application",
        description: "ESENT: database detached",
        mitre_techniques: &["T1003.003"],
        artifact_ids: &["evtx_application"],
        high_value: false,
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
