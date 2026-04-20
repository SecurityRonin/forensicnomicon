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
