//! Native event-signature → MITRE ATT&CK technique knowledge.
//!
//! Pure facts: "Windows event ID *X* (optionally with logon type *Y*) is
//! consistent with ATT&CK technique *Z* under tactic *W*." No detection logic,
//! no severity judgment, no thresholds, no I/O — those are analyzer decisions
//! and live in the tool that *reads* this table.
//!
//! This is the **behavioral-signature** refinement layer, complementary to the
//! broad [`crate::eventids`] enrichment table: it is logon-type aware (so a
//! type-10 RDP logon resolves to the specific lateral-movement technique
//! `T1021.001` rather than the generic `T1078`) and it carries the ATT&CK
//! `tactic`, which `eventids` does not. Findings derived from it are
//! observations *consistent with* the named technique — never a verdict.

/// A native event signature mapped to the ATT&CK technique it is consistent
/// with. `logon_type == None` matches any logon type (or events that have none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct NativeEventTechnique {
    /// Windows event ID, e.g. `4624`, `7045`.
    pub event_id: u32,
    /// Required logon type (e.g. `10` = RemoteInteractive/RDP), or `None` for any.
    pub logon_type: Option<u32>,
    /// ATT&CK technique ID, e.g. `"T1021.001"`.
    pub technique: &'static str,
    /// ATT&CK tactic in lowercase snake form, e.g. `"initial_access"`.
    pub tactic: &'static str,
    /// Short forensic description of the signature.
    pub description: &'static str,
}

/// Per-event behavioral signatures. The first entry whose `event_id` matches
/// and whose `logon_type` constraint is satisfied wins (see [`technique_for`]).
pub static NATIVE_EVENT_TECHNIQUES: &[NativeEventTechnique] = &[];

/// The technique a *burst* of failed logons (4625) is consistent with. The
/// burst threshold is a tuning decision the analyzer owns, not a fact, so it is
/// deliberately absent here.
pub const FAILED_LOGON_BURST: NativeEventTechnique = NativeEventTechnique {
    event_id: 4625,
    logon_type: None,
    technique: "PLACEHOLDER",
    tactic: "placeholder",
    description: "RED stub",
};

/// Look up the behavioral technique consistent with a single event signature.
///
/// Returns the first matching entry: `event_id` must match and, if the entry
/// constrains `logon_type`, the supplied `logon_type` must equal it.
#[must_use]
pub fn technique_for(
    _event_id: u32,
    _logon_type: Option<u32>,
) -> Option<&'static NativeEventTechnique> {
    // RED stub — implementation lands in the GREEN commit.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdp_type_10_resolves_to_t1021_001() {
        let t = technique_for(4624, Some(10)).expect("4624 type-10 must resolve");
        assert_eq!(t.technique, "T1021.001");
        assert_eq!(t.tactic, "initial_access");
    }

    #[test]
    fn console_type_2_logon_is_not_rdp() {
        assert!(technique_for(4624, Some(2)).is_none());
    }

    #[test]
    fn service_install_resolves_to_t1543_003() {
        let t = technique_for(7045, None).expect("7045 must resolve");
        assert_eq!(t.technique, "T1543.003");
        assert_eq!(t.tactic, "persistence");
    }

    #[test]
    fn privileged_logon_resolves_to_t1078() {
        let t = technique_for(4672, None).expect("4672 must resolve");
        assert_eq!(t.technique, "T1078");
        assert_eq!(t.tactic, "privilege_escalation");
    }

    #[test]
    fn unknown_event_resolves_to_none() {
        assert!(technique_for(4634, None).is_none());
    }

    #[test]
    fn failed_logon_burst_is_t1110_initial_access() {
        assert_eq!(FAILED_LOGON_BURST.event_id, 4625);
        assert_eq!(FAILED_LOGON_BURST.technique, "T1110");
        assert_eq!(FAILED_LOGON_BURST.tactic, "initial_access");
    }
}
