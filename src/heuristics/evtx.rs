//! EVTX event log "hiding" anomaly heuristics.
//!
//! Detection predicates for the technique described in Harlan Carvey's
//! [*Hiding In The Windows Event Log*](https://windowsir.blogspot.com/2023/07/hiding-in-windows-event-log.html)
//! (windowsir, 2023-07-08), which builds on Kaspersky's
//! [*A new secret stash for fileless malware*](https://securelist.com/a-new-secret-stash-for-fileless-malware/106393/)
//! (May 2022) and Tim Fowler's
//! [*Windows Event Logs for Red Teams*](https://www.blackhillsinfosec.com/windows-event-logs-for-red-teams/)
//! (BlackHillsInfoSec).
//!
//! Threat actors abuse the Windows Event Log as a covert persistent storage
//! channel because:
//!
//! 1. Of the ~400 `.evtx` files under `%SystemRoot%\System32\winevt\Logs`,
//!    most analysts only collect the "Big Three" (Security, System, Application).
//! 2. Low-volume or unpopulated channels (the post highlights *Key Management
//!    Service*) make great repositories — anomalous record growth stands out
//!    against an otherwise empty file.
//! 3. Custom event sources can write any event ID; Carvey reports observing
//!    multiple threat-actor tools that emit *every* record as event ID 0.
//! 4. Identifying records solely by event ID is insufficient — `(provider,
//!    event_id)` is the unique key, and an unfamiliar `(provider, id)` pair
//!    appearing rarely is a pivot point an Events Ripper plugin could surface.
//!
//! All predicates here are pure functions over primitives — no I/O, no parsing,
//! no `chrono`. EVTX file/record decoding lives in higher layers; this module
//! only encodes the *anomaly thresholds*.

// ── Event ID anomalies ────────────────────────────────────────────────────────

/// Event IDs at or below this value are reserved/sentinel and rarely emitted by
/// legitimate Windows providers as "normal" telemetry.
///
/// Per the post, multiple threat-actor tools emit *every* record as event
/// ID 0 — a strong indicator of a custom event source registered for covert
/// logging rather than legitimate Windows component telemetry.
pub const RESERVED_EVENT_ID_MAX: u32 = 0;

/// Returns `true` if the event ID is the sentinel value 0, which threat-actor
/// tools have been observed to use as a catch-all ID for every record they
/// write.
///
/// # Detection
/// Per [Carvey 2023](https://windowsir.blogspot.com/2023/07/hiding-in-windows-event-log.html):
/// "two of which use event ID 0 (zero) for *everything*, literally every
/// record written, regardless of the message, is event ID 0."
#[must_use]
pub fn is_reserved_event_id(event_id: u32) -> bool {
    event_id <= RESERVED_EVENT_ID_MAX
}

// ── Channel volume anomalies ──────────────────────────────────────────────────

/// Maximum record count for an EVTX channel to be considered "low volume" —
/// a candidate covert-storage host per the post.
///
/// The post identifies "Key Management Service" as an attractive repository
/// because it is "enabled on the systems I have access to, [but] it's not
/// populated on any of them." Channels normally carrying zero or a handful of
/// records make even a single planted record stand out.
pub const LOW_VOLUME_CHANNEL_MAX_RECORDS: u64 = 10;

/// Returns `true` if a channel's record count is low enough that it would
/// serve as a "decent persistent repository" per the post — i.e. one whose
/// baseline volume is so low that any new record is suspicious.
#[must_use]
pub fn is_low_volume_channel(record_count: u64) -> bool {
    record_count <= LOW_VOLUME_CHANNEL_MAX_RECORDS
}

// ── (Provider, EventID) pair frequency ────────────────────────────────────────

/// Maximum occurrence count for a `(provider, event_id)` pair to be considered
/// "rare" within a collection — a pivot worth investigating per the post's
/// suggested Events Ripper plugin.
///
/// Carvey: "An Events Ripper plugin that listed all source/ID pairs and their
/// frequency *might* provide a pivot point for the analyst."
pub const RARE_SOURCE_ID_PAIR_MAX: u64 = 3;

/// Returns `true` if a `(provider, event_id)` pair occurs rarely enough that
/// it is a worthwhile pivot for the analyst.
///
/// The post stresses event IDs are not unique — `(provider, id)` is the real
/// key. A pair seen only once or twice across an entire image is a candidate
/// for hand-crafted custom logging.
#[must_use]
pub fn is_rare_source_id_pair(occurrence_count: u64) -> bool {
    occurrence_count > 0 && occurrence_count <= RARE_SOURCE_ID_PAIR_MAX
}

// ── "Big Three" channel coverage ─────────────────────────────────────────────

/// The three EVTX channels that the post calls out as the historical-and-still-
/// over-collected default ("The Big Three"). Anything *outside* this set is
/// where covert persistence is more likely to land unnoticed.
pub const BIG_THREE_CHANNELS: &[&str] = &["Security", "System", "Application"];

/// Returns `true` if `channel_name` is one of the historical "Big Three"
/// (`Security`, `System`, `Application`).
///
/// Matching is case-insensitive against ASCII; locale-specific channel names
/// are not normalized here — feed the canonical English name from the EVTX
/// header.
#[must_use]
pub fn is_big_three_channel(channel_name: &str) -> bool {
    BIG_THREE_CHANNELS
        .iter()
        .any(|c| c.eq_ignore_ascii_case(channel_name))
}

/// Returns `true` if the channel falls *outside* the Big Three — i.e. the kind
/// of channel the post identifies as a likely covert-storage candidate because
/// "responders and analysts aren't likely to look there."
#[must_use]
pub fn is_overlooked_channel(channel_name: &str) -> bool {
    !is_big_three_channel(channel_name)
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ────────────────────────────────────────────────────────────

    #[test]
    fn reserved_event_id_max_is_zero() {
        assert_eq!(RESERVED_EVENT_ID_MAX, 0);
    }

    #[test]
    fn low_volume_channel_max_records_is_ten() {
        assert_eq!(LOW_VOLUME_CHANNEL_MAX_RECORDS, 10);
    }

    #[test]
    fn rare_source_id_pair_max_is_three() {
        assert_eq!(RARE_SOURCE_ID_PAIR_MAX, 3);
    }

    #[test]
    fn big_three_contains_security_system_application() {
        assert!(BIG_THREE_CHANNELS.contains(&"Security"));
        assert!(BIG_THREE_CHANNELS.contains(&"System"));
        assert!(BIG_THREE_CHANNELS.contains(&"Application"));
        assert_eq!(BIG_THREE_CHANNELS.len(), 3);
    }

    // ── is_reserved_event_id ─────────────────────────────────────────────────

    #[test]
    fn event_id_zero_is_reserved() {
        // Per Carvey 2023: threat-actor tools emit every record as ID 0.
        assert!(is_reserved_event_id(0));
    }

    #[test]
    fn event_id_one_is_not_reserved() {
        assert!(!is_reserved_event_id(1));
    }

    #[test]
    fn event_id_4624_logon_is_not_reserved() {
        // The classic "successful login" event — must not flag.
        assert!(!is_reserved_event_id(4624));
    }

    #[test]
    fn event_id_max_is_not_reserved() {
        assert!(!is_reserved_event_id(u32::MAX));
    }

    // ── is_low_volume_channel ────────────────────────────────────────────────

    #[test]
    fn empty_channel_is_low_volume() {
        // The post's KMS example: "not populated on any of them".
        assert!(is_low_volume_channel(0));
    }

    #[test]
    fn channel_with_ten_records_is_low_volume() {
        assert!(is_low_volume_channel(10));
    }

    #[test]
    fn channel_with_eleven_records_is_not_low_volume() {
        assert!(!is_low_volume_channel(11));
    }

    #[test]
    fn busy_channel_is_not_low_volume() {
        // Security.evtx with thousands of records — must not flag.
        assert!(!is_low_volume_channel(50_000));
    }

    // ── is_rare_source_id_pair ───────────────────────────────────────────────

    #[test]
    fn zero_occurrence_pair_is_not_rare() {
        // A pair seen zero times doesn't exist in the collection.
        assert!(!is_rare_source_id_pair(0));
    }

    #[test]
    fn single_occurrence_pair_is_rare() {
        assert!(is_rare_source_id_pair(1));
    }

    #[test]
    fn three_occurrence_pair_is_rare() {
        assert!(is_rare_source_id_pair(3));
    }

    #[test]
    fn four_occurrence_pair_is_not_rare() {
        assert!(!is_rare_source_id_pair(4));
    }

    #[test]
    fn very_common_pair_is_not_rare() {
        assert!(!is_rare_source_id_pair(10_000));
    }

    // ── is_big_three_channel / is_overlooked_channel ─────────────────────────

    #[test]
    fn security_is_big_three() {
        assert!(is_big_three_channel("Security"));
    }

    #[test]
    fn system_is_big_three() {
        assert!(is_big_three_channel("System"));
    }

    #[test]
    fn application_is_big_three() {
        assert!(is_big_three_channel("Application"));
    }

    #[test]
    fn big_three_match_is_case_insensitive() {
        assert!(is_big_three_channel("security"));
        assert!(is_big_three_channel("SYSTEM"));
        assert!(is_big_three_channel("ApPlIcAtIoN"));
    }

    #[test]
    fn key_management_service_is_overlooked() {
        // The post's headline example.
        assert!(is_overlooked_channel("Key Management Service"));
    }

    #[test]
    fn microsoft_windows_powershell_operational_is_overlooked() {
        assert!(is_overlooked_channel(
            "Microsoft-Windows-PowerShell/Operational"
        ));
    }

    #[test]
    fn security_is_not_overlooked() {
        assert!(!is_overlooked_channel("Security"));
    }

    #[test]
    fn empty_channel_name_is_overlooked() {
        // Defensive: empty string is not in the Big Three.
        assert!(is_overlooked_channel(""));
    }
}
