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

// ── Super-timeline channels ───────────────────────────────────────────────────

/// The five Windows EVTX channels merged into a unified forensic super-timeline.
///
/// Combining Security, System, Sysmon, PowerShell, and TaskScheduler gives
/// comprehensive coverage of authentication, process execution, file activity,
/// network connections, and scheduled task abuse in a single chronological stream.
pub const SUPER_TIMELINE_CHANNELS: &[&str] = &[
    "Security",
    "System",
    SYSMON_CHANNEL,
    POWERSHELL_OPERATIONAL_CHANNEL,
    TASKSCHEDULER_OPERATIONAL_CHANNEL,
];

/// Canonical channel name for Microsoft Sysmon.
pub const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

/// Canonical channel name for PowerShell operational logging.
pub const POWERSHELL_OPERATIONAL_CHANNEL: &str = "Microsoft-Windows-PowerShell/Operational";

/// Canonical channel name for the Task Scheduler operational log.
pub const TASKSCHEDULER_OPERATIONAL_CHANNEL: &str = "Microsoft-Windows-TaskScheduler/Operational";

// ── Sysmon Event IDs ──────────────────────────────────────────────────────────

/// Sysmon EID 1: Process Create — captures ProcessGuid chains for tree reconstruction.
pub const EID_SYSMON_PROCESS_CREATE: u32 = 1;
/// Sysmon EID 3: Network Connection.
pub const EID_SYSMON_NETWORK_CONNECT: u32 = 3;
/// Sysmon EID 7: Image Loaded.
pub const EID_SYSMON_IMAGE_LOAD: u32 = 7;
/// Sysmon EID 11: File Created — primary source for MFT/USN correlation.
pub const EID_SYSMON_FILE_CREATE: u32 = 11;
/// Sysmon EID 15: FileCreateStreamHash — alternate-data-stream detection.
pub const EID_SYSMON_FILE_CREATE_STREAM_HASH: u32 = 15;
/// Sysmon EID 22: DNS Query.
pub const EID_SYSMON_DNS_QUERY: u32 = 22;

// ── Boot / shutdown Event IDs (System channel) ────────────────────────────────

/// System EID 6005: EventLog service started — marks a clean boot boundary.
pub const EID_BOOT: u32 = 6005;
/// System EID 6006: EventLog service stopped — marks a clean shutdown boundary.
pub const EID_SHUTDOWN: u32 = 6006;
/// System EID 6008: Unexpected shutdown — dirty-shutdown / crash boundary.
pub const EID_UNEXPECTED_SHUTDOWN: u32 = 6008;

// ── Sysmon field name constants ───────────────────────────────────────────────

/// `data` key for the Sysmon process GUID (all Sysmon process events).
pub const SYSMON_FIELD_PROCESS_GUID: &str = "ProcessGuid";
/// `data` key for the Sysmon parent process GUID (EID 1).
pub const SYSMON_FIELD_PARENT_PROCESS_GUID: &str = "ParentProcessGuid";
/// `data` key for the file path in Sysmon file events (EID 11, 15).
pub const SYSMON_FIELD_TARGET_FILENAME: &str = "TargetFilename";
/// `data` key for the process image path (EID 1, 3, 7, 11, 15).
pub const SYSMON_FIELD_IMAGE: &str = "Image";
/// `data` key for the parent image path (EID 1).
pub const SYSMON_FIELD_PARENT_IMAGE: &str = "ParentImage";
/// `data` key for the command line (EID 1).
pub const SYSMON_FIELD_COMMAND_LINE: &str = "CommandLine";
/// `data` key for the parent command line (EID 1).
pub const SYSMON_FIELD_PARENT_COMMAND_LINE: &str = "ParentCommandLine";

// ── Security channel EID constants (commonly referenced in orchestration) ─────

/// Security EID 4624: Successful logon.
pub const EID_LOGON: u32 = 4624;
/// Security EID 4625: Failed logon.
pub const EID_LOGON_FAILURE: u32 = 4625;
/// Security EID 4634: Logoff.
pub const EID_LOGOFF: u32 = 4634;
/// Security EID 4647: User-initiated logoff.
pub const EID_LOGOFF_USER: u32 = 4647;
/// Security EID 4672: Special privileges assigned to new logon.
pub const EID_SPECIAL_LOGON: u32 = 4672;
/// Security EID 4688: Process creation.
pub const EID_PROCESS_CREATE: u32 = 4688;
/// Security EID 4689: Process exit.
pub const EID_PROCESS_EXIT: u32 = 4689;
/// Security EID 4697: Service installed (Security channel).
pub const EID_SERVICE_INSTALLED_SECURITY: u32 = 4697;
/// Security EID 4662: Directory service object access (DCSync uses this).
pub const EID_DIRECTORY_SERVICE_ACCESS: u32 = 4662;
/// Security EID 4768: Kerberos TGT request (AS-REP Roasting target).
pub const EID_KERBEROS_TGT_REQUEST: u32 = 4768;
/// Security EID 4769: Kerberos TGS request (Kerberoasting target).
pub const EID_KERBEROS_TGS_REQUEST: u32 = 4769;
/// Security EID 1102: Security audit log cleared.
pub const EID_LOG_CLEARED: u32 = 1102;
/// Security EID 5140: Network share object accessed.
pub const EID_SMB_SHARE_ACCESS: u32 = 5140;
/// Security EID 5145: Network share object check (file-level SMB access).
pub const EID_SMB_OBJECT_ACCESS: u32 = 5145;

// ── System / Service EID constants ───────────────────────────────────────────

/// System EID 7045: New service installed (System channel).
pub const EID_SERVICE_INSTALLED: u32 = 7045;
/// System / Application EID 104: Application log cleared.
pub const EID_LOG_CLEARED_SYSTEM: u32 = 104;
/// System EID 105: Channel log cleared or disabled.
pub const EID_CHANNEL_LOG_CLEARED: u32 = 105;

// ── Task Scheduler EID constants (Microsoft-Windows-TaskScheduler/Operational)

/// TaskScheduler EID 106: Task registered (created or updated).
pub const EID_TASK_REGISTERED: u32 = 106;
/// TaskScheduler EID 140: Task updated.
pub const EID_TASK_UPDATED: u32 = 140;
/// TaskScheduler EID 141: Task deleted.
pub const EID_TASK_DELETED: u32 = 141;
/// TaskScheduler EID 200: Task action started.
pub const EID_TASK_LAUNCHED: u32 = 200;
/// TaskScheduler EID 201: Task action completed.
pub const EID_TASK_COMPLETED: u32 = 201;

// ── WMI-Activity EID constants (Microsoft-Windows-WMI-Activity/Operational) ──

/// WMI-Activity EID 5860: WMI filter subscribed.
pub const EID_WMI_FILTER_SUBSCRIBED: u32 = 5860;
/// WMI-Activity EID 5861: WMI filter triggered (subscription fired).
pub const EID_WMI_FILTER_TRIGGERED: u32 = 5861;

// ── BITS-Client EID constants (Microsoft-Windows-Bits-Client/Operational) ────

/// BITS-Client EID 59: Job transfer initiated.
pub const EID_BITS_TRANSFER_START: u32 = 59;
/// BITS-Client EID 60: Job transfer completed.
pub const EID_BITS_TRANSFER_COMPLETE: u32 = 60;

// ── PowerShell EID constants (Microsoft-Windows-PowerShell/Operational) ──────

/// PowerShell EID 4104: Script block logging — full script text captured.
pub const EID_PS_SCRIPT_BLOCK: u32 = 4104;

// ── Microsoft Defender EID constants ─────────────────────────────────────────

/// Microsoft Defender EID 1116: Malware detected.
pub const EID_DEFENDER_MALWARE_DETECTED: u32 = 1116;
/// Microsoft Defender EID 5001: Real-time protection disabled.
pub const EID_DEFENDER_REALTIME_DISABLED: u32 = 5001;
/// Microsoft Defender EID 5007: Antimalware configuration changed.
pub const EID_DEFENDER_CONFIG_CHANGED: u32 = 5007;

// ── W32Time EID constants (System channel) ───────────────────────────────────

/// W32Time EID 37: NtpClient could not find a domain controller.
pub const EID_W32TIME_NTP_FAILED: u32 = 37;
/// W32Time EID 158: System clock synchronized.
pub const EID_W32TIME_SYNC: u32 = 158;

// ── Additional Sysmon EID constants ─────────────────────────────────────────

/// Sysmon EID 10: ProcessAccess — one process opened a handle to another.
pub const EID_SYSMON_PROCESS_ACCESS: u32 = 10;
/// Sysmon EID 16: Sysmon configuration changed.
pub const EID_SYSMON_CONFIG_CHANGE: u32 = 16;
/// Sysmon EID 255: Sysmon error / driver unload.
pub const EID_SYSMON_DRIVER_UNLOAD: u32 = 255;

// ── Additional Sysmon field name constants ───────────────────────────────────

/// `data` key for DNS query name in Sysmon EID 22.
pub const SYSMON_FIELD_QUERY_NAME: &str = "QueryName";
/// `data` key for the access mask in Sysmon EID 10 (ProcessAccess).
pub const SYSMON_FIELD_GRANTED_ACCESS: &str = "GrantedAccess";
/// `data` key for the target process image in Sysmon EID 10.
pub const SYSMON_FIELD_TARGET_IMAGE: &str = "TargetImage";
/// `data` key for the source IP in Sysmon EID 3 (NetworkConnect).
pub const SYSMON_FIELD_SOURCE_IP: &str = "SourceIp";
/// `data` key for the destination IP in Sysmon EID 3.
pub const SYSMON_FIELD_DEST_IP: &str = "DestinationIp";
/// `data` key for the destination port in Sysmon EID 3.
pub const SYSMON_FIELD_DEST_PORT: &str = "DestinationPort";

// ── DCSync replication GUIDs ─────────────────────────────────────────────────
// These appear in the Properties field of Security EID 4662 during DCSync.
// Source: MS-ADTS §3.1.1.3.3 — Active Directory replication access rights.

/// Active Directory DS-Replication-Get-Changes right (required for DCSync).
pub const GUID_DS_REPLICATION_GET_CHANGES: &str = "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}";
/// Active Directory DS-Replication-Get-Changes-All (full DCSync, incl. secrets).
pub const GUID_DS_REPLICATION_GET_CHANGES_ALL: &str = "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}";
/// DS-Replication-Get-Changes-In-Filtered-Set (partial DC sync).
pub const GUID_DS_REPLICATION_FILTERED: &str = "{89e95b76-444d-4c62-991a-0facbeda640c}";

// ── AMSI bypass indicator strings ────────────────────────────────────────────
// These appear in PowerShell 4104 ScriptBlockText when AMSI is patched
// in-memory. Each string is a known-bad substring, case-insensitive.

/// Known AMSI bypass indicator strings found in PowerShell 4104 script blocks.
pub const AMSI_BYPASS_PATTERNS: &[&str] = &[
    "amsiInitFailed",
    "amsiContext",
    "amsiSession",
    "AmsiUtils",
    "PatchAmsi",
    "amsi.dll",
    "AmsiScanBuffer",
    "AmsiScanString",
    "[Runtime.InteropServices.Marshal]::Copy",
];

// ── Archiver process names (Compression/Staging detection) ───────────────────

/// Archiver process basenames that indicate compression/staging activity.
pub const ARCHIVER_PROCESS_NAMES: &[&str] = &[
    "7z.exe",
    "7za.exe",
    "winrar.exe",
    "rar.exe",
    "pkzip.exe",
    "winzip.exe",
    "compress.exe",
    "compact.exe",
    "xcopy.exe",
];

/// Compressed archive extensions indicative of staging in temp directories.
pub const STAGING_ARCHIVE_EXTENSIONS: &[&str] =
    &[".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".cab"];

// ── LSASS process name ────────────────────────────────────────────────────────

/// LSASS process image name — target of credential dumping (EID 10).
pub const LSASS_IMAGE_NAME: &str = "lsass.exe";

/// Known GrantedAccess masks used for LSASS credential dumping.
pub const LSASS_DUMP_ACCESS_MASKS: &[u32] = &[
    0x0010,   // PROCESS_VM_READ
    0x1010,   // PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
    0x1410,   // PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | ...
    0x1fffff, // PROCESS_ALL_ACCESS
];

// ── PsExec / service-execution indicators ────────────────────────────────────

/// Service name patterns written by PsExec and compatible tools.
pub const PSEXEC_SERVICE_PATTERNS: &[&str] = &[
    "PSEXESVC",
    "psexesvc",
    "PAExec",
    "paexec",
    "remcom",
    "RemComSvc",
];

// ── Defender tampering PowerShell patterns ────────────────────────────────────

/// PowerShell patterns that appear when Defender is being tampered with.
pub const DEFENDER_TAMPER_PATTERNS: &[&str] = &[
    "Set-MpPreference",
    "Add-MpPreference",
    "DisableRealtimeMonitoring",
    "ExclusionPath",
    "ExclusionProcess",
    "ExclusionExtension",
    "DisableAntiSpyware",
    "DisableAntiVirus",
];

// ── Channel constants ─────────────────────────────────────────────────────────

/// WMI-Activity operational channel.
pub const WMI_ACTIVITY_CHANNEL: &str = "Microsoft-Windows-WMI-Activity/Operational";
/// TaskScheduler operational channel.
pub const TASKSCHEDULER_CHANNEL: &str = "Microsoft-Windows-TaskScheduler/Operational";
/// BITS-Client operational channel.
pub const BITS_CLIENT_CHANNEL: &str = "Microsoft-Windows-Bits-Client/Operational";
/// Windows Defender operational channel.
pub const DEFENDER_CHANNEL: &str = "Microsoft-Windows-Windows Defender/Operational";
/// Hyper-V Virtual Machine Management Service (VMMS) Admin channel.
pub const HYPERV_VMMS_CHANNEL: &str = "Microsoft-Windows-Hyper-V-VMMS/Admin";

// ── VSS EID constants (Application channel, source "VSS") ────────────────────

/// Application EID 8193: VSS service error — often fired when shadow copies are
/// deleted via vssadmin or wmic (T1490 inhibit system recovery).
pub const EID_VSS_ERROR: u32 = 8193;
/// Application EID 524: VSS snapshot deleted event.
pub const EID_VSS_SNAPSHOT_DELETED: u32 = 524;

// ── Hyper-V VMMS EID constants ───────────────────────────────────────────────

/// Hyper-V-VMMS EID 13002: Virtual machine state change initiated (e.g. stopping).
/// QWCrypt/RedCurl shuts down all VMs before encrypting VHD/VHDX files on-disk.
pub const EID_HYPERV_VM_STATE_CHANGE: u32 = 13002;
/// Hyper-V-VMMS EID 13003: Virtual machine has stopped.
pub const EID_HYPERV_VM_STOPPED: u32 = 13003;

// ── WMI-Activity EID constants (query / error pivots) ────────────────────────

/// WMI-Activity EID 5857: WMI provider loaded — lateral-movement pivot when
/// ClientMachine indicates a remote host.
pub const EID_WMI_QUERY: u32 = 5857;
/// WMI-Activity EID 5858: WMI operation failure — remote WMI lateral movement
/// attempt leaves an artifact even when the operation fails.
pub const EID_WMI_OPERATION_FAILURE: u32 = 5858;

// ── Security audit task EID ───────────────────────────────────────────────────

/// Security EID 4698: Scheduled task created (Security audit channel).
/// Complements TaskScheduler/Operational EID 106; fires even when the
/// task scheduler operational log is cleared.
pub const EID_SECURITY_TASK_CREATED: u32 = 4698;

// ── BYOVD driver names ───────────────────────────────────────────────────────
// Known-vulnerable driver service names used in Bring-Your-Own-Vulnerable-Driver
// attacks (MITRE T1068). QWCrypt (RedCurl/GOLD BLADE) uses the Zemana Anti-Malware
// driver (ZAM64.sys) to terminate EDR processes before deploying the encryptor.
// Sources: LOLDrivers project, CISA advisories, vendor incident reports.

/// Service names of known-vulnerable drivers abused in BYOVD attacks.
pub const BYOVD_DRIVER_NAMES: &[&str] = &[
    "ZemanaAntiMalware",
    "zamguard64",
    "ZAM",
    "gdrv",          // Gigabyte App Center GDRV.sys
    "AsrDrv104",     // ASRock Motherboard Utility
    "AsrDrv10",
    "RTCore64",      // MSI Afterburner / RTSS
    "dbutil_2_3",    // Dell BIOS Utility
    "ATSZIO64",      // ASUSTeK I/O driver
    "WinRing0_1_2_0",
    "cpuz136_x64",   // CPU-Z driver
    "speedfan",
];

// ── QWCrypt-specific PowerShell patterns ─────────────────────────────────────
// Observed in RedCurl/GOLD BLADE intrusions 2024–2025.
// Match case-insensitively against EID 4104 ScriptBlockText.

/// PowerShell script-block substrings associated with QWCrypt ransomware.
pub const QWCRYPT_PS_PATTERNS: &[&str] = &[
    "Get-VM",
    "Stop-VM",
    "Start-VM",
    "Save-VM",
    "Set-VMFirmware",
    "Export-VM",
    "vssadmin delete shadows",
    "wbadmin delete",
    "bcdedit /set.*recoveryenabled",
];

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

    // ── Super-timeline channels ───────────────────────────────────────────────

    #[test]
    fn super_timeline_channels_has_five_entries() {
        assert_eq!(SUPER_TIMELINE_CHANNELS.len(), 5);
    }

    #[test]
    fn super_timeline_channels_includes_security_and_system() {
        assert!(SUPER_TIMELINE_CHANNELS.contains(&"Security"));
        assert!(SUPER_TIMELINE_CHANNELS.contains(&"System"));
    }

    #[test]
    fn super_timeline_channels_includes_sysmon() {
        assert!(SUPER_TIMELINE_CHANNELS.contains(&SYSMON_CHANNEL));
    }

    #[test]
    fn super_timeline_channels_includes_powershell_and_taskscheduler() {
        assert!(SUPER_TIMELINE_CHANNELS.contains(&POWERSHELL_OPERATIONAL_CHANNEL));
        assert!(SUPER_TIMELINE_CHANNELS.contains(&TASKSCHEDULER_OPERATIONAL_CHANNEL));
    }

    #[test]
    fn sysmon_channel_name_is_correct() {
        assert_eq!(SYSMON_CHANNEL, "Microsoft-Windows-Sysmon/Operational");
    }

    // ── Sysmon EIDs ──────────────────────────────────────────────────────────

    #[test]
    fn sysmon_process_create_is_eid_1() {
        assert_eq!(EID_SYSMON_PROCESS_CREATE, 1);
    }

    #[test]
    fn sysmon_file_create_is_eid_11() {
        assert_eq!(EID_SYSMON_FILE_CREATE, 11);
    }

    #[test]
    fn sysmon_file_create_stream_hash_is_eid_15() {
        assert_eq!(EID_SYSMON_FILE_CREATE_STREAM_HASH, 15);
    }

    // ── Boot / shutdown EIDs ─────────────────────────────────────────────────

    #[test]
    fn eid_boot_is_6005() {
        assert_eq!(EID_BOOT, 6005);
    }

    #[test]
    fn eid_shutdown_is_6006() {
        assert_eq!(EID_SHUTDOWN, 6006);
    }

    #[test]
    fn eid_unexpected_shutdown_is_6008() {
        assert_eq!(EID_UNEXPECTED_SHUTDOWN, 6008);
    }

    // ── Sysmon field names ────────────────────────────────────────────────────

    #[test]
    fn sysmon_field_process_guid_is_correct() {
        assert_eq!(SYSMON_FIELD_PROCESS_GUID, "ProcessGuid");
    }

    #[test]
    fn sysmon_field_target_filename_is_correct() {
        assert_eq!(SYSMON_FIELD_TARGET_FILENAME, "TargetFilename");
    }

    // ── Security EID constants ────────────────────────────────────────────────

    #[test]
    fn eid_logon_is_4624() {
        assert_eq!(EID_LOGON, 4624);
    }

    #[test]
    fn eid_special_logon_is_4672() {
        assert_eq!(EID_SPECIAL_LOGON, 4672);
    }

    #[test]
    fn eid_process_create_is_4688() {
        assert_eq!(EID_PROCESS_CREATE, 4688);
    }
}
