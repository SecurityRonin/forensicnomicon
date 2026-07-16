//! EVTX binary format constants and offset layouts.
//!
//! Single source of truth for all magic bytes, sizes, and field offsets
//! used by EVTX parsers and carvers. Parser crates re-export from here
//! rather than defining their own copies.
//!
//! ```rust
//! use forensicnomicon::evtx::{ELFFILE_MAGIC, EVTX_FILE_HEADER_OFFSETS};
//! // magic at byte 0, checksum at 0x7C
//! let _ = EVTX_FILE_HEADER_OFFSETS.checksum;
//! ```

// ── File header ───────────────────────────────────────────────────────────────

pub const ELFFILE_MAGIC: [u8; 8] = *b"ElfFile\0";
pub const FILE_HEADER_SIZE: u64 = 0x80;
pub const FILE_HEADER_BLOCK_SIZE: u64 = 0x1000; // 4 KiB

// ── Chunk ─────────────────────────────────────────────────────────────────────

pub const ELFCHNK_MAGIC: [u8; 8] = *b"ElfChnk\0";
pub const CHUNK_SIZE: u64 = 0x1_0000; // 64 KiB
pub const CHUNK_HEADER_SIZE: u64 = 0x80;
pub const CHUNK_RECORDS_OFFSET: u64 = 0x200; // records start here within each chunk

/// Byte range covered by the chunk header CRC32 (stored at `CHUNK_HEADER_CRC_OFFSET`).
pub const CHUNK_HEADER_CRC_RANGE: core::ops::Range<usize> = 0..0x78;
pub const CHUNK_HEADER_CRC_OFFSET: usize = 0x78;
pub const EVENT_RECORDS_CRC_OFFSET: usize = 0x34;

// ── Event record ──────────────────────────────────────────────────────────────

/// `**\0\0` — marks the start of every event record.
pub const RECORD_MAGIC: [u8; 4] = [0x2A, 0x2A, 0x00, 0x00];
/// magic(4) + size(4) + record_id(8) + timestamp(8) = 24 bytes.
pub const RECORD_HEADER_SIZE: u64 = 0x18;

// ── File flags ────────────────────────────────────────────────────────────────

pub const FILE_FLAG_DIRTY: u32 = 0x0001;
pub const FILE_FLAG_FULL: u32 = 0x0002;

// ── Offset layout structs ─────────────────────────────────────────────────────

/// Field offsets within the 128-byte EVTX file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EvtxFileHeaderOffsets {
    pub magic: u64,              // 0x00
    pub first_chunk_number: u64, // 0x08
    pub last_chunk_number: u64,  // 0x10
    pub next_record_id: u64,     // 0x18
    pub header_size: u64,        // 0x20
    pub minor_version: u64,      // 0x24
    pub major_version: u64,      // 0x26
    pub header_block_size: u64,  // 0x28
    pub chunk_count: u64,        // 0x2A
    pub file_flags: u64,         // 0x78
    pub checksum: u64,           // 0x7C
}

/// Field offsets within the 128-byte EVTX chunk header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EvtxChunkHeaderOffsets {
    pub magic: u64,                         // 0x00
    pub first_event_record_number: u64,     // 0x08
    pub last_event_record_number: u64,      // 0x10
    pub first_event_record_id: u64,         // 0x18
    pub last_event_record_id: u64,          // 0x20
    pub header_size: u64,                   // 0x28
    pub last_event_record_data_offset: u64, // 0x2C
    pub free_space_offset: u64,             // 0x30
    pub event_records_checksum: u64,        // 0x34
    pub header_checksum: u64,               // 0x78
}

pub const EVTX_FILE_HEADER_OFFSETS: EvtxFileHeaderOffsets = EvtxFileHeaderOffsets {
    magic: 0x00,
    first_chunk_number: 0x08,
    last_chunk_number: 0x10,
    next_record_id: 0x18,
    header_size: 0x20,
    minor_version: 0x24,
    major_version: 0x26,
    header_block_size: 0x28,
    chunk_count: 0x2A,
    file_flags: 0x78,
    checksum: 0x7C,
};

pub const EVTX_CHUNK_HEADER_OFFSETS: EvtxChunkHeaderOffsets = EvtxChunkHeaderOffsets {
    magic: 0x00,
    first_event_record_number: 0x08,
    last_event_record_number: 0x10,
    first_event_record_id: 0x18,
    last_event_record_id: 0x20,
    header_size: 0x28,
    last_event_record_data_offset: 0x2C,
    free_space_offset: 0x30,
    event_records_checksum: 0x34,
    header_checksum: 0x78,
};

// ── Semantic EVTX event structs ───────────────────────────────────────────────
//
// Plain data types — zero deps. Populated by winevt-extract; consumed by
// forensic correlation layers (issen, etc.).

/// An explicit-credential / Kerberos / NTLM lateral-movement event.
/// Produced from EID 4648 (RunAs/PtH), 4769 (Kerberos SPN), 4776 (NTLM).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LateralMovementEvent {
    pub timestamp: String,
    pub event_id: u32,
    pub source_user: Option<String>,
    pub target_user: Option<String>,
    pub target_host: Option<String>,
    pub logon_type: Option<u32>,
    pub auth_package: Option<String>,
    pub encryption_type: Option<String>,
}

/// A Remote Desktop session reconnect or disconnect event.
/// Produced from EID 4778 (reconnected) and 4779 (disconnected).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RdpSessionEvent {
    pub timestamp: String,
    pub event_id: u32,
    pub user: Option<String>,
    pub session_id: Option<u32>,
    pub source_ip: Option<String>,
}

/// A network share access or access-check event.
/// Produced from EID 5140 (share accessed) and 5145 (share object access check).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SmbAccessEvent {
    pub timestamp: String,
    pub event_id: u32,
    pub subject_user: Option<String>,
    pub share_name: Option<String>,
    pub share_path: Option<String>,
    pub relative_target: Option<String>,
    pub ip_address: Option<String>,
}

/// A Microsoft Defender malware detection or action event.
/// Produced from EID 1116 (detected), 1117 (action taken), 1006 (scan result).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DefenderEvent {
    pub timestamp: String,
    pub event_id: u32,
    pub threat_name: Option<String>,
    pub severity: Option<String>,
    pub path: Option<String>,
    pub action_taken: Option<String>,
    pub process_name: Option<String>,
}

/// A WMI activity or subscription event.
/// Produced from EID 5857/5858/5860/5861 (WMI-Activity) and Sysmon EID 19/20/21.
/// EID 5861 / Sysmon 19 = permanent subscription — classic WMI backdoor indicator.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WmiEvent {
    pub timestamp: String,
    pub event_id: u32,
    pub provider: Option<String>,
    pub filter_name: Option<String>,
    pub consumer_name: Option<String>,
    pub query: Option<String>,
}

/// A scheduled task creation or modification event.
/// Produced from EID 4698 (task created) and EID 4702 (task updated).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScheduledTask {
    pub timestamp: String,
    pub event_id: u32,
    pub task_name: Option<String>,
    /// Raw XML task body; may contain inline script (VBScript/JScript).
    pub task_content: Option<String>,
    pub subject_user: Option<String>,
}

/// A process-creation event with LOLBin detection.
/// Produced from Security EID 4688 and Sysmon EID 1.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProcessExecution {
    pub timestamp: String,
    pub event_id: u32,
    pub pid: u64,
    pub parent_pid: u64,
    pub image: String,
    pub command_line: String,
    pub parent_image: Option<String>,
    pub is_lolbin: bool,
}

// ── Unified tagged enum ───────────────────────────────────────────────────────

/// A unified EVTX semantic event — one variant per extraction type.
///
/// Use this when building mixed-event collections (e.g. a unified timeline).
/// Each variant carries the fully-typed inner struct so the compiler enforces
/// which fields are available per event kind.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind"))]
pub enum EvtxEvent {
    LateralMovement(LateralMovementEvent),
    RdpSession(RdpSessionEvent),
    SmbAccess(SmbAccessEvent),
    Defender(DefenderEvent),
    Wmi(WmiEvent),
    ScheduledTask(ScheduledTask),
    ProcessExecution(ProcessExecution),
}

impl EvtxEvent {
    pub fn timestamp(&self) -> &str {
        match self {
            Self::LateralMovement(e) => &e.timestamp,
            Self::RdpSession(e) => &e.timestamp,
            Self::SmbAccess(e) => &e.timestamp,
            Self::Defender(e) => &e.timestamp,
            Self::Wmi(e) => &e.timestamp,
            Self::ScheduledTask(e) => &e.timestamp,
            Self::ProcessExecution(e) => &e.timestamp,
        }
    }

    pub fn event_id(&self) -> u32 {
        match self {
            Self::LateralMovement(e) => e.event_id,
            Self::RdpSession(e) => e.event_id,
            Self::SmbAccess(e) => e.event_id,
            Self::Defender(e) => e.event_id,
            Self::Wmi(e) => e.event_id,
            Self::ScheduledTask(e) => e.event_id,
            Self::ProcessExecution(e) => e.event_id,
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn evtx_event_timestamp_and_event_id_cover_all_variants() {
        let events = [
            EvtxEvent::LateralMovement(LateralMovementEvent {
                timestamp: "t-lm".into(),
                event_id: 4648,
                source_user: None,
                target_user: None,
                target_host: None,
                logon_type: None,
                auth_package: None,
                encryption_type: None,
            }),
            EvtxEvent::RdpSession(RdpSessionEvent {
                timestamp: "t-rdp".into(),
                event_id: 4778,
                user: None,
                session_id: None,
                source_ip: None,
            }),
            EvtxEvent::SmbAccess(SmbAccessEvent {
                timestamp: "t-smb".into(),
                event_id: 5140,
                subject_user: None,
                share_name: None,
                share_path: None,
                relative_target: None,
                ip_address: None,
            }),
            EvtxEvent::Defender(DefenderEvent {
                timestamp: "t-def".into(),
                event_id: 1116,
                threat_name: None,
                severity: None,
                path: None,
                action_taken: None,
                process_name: None,
            }),
            EvtxEvent::Wmi(WmiEvent {
                timestamp: "t-wmi".into(),
                event_id: 5861,
                provider: None,
                filter_name: None,
                consumer_name: None,
                query: None,
            }),
            EvtxEvent::ScheduledTask(ScheduledTask {
                timestamp: "t-task".into(),
                event_id: 4698,
                task_name: None,
                task_content: None,
                subject_user: None,
            }),
            EvtxEvent::ProcessExecution(ProcessExecution {
                timestamp: "t-proc".into(),
                event_id: 4688,
                pid: 1,
                parent_pid: 0,
                image: "x.exe".into(),
                command_line: String::new(),
                parent_image: None,
                is_lolbin: false,
            }),
        ];
        let expected_ids = [4648u32, 4778, 5140, 1116, 5861, 4698, 4688];
        let expected_ts = [
            "t-lm", "t-rdp", "t-smb", "t-def", "t-wmi", "t-task", "t-proc",
        ];
        for (i, e) in events.iter().enumerate() {
            assert_eq!(e.event_id(), expected_ids[i]);
            assert_eq!(e.timestamp(), expected_ts[i]);
        }
    }
    use super::*;

    // EVTX on-disk signatures. Source: libyal libevtx format spec
    // (Windows XML Event Log (EVTX) format): file header "ElfFile\0", chunk header
    // "ElfChnk\0", event record "**\0\0" (0x2A 0x2A 0x00 0x00).
    #[test]
    fn file_magic_is_correct() {
        assert_eq!(&ELFFILE_MAGIC, b"ElfFile\0");
    }
    #[test]
    fn chunk_magic_is_correct() {
        assert_eq!(&ELFCHNK_MAGIC, b"ElfChnk\0");
    }
    #[test]
    fn record_magic_is_correct() {
        assert_eq!(RECORD_MAGIC, [0x2A, 0x2A, 0x00, 0x00]);
    }
    #[test]
    fn chunk_size_is_64kib() {
        assert_eq!(CHUNK_SIZE, 65536);
    }
    #[test]
    fn records_start_at_0x200() {
        assert_eq!(CHUNK_RECORDS_OFFSET, 0x200);
    }
    #[test]
    fn header_crc_covers_first_120_bytes() {
        assert_eq!(CHUNK_HEADER_CRC_RANGE, 0..0x78);
        assert_eq!(CHUNK_HEADER_CRC_OFFSET, 0x78);
    }
    #[test]
    fn file_header_offsets_are_correct() {
        assert_eq!(EVTX_FILE_HEADER_OFFSETS.magic, 0x00);
        assert_eq!(EVTX_FILE_HEADER_OFFSETS.next_record_id, 0x18);
        assert_eq!(EVTX_FILE_HEADER_OFFSETS.chunk_count, 0x2A);
        assert_eq!(EVTX_FILE_HEADER_OFFSETS.checksum, 0x7C);
    }
    #[test]
    fn chunk_header_offsets_are_correct() {
        assert_eq!(EVTX_CHUNK_HEADER_OFFSETS.first_event_record_number, 0x08);
        assert_eq!(EVTX_CHUNK_HEADER_OFFSETS.event_records_checksum, 0x34);
        assert_eq!(EVTX_CHUNK_HEADER_OFFSETS.header_checksum, 0x78);
    }
}
