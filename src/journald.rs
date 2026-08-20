//! Systemd journal binary format constants.
//!
//! Sources: systemd/src/libsystemd/sd-journal/journal-def.h
//! The binary `.journal` format is the LOG FORMAT layer for Linux systemd
//! journald. These constants are used by `journald-forensic` for parsing.

/// File magic bytes at offset 0 of every `.journal` file header.
pub const JOURNAL_MAGIC: &[u8; 8] = b"LPKSHHRH";

/// Object type byte values (ObjectHeader.type field).
pub mod object_type {
    pub const UNUSED: u8 = 0;
    pub const DATA: u8 = 1;
    pub const FIELD: u8 = 2;
    pub const ENTRY: u8 = 3;
    pub const DATA_HASH_TABLE: u8 = 4;
    pub const FIELD_HASH_TABLE: u8 = 5;
    pub const ENTRY_ARRAY: u8 = 6;
    pub const TAG: u8 = 7;
    /// All valid object type bytes.
    pub const ALL: &[u8] = &[
        UNUSED,
        DATA,
        FIELD,
        ENTRY,
        DATA_HASH_TABLE,
        FIELD_HASH_TABLE,
        ENTRY_ARRAY,
        TAG,
    ];
}

/// Object compression flag values (ObjectHeader.flags field).
pub mod compression {
    pub const NONE: u8 = 0;
    pub const XZ: u8 = 1;
    pub const LZ4: u8 = 2;
    pub const ZSTD: u8 = 4;
}

/// Journal file state values (Header.state field).
pub mod state {
    pub const OFFLINE: u8 = 0; // clean shutdown
    pub const ONLINE: u8 = 1; // currently open (or dirty)
    pub const ARCHIVED: u8 = 2; // rotated, read-only
}

/// Known journal field names (the KEY in KEY=VALUE journal entries).
/// These are the standard systemd and kernel-defined field names.
pub mod field {
    /// Human-readable log message.
    pub const MESSAGE: &str = "MESSAGE";
    /// syslog priority (0=EMERG … 7=DEBUG).
    pub const PRIORITY: &str = "PRIORITY";
    /// syslog facility number.
    pub const SYSLOG_FACILITY: &str = "SYSLOG_FACILITY";
    /// syslog identifier (process name used in syslog).
    pub const SYSLOG_IDENTIFIER: &str = "SYSLOG_IDENTIFIER";
    /// syslog PID field.
    pub const SYSLOG_PID: &str = "SYSLOG_PID";
    /// Process ID of the logging process.
    pub const PID: &str = "_PID";
    /// User ID of the logging process.
    pub const UID: &str = "_UID";
    /// Group ID of the logging process.
    pub const GID: &str = "_GID";
    /// Command name (basename of executable).
    pub const COMM: &str = "_COMM";
    /// Executable path.
    pub const EXE: &str = "_EXE";
    /// Full command line.
    pub const CMDLINE: &str = "_CMDLINE";
    /// Kernel subsystem / audit type.
    pub const KERNEL_SUBSYSTEM: &str = "_KERNEL_SUBSYSTEM";
    /// systemd unit name.
    pub const SYSTEMD_UNIT: &str = "_SYSTEMD_UNIT";
    /// systemd user unit name.
    pub const SYSTEMD_USER_UNIT: &str = "_SYSTEMD_USER_UNIT";
    /// Boot ID (hex UUID, changes per boot).
    pub const BOOT_ID: &str = "_BOOT_ID";
    /// Machine ID (hex UUID, stable per machine).
    pub const MACHINE_ID: &str = "_MACHINE_ID";
    /// Hostname.
    pub const HOSTNAME: &str = "_HOSTNAME";
    /// Transport used to collect the entry (journal, syslog, kernel, etc.).
    pub const TRANSPORT: &str = "_TRANSPORT";
    /// Source realtime timestamp (microseconds since epoch), as written by the originating process.
    pub const SOURCE_REALTIME_TIMESTAMP: &str = "_SOURCE_REALTIME_TIMESTAMP";
    /// Journal cursor string for this entry.
    pub const CURSOR: &str = "__CURSOR";
    /// Realtime timestamp of this entry as stored in the journal (microseconds since epoch).
    pub const REALTIME_TIMESTAMP: &str = "__REALTIME_TIMESTAMP";
    /// Monotonic timestamp of this entry (microseconds since boot).
    pub const MONOTONIC_TIMESTAMP: &str = "__MONOTONIC_TIMESTAMP";
}

/// Header field byte offsets within the journal file header object.
/// All offsets are from the start of the file (the Header object starts at offset 0).
/// Layout per systemd journal-def.h (little-endian, packed structs).
pub mod header_offset {
    /// Magic bytes: 8 bytes at offset 0.
    pub const MAGIC: usize = 0;
    /// compatible_flags: u32 at offset 8.
    pub const COMPATIBLE_FLAGS: usize = 8;
    /// incompatible_flags: u32 at offset 12.
    pub const INCOMPATIBLE_FLAGS: usize = 12;
    /// state: u8 at offset 16.
    pub const STATE: usize = 16;
    /// `reserved[7]: u8[7]` at offset 17.
    pub const RESERVED: usize = 17;
    /// file_id: [u8; 16] at offset 24.
    pub const FILE_ID: usize = 24;
    /// machine_id: [u8; 16] at offset 40.
    pub const MACHINE_ID: usize = 40;
    /// boot_id: [u8; 16] at offset 56.
    pub const BOOT_ID: usize = 56;
    /// seqnum_id: [u8; 16] at offset 72.
    pub const SEQNUM_ID: usize = 72;
    /// header_size: u64 at offset 88.
    pub const HEADER_SIZE: usize = 88;
    /// arena_size: u64 at offset 96.
    pub const ARENA_SIZE: usize = 96;
    /// data_hash_table_offset: u64 at offset 104.
    pub const DATA_HASH_TABLE_OFFSET: usize = 104;
    /// data_hash_table_size: u64 at offset 112.
    pub const DATA_HASH_TABLE_SIZE: usize = 112;
    /// field_hash_table_offset: u64 at offset 120.
    pub const FIELD_HASH_TABLE_OFFSET: usize = 120;
    /// field_hash_table_size: u64 at offset 128.
    pub const FIELD_HASH_TABLE_SIZE: usize = 128;
    /// tail_object_offset: u64 at offset 136.
    pub const TAIL_OBJECT_OFFSET: usize = 136;
    /// n_objects: u64 at offset 160.
    pub const N_OBJECTS: usize = 160;
    /// n_entries: u64 at offset 168.
    pub const N_ENTRIES: usize = 168;
    /// tail_entry_seqnum: u64 at offset 176.
    pub const TAIL_ENTRY_SEQNUM: usize = 176;
    /// head_entry_seqnum: u64 at offset 184.
    pub const HEAD_ENTRY_SEQNUM: usize = 184;
    /// entry_array_offset: u64 at offset 192.
    pub const ENTRY_ARRAY_OFFSET: usize = 192;
    /// head_entry_realtime: u64 at offset 208.
    pub const HEAD_ENTRY_REALTIME: usize = 208;
    /// tail_entry_realtime: u64 at offset 216.
    pub const TAIL_ENTRY_REALTIME: usize = 216;
    /// Minimum valid header size (224 bytes covers all fields above).
    pub const MIN_HEADER_SIZE: usize = 224;
}

/// Object header field byte offsets (relative to start of any object).
pub mod object_header_offset {
    /// type: u8 at offset 0.
    pub const TYPE: usize = 0;
    /// flags: u8 at offset 1.
    pub const FLAGS: usize = 1;
    /// reserved: [u8; 6] at offset 2.
    pub const RESERVED: usize = 2;
    /// size: u64 at offset 8 (little-endian).
    pub const SIZE: usize = 8;
    /// Total object header size in bytes.
    pub const HEADER_SIZE: usize = 16;
}

/// Cursor string field separators and key names.
pub mod cursor {
    /// Full cursor format: "s=SEQNUM_ID;i=SEQNUM;b=BOOT_ID;m=MONOTONIC;t=REALTIME;x=XOR_HASH"
    /// All UUID values are lowercase hex without dashes (32 hex chars = 128 bits).
    /// All numeric values are lowercase hex.
    pub const SEQNUM_ID_KEY: &str = "s";
    pub const SEQNUM_KEY: &str = "i";
    pub const BOOT_ID_KEY: &str = "b";
    pub const MONOTONIC_KEY: &str = "m";
    pub const REALTIME_KEY: &str = "t";
    pub const XOR_HASH_KEY: &str = "x";
    pub const SEPARATOR: char = ';';
    pub const KEY_VALUE_SEP: char = '=';
}

/// Returns true if the byte is a valid journal object type.
#[must_use]
pub fn is_valid_object_type(b: u8) -> bool {
    object_type::ALL.contains(&b)
}

/// Returns true if the compression flags byte is a known value.
#[must_use]
pub fn is_valid_compression_flags(b: u8) -> bool {
    matches!(
        b,
        compression::NONE | compression::XZ | compression::LZ4 | compression::ZSTD
    )
}

/// Returns true if the state byte is a known journal state.
#[must_use]
pub fn is_valid_state(b: u8) -> bool {
    matches!(b, state::OFFLINE | state::ONLINE | state::ARCHIVED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_is_lpkshhrh() {
        assert_eq!(JOURNAL_MAGIC, b"LPKSHHRH");
    }

    #[test]
    fn object_type_entry_is_3() {
        assert_eq!(object_type::ENTRY, 3);
    }

    #[test]
    fn object_type_tag_is_7() {
        assert_eq!(object_type::TAG, 7);
    }

    #[test]
    fn is_valid_object_type_known() {
        assert!(is_valid_object_type(3));
    }

    #[test]
    fn is_valid_object_type_unknown() {
        assert!(!is_valid_object_type(99));
    }

    #[test]
    fn is_valid_compression_flags_none() {
        assert!(is_valid_compression_flags(0));
    }

    #[test]
    fn is_valid_compression_flags_zstd() {
        assert!(is_valid_compression_flags(4));
    }

    #[test]
    fn is_valid_compression_flags_unknown() {
        assert!(!is_valid_compression_flags(8));
    }

    #[test]
    fn is_valid_state_offline() {
        assert!(is_valid_state(0));
    }

    #[test]
    fn is_valid_state_unknown() {
        assert!(!is_valid_state(3));
    }

    #[test]
    fn field_message_constant() {
        assert_eq!(field::MESSAGE, "MESSAGE");
    }

    #[test]
    fn field_pid_constant() {
        assert_eq!(field::PID, "_PID");
    }

    #[test]
    fn header_offset_magic_is_zero() {
        assert_eq!(header_offset::MAGIC, 0);
    }

    #[test]
    fn header_offset_boot_id_is_56() {
        assert_eq!(header_offset::BOOT_ID, 56);
    }

    #[test]
    fn header_offset_machine_id_is_40() {
        assert_eq!(header_offset::MACHINE_ID, 40);
    }

    #[test]
    fn object_header_size_field_offset() {
        assert_eq!(object_header_offset::SIZE, 8);
    }

    #[test]
    fn object_header_total_size() {
        assert_eq!(object_header_offset::HEADER_SIZE, 16);
    }

    #[test]
    fn cursor_seqnum_key() {
        assert_eq!(cursor::SEQNUM_KEY, "i");
    }

    #[test]
    fn cursor_separator() {
        assert_eq!(cursor::SEPARATOR, ';');
    }
}
