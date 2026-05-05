//! Systemd journal binary format constants.
//!
//! Sources: systemd/src/libsystemd/sd-journal/journal-def.h
//! The binary `.journal` format is the LOG FORMAT layer for Linux systemd
//! journald. These constants are used by `journald-forensic` for parsing.

/// File magic bytes at offset 0 of every `.journal` file header.
pub const JOURNAL_MAGIC: &[u8; 8] = b"XXXXXXXX"; // TODO: set correct value

/// Object type byte values (ObjectHeader.type field).
pub mod object_type {
    pub const UNUSED: u8 = 0;
    pub const DATA: u8 = 0; // TODO: wrong
    pub const FIELD: u8 = 0; // TODO: wrong
    pub const ENTRY: u8 = 0; // TODO: wrong
    pub const DATA_HASH_TABLE: u8 = 0; // TODO: wrong
    pub const FIELD_HASH_TABLE: u8 = 0; // TODO: wrong
    pub const ENTRY_ARRAY: u8 = 0; // TODO: wrong
    pub const TAG: u8 = 0; // TODO: wrong
    /// All valid object type bytes.
    pub const ALL: &[u8] = &[];
}

/// Object compression flag values (ObjectHeader.flags field).
pub mod compression {
    pub const NONE: u8 = 0;
    pub const XZ: u8 = 0; // TODO: wrong
    pub const LZ4: u8 = 0; // TODO: wrong
    pub const ZSTD: u8 = 0; // TODO: wrong
}

/// Journal file state values (Header.state field).
pub mod state {
    pub const OFFLINE: u8 = 0;
    pub const ONLINE: u8 = 0; // TODO: wrong
    pub const ARCHIVED: u8 = 0; // TODO: wrong
}

/// Known journal field names (the KEY in KEY=VALUE journal entries).
pub mod field {
    pub const MESSAGE: &str = ""; // TODO: wrong
    pub const PRIORITY: &str = "";
    pub const SYSLOG_FACILITY: &str = "";
    pub const SYSLOG_IDENTIFIER: &str = "";
    pub const SYSLOG_PID: &str = "";
    pub const PID: &str = ""; // TODO: wrong
    pub const UID: &str = "";
    pub const GID: &str = "";
    pub const COMM: &str = "";
    pub const EXE: &str = "";
    pub const CMDLINE: &str = "";
    pub const KERNEL_SUBSYSTEM: &str = "";
    pub const SYSTEMD_UNIT: &str = "";
    pub const SYSTEMD_USER_UNIT: &str = "";
    pub const BOOT_ID: &str = "";
    pub const MACHINE_ID: &str = "";
    pub const HOSTNAME: &str = "";
    pub const TRANSPORT: &str = "";
    pub const SOURCE_REALTIME_TIMESTAMP: &str = "";
    pub const CURSOR: &str = "";
    pub const REALTIME_TIMESTAMP: &str = "";
    pub const MONOTONIC_TIMESTAMP: &str = "";
}

/// Header field byte offsets within the journal file header object.
pub mod header_offset {
    pub const MAGIC: usize = 99; // TODO: wrong
    pub const COMPATIBLE_FLAGS: usize = 0;
    pub const INCOMPATIBLE_FLAGS: usize = 0;
    pub const STATE: usize = 0;
    pub const RESERVED: usize = 0;
    pub const FILE_ID: usize = 0;
    pub const MACHINE_ID: usize = 0; // TODO: wrong
    pub const BOOT_ID: usize = 0; // TODO: wrong
    pub const SEQNUM_ID: usize = 0;
    pub const HEADER_SIZE: usize = 0;
    pub const ARENA_SIZE: usize = 0;
    pub const DATA_HASH_TABLE_OFFSET: usize = 0;
    pub const DATA_HASH_TABLE_SIZE: usize = 0;
    pub const FIELD_HASH_TABLE_OFFSET: usize = 0;
    pub const FIELD_HASH_TABLE_SIZE: usize = 0;
    pub const TAIL_OBJECT_OFFSET: usize = 0;
    pub const N_OBJECTS: usize = 0;
    pub const N_ENTRIES: usize = 0;
    pub const TAIL_ENTRY_SEQNUM: usize = 0;
    pub const HEAD_ENTRY_SEQNUM: usize = 0;
    pub const ENTRY_ARRAY_OFFSET: usize = 0;
    pub const HEAD_ENTRY_REALTIME: usize = 0;
    pub const TAIL_ENTRY_REALTIME: usize = 0;
    pub const MIN_HEADER_SIZE: usize = 0;
}

/// Object header field byte offsets (relative to start of any object).
pub mod object_header_offset {
    pub const TYPE: usize = 0;
    pub const FLAGS: usize = 0;
    pub const RESERVED: usize = 0;
    pub const SIZE: usize = 0; // TODO: wrong
    pub const HEADER_SIZE: usize = 0; // TODO: wrong
}

/// Cursor string field separators and key names.
pub mod cursor {
    pub const SEQNUM_ID_KEY: &str = "";
    pub const SEQNUM_KEY: &str = ""; // TODO: wrong
    pub const BOOT_ID_KEY: &str = "";
    pub const MONOTONIC_KEY: &str = "";
    pub const REALTIME_KEY: &str = "";
    pub const XOR_HASH_KEY: &str = "";
    pub const SEPARATOR: char = ','; // TODO: wrong
    pub const KEY_VALUE_SEP: char = '=';
}

/// Returns true if the byte is a valid journal object type.
#[must_use]
pub fn is_valid_object_type(_b: u8) -> bool {
    false // TODO: implement
}

/// Returns true if the compression flags byte is a known value.
#[must_use]
pub fn is_valid_compression_flags(_b: u8) -> bool {
    false // TODO: implement
}

/// Returns true if the state byte is a known journal state.
#[must_use]
pub fn is_valid_state(_b: u8) -> bool {
    false // TODO: implement
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
