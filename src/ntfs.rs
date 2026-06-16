//! NTFS on-disk structure knowledge: signatures, attribute type codes,
//! well-known MFT record numbers, record-header field offsets, flags, and
//! `$FILE_NAME` namespaces.
//!
//! Single source of truth for forensic tools that parse NTFS (e.g. the
//! `ntfs-forensic` crate). This module holds **constants and layout facts
//! only** — no parsing, no I/O.
//!
//! Sources:
//! - Microsoft, "[MS-FSCC]: File System Control Codes" and the NTFS on-disk
//!   format documentation.
//! - Brian Carrier, *File System Forensic Analysis* (Addison-Wesley, 2005),
//!   chapters 11–13 (NTFS).
//! - Joachim Metz, "libfsntfs — NTFS format specification":
//!   <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20%28NTFS%29.asciidoc>
//! - The NTFS Documentation project (Russon & Fledel):
//!   <https://flatcap.github.io/linux-ntfs/ntfs/>

// ── Signatures ────────────────────────────────────────────────────────────────

/// Magic at the start of an in-use MFT file-record segment.
pub const SIGNATURE_FILE: [u8; 4] = *b"FILE";
/// Magic written by `chkdsk` over a record it found corrupt.
pub const SIGNATURE_BAAD: [u8; 4] = *b"BAAD";
/// Magic at the start of an index-allocation buffer (`$INDEX_ALLOCATION`).
pub const SIGNATURE_INDX: [u8; 4] = *b"INDX";
/// OEM identifier at offset 3 of the NTFS boot sector.
pub const OEM_ID: [u8; 8] = *b"NTFS    ";

// ── Attribute type codes ────────────────────────────────────────────────────────

/// NTFS attribute type identifiers (the `type` field of an attribute header).
pub mod attr_types {
    pub const STANDARD_INFORMATION: u32 = 0x10;
    pub const ATTRIBUTE_LIST: u32 = 0x20;
    pub const FILE_NAME: u32 = 0x30;
    pub const OBJECT_ID: u32 = 0x40;
    pub const SECURITY_DESCRIPTOR: u32 = 0x50;
    pub const VOLUME_NAME: u32 = 0x60;
    pub const VOLUME_INFORMATION: u32 = 0x70;
    pub const DATA: u32 = 0x80;
    pub const INDEX_ROOT: u32 = 0x90;
    pub const INDEX_ALLOCATION: u32 = 0xA0;
    pub const BITMAP: u32 = 0xB0;
    pub const REPARSE_POINT: u32 = 0xC0;
    pub const EA_INFORMATION: u32 = 0xD0;
    pub const EA: u32 = 0xE0;
    pub const PROPERTY_SET: u32 = 0xF0;
    pub const LOGGED_UTILITY_STREAM: u32 = 0x100;
    /// End-of-attributes marker.
    pub const END: u32 = 0xFFFF_FFFF;
}

/// Attribute type code → canonical `$NAME`, in ascending code order.
pub const ATTRIBUTE_TYPES: &[(u32, &str)] = &[
    (attr_types::STANDARD_INFORMATION, "$STANDARD_INFORMATION"),
    (attr_types::ATTRIBUTE_LIST, "$ATTRIBUTE_LIST"),
    (attr_types::FILE_NAME, "$FILE_NAME"),
    (attr_types::OBJECT_ID, "$OBJECT_ID"),
    (attr_types::SECURITY_DESCRIPTOR, "$SECURITY_DESCRIPTOR"),
    (attr_types::VOLUME_NAME, "$VOLUME_NAME"),
    (attr_types::VOLUME_INFORMATION, "$VOLUME_INFORMATION"),
    (attr_types::DATA, "$DATA"),
    (attr_types::INDEX_ROOT, "$INDEX_ROOT"),
    (attr_types::INDEX_ALLOCATION, "$INDEX_ALLOCATION"),
    (attr_types::BITMAP, "$BITMAP"),
    (attr_types::REPARSE_POINT, "$REPARSE_POINT"),
    (attr_types::EA_INFORMATION, "$EA_INFORMATION"),
    (attr_types::EA, "$EA"),
    (attr_types::PROPERTY_SET, "$PROPERTY_SET"),
    (attr_types::LOGGED_UTILITY_STREAM, "$LOGGED_UTILITY_STREAM"),
];

/// Look up an attribute type code's canonical name. Returns `None` for unknown
/// codes (including the `END` marker).
#[must_use]
pub fn attribute_type_name(ty: u32) -> Option<&'static str> {
    ATTRIBUTE_TYPES
        .iter()
        .find(|(code, _)| *code == ty)
        .map(|(_, name)| *name)
}

// ── Attribute header field offsets ────────────────────────────────────────────

/// Byte offsets of fields within an attribute header (common header followed by
/// a resident or non-resident body, both beginning at `0x10`).
pub mod attr_offsets {
    // Common header.
    pub const TYPE: usize = 0x00;
    pub const LENGTH: usize = 0x04;
    pub const NON_RESIDENT: usize = 0x08;
    pub const NAME_LENGTH: usize = 0x09;
    pub const NAME_OFFSET: usize = 0x0A;
    pub const FLAGS: usize = 0x0C;
    pub const ATTRIBUTE_ID: usize = 0x0E;
    // Resident body.
    pub const RES_CONTENT_LENGTH: usize = 0x10;
    pub const RES_CONTENT_OFFSET: usize = 0x14;
    // Non-resident body.
    pub const NR_START_VCN: usize = 0x10;
    pub const NR_LAST_VCN: usize = 0x18;
    pub const NR_RUNS_OFFSET: usize = 0x20;
    pub const NR_COMPRESSION_UNIT: usize = 0x22;
    pub const NR_ALLOCATED_SIZE: usize = 0x28;
    pub const NR_REAL_SIZE: usize = 0x30;
    pub const NR_INITIALIZED_SIZE: usize = 0x38;
}

/// Attribute header flags (`flags` field at offset `0x0C`).
pub mod attr_flags {
    pub const COMPRESSED: u16 = 0x0001;
    pub const ENCRYPTED: u16 = 0x4000;
    pub const SPARSE: u16 = 0x8000;
}

// ── File attribute flags ──────────────────────────────────────────────────────

/// Windows `FILE_ATTRIBUTE_*` flags, as stored in `$STANDARD_INFORMATION` and
/// `$FILE_NAME`. Values per [MS-FSCC] §2.6.
pub mod file_attributes {
    pub const READONLY: u32 = 0x0001;
    pub const HIDDEN: u32 = 0x0002;
    pub const SYSTEM: u32 = 0x0004;
    pub const ARCHIVE: u32 = 0x0020;
    pub const TEMPORARY: u32 = 0x0100;
    pub const SPARSE_FILE: u32 = 0x0200;
    pub const REPARSE_POINT: u32 = 0x0400;
    pub const COMPRESSED: u32 = 0x0800;
    pub const ENCRYPTED: u32 = 0x4000;
}

// ── Well-known MFT record numbers ─────────────────────────────────────────────

/// Fixed MFT record numbers for NTFS metadata files (records 0–11).
pub mod mft_records {
    pub const MFT: u64 = 0;
    pub const MFTMIRR: u64 = 1;
    pub const LOGFILE: u64 = 2;
    pub const VOLUME: u64 = 3;
    pub const ATTRDEF: u64 = 4;
    /// The root directory (`.`).
    pub const ROOT: u64 = 5;
    pub const BITMAP: u64 = 6;
    pub const BOOT: u64 = 7;
    pub const BADCLUS: u64 = 8;
    pub const SECURE: u64 = 9;
    pub const UPCASE: u64 = 10;
    pub const EXTEND: u64 = 11;
}

/// Record number → metadata-file name, in ascending order.
pub const MFT_RECORD_NAMES: &[(u64, &str)] = &[
    (mft_records::MFT, "$MFT"),
    (mft_records::MFTMIRR, "$MFTMirr"),
    (mft_records::LOGFILE, "$LogFile"),
    (mft_records::VOLUME, "$Volume"),
    (mft_records::ATTRDEF, "$AttrDef"),
    (mft_records::ROOT, ". (root directory)"),
    (mft_records::BITMAP, "$Bitmap"),
    (mft_records::BOOT, "$Boot"),
    (mft_records::BADCLUS, "$BadClus"),
    (mft_records::SECURE, "$Secure"),
    (mft_records::UPCASE, "$UpCase"),
    (mft_records::EXTEND, "$Extend"),
];

/// Look up a well-known MFT record number's name. Returns `None` for ordinary
/// (non-reserved) records.
#[must_use]
pub fn mft_record_name(n: u64) -> Option<&'static str> {
    MFT_RECORD_NAMES
        .iter()
        .find(|(num, _)| *num == n)
        .map(|(_, name)| *name)
}

// ── MFT record header field offsets ──────────────────────────────────────────

/// Byte offsets of fields within an MFT file-record-segment header.
pub mod mft_offsets {
    pub const SIGNATURE: usize = 0x00;
    pub const USA_OFFSET: usize = 0x04;
    pub const USA_COUNT: usize = 0x06;
    pub const LSN: usize = 0x08;
    pub const SEQUENCE_NUMBER: usize = 0x10;
    pub const HARD_LINK_COUNT: usize = 0x12;
    pub const FIRST_ATTRIBUTE: usize = 0x14;
    pub const FLAGS: usize = 0x16;
    pub const USED_SIZE: usize = 0x18;
    pub const ALLOCATED_SIZE: usize = 0x1C;
    pub const BASE_RECORD: usize = 0x20;
    pub const NEXT_ATTR_ID: usize = 0x28;
    /// MFT record number (Windows XP and later).
    pub const RECORD_NUMBER: usize = 0x2C;
}

/// MFT file-record-segment header flags (`flags` field at offset 0x16).
pub mod mft_flags {
    pub const IN_USE: u16 = 0x0001;
    pub const DIRECTORY: u16 = 0x0002;
    pub const EXTENSION: u16 = 0x0004;
    pub const VIEW_INDEX: u16 = 0x0008;
}

// ── $FILE_NAME namespaces ─────────────────────────────────────────────────────

/// `$FILE_NAME` namespace codes (the `namespace` byte of the attribute).
pub mod filename_namespace {
    pub const POSIX: u8 = 0;
    pub const WIN32: u8 = 1;
    pub const DOS: u8 = 2;
    pub const WIN32_AND_DOS: u8 = 3;

    /// Human-readable namespace name, or `None` for an unknown code.
    #[must_use]
    pub fn name(ns: u8) -> Option<&'static str> {
        match ns {
            POSIX => Some("POSIX"),
            WIN32 => Some("Win32"),
            DOS => Some("DOS"),
            WIN32_AND_DOS => Some("Win32+DOS"),
            _ => None,
        }
    }
}

// ── Boot sector (BPB / extended BPB) field offsets ────────────────────────────

/// Byte offsets of fields within the NTFS boot sector.
pub mod boot_offsets {
    pub const OEM_ID: usize = 0x03;
    pub const BYTES_PER_SECTOR: usize = 0x0B;
    pub const SECTORS_PER_CLUSTER: usize = 0x0D;
    pub const TOTAL_SECTORS: usize = 0x28;
    pub const MFT_LCN: usize = 0x30;
    pub const MFTMIRR_LCN: usize = 0x38;
    pub const CLUSTERS_PER_RECORD: usize = 0x40;
    pub const CLUSTERS_PER_INDEX: usize = 0x44;
    pub const VOLUME_SERIAL: usize = 0x48;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_signatures_are_correct() {
        assert_eq!(&SIGNATURE_FILE, b"FILE");
        assert_eq!(&SIGNATURE_BAAD, b"BAAD");
        assert_eq!(&OEM_ID, b"NTFS    ");
    }

    #[test]
    fn attribute_type_codes_resolve() {
        assert_eq!(
            attribute_type_name(attr_types::STANDARD_INFORMATION),
            Some("$STANDARD_INFORMATION")
        );
        assert_eq!(
            attribute_type_name(attr_types::FILE_NAME),
            Some("$FILE_NAME")
        );
        assert_eq!(attribute_type_name(attr_types::DATA), Some("$DATA"));
        assert_eq!(
            attribute_type_name(attr_types::INDEX_ROOT),
            Some("$INDEX_ROOT")
        );
        assert_eq!(
            attribute_type_name(attr_types::LOGGED_UTILITY_STREAM),
            Some("$LOGGED_UTILITY_STREAM")
        );
        assert_eq!(attribute_type_name(0x1234), None);
    }

    #[test]
    fn attribute_type_codes_are_unique() {
        let codes: Vec<u32> = ATTRIBUTE_TYPES.iter().map(|(c, _)| *c).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "duplicate attribute type code");
    }

    #[test]
    fn well_known_record_numbers_resolve() {
        assert_eq!(mft_records::MFT, 0);
        assert_eq!(mft_records::ROOT, 5);
        assert_eq!(mft_records::EXTEND, 11);
        assert_eq!(mft_record_name(mft_records::MFT), Some("$MFT"));
        assert_eq!(
            mft_record_name(mft_records::ROOT),
            Some(". (root directory)")
        );
        assert_eq!(mft_record_name(mft_records::LOGFILE), Some("$LogFile"));
        assert_eq!(mft_record_name(99), None);
    }

    #[test]
    fn record_header_offsets_are_in_layout_order() {
        use mft_offsets as o;
        assert_eq!(o::SIGNATURE, 0x00);
        assert_eq!(o::USA_OFFSET, 0x04);
        assert_eq!(o::USA_COUNT, 0x06);
        assert_eq!(o::FLAGS, 0x16);
        assert_eq!(o::FIRST_ATTRIBUTE, 0x14);
        assert_eq!(o::BASE_RECORD, 0x20);
        assert!(o::SIGNATURE < o::USA_OFFSET && o::USA_OFFSET < o::USA_COUNT);
        assert!(o::FIRST_ATTRIBUTE < o::FLAGS && o::FLAGS < o::BASE_RECORD);
    }

    #[test]
    fn record_flags_are_distinct_single_bits() {
        let bits = [
            mft_flags::IN_USE,
            mft_flags::DIRECTORY,
            mft_flags::EXTENSION,
            mft_flags::VIEW_INDEX,
        ];
        for b in bits {
            assert_eq!(b.count_ones(), 1, "flag must be a single bit: {b:#06x}");
        }
        // No two flags share a bit.
        let or: u16 = bits.iter().fold(0, |a, b| a | b);
        assert_eq!(or.count_ones() as usize, bits.len());
    }

    #[test]
    fn filename_namespaces_resolve() {
        assert_eq!(filename_namespace::POSIX, 0);
        assert_eq!(filename_namespace::WIN32, 1);
        assert_eq!(filename_namespace::DOS, 2);
        assert_eq!(filename_namespace::WIN32_AND_DOS, 3);
        assert_eq!(
            filename_namespace::name(filename_namespace::DOS),
            Some("DOS")
        );
        assert_eq!(filename_namespace::name(9), None);
    }

    #[test]
    fn indx_signature_is_correct() {
        assert_eq!(&SIGNATURE_INDX, b"INDX");
    }

    #[test]
    fn file_attribute_flags_are_distinct_single_bits() {
        use file_attributes as fa;
        let bits = [
            fa::READONLY,
            fa::HIDDEN,
            fa::SYSTEM,
            fa::ARCHIVE,
            fa::TEMPORARY,
            fa::SPARSE_FILE,
            fa::REPARSE_POINT,
            fa::COMPRESSED,
            fa::ENCRYPTED,
        ];
        for b in bits {
            assert_eq!(b.count_ones(), 1, "flag must be a single bit: {b:#06x}");
        }
        let or: u32 = bits.iter().fold(0, |a, b| a | b);
        assert_eq!(or.count_ones() as usize, bits.len(), "flags overlap");
    }

    #[test]
    fn attribute_offsets_in_layout_order() {
        use attr_offsets as o;
        assert_eq!(o::TYPE, 0x00);
        assert_eq!(o::LENGTH, 0x04);
        assert_eq!(o::NON_RESIDENT, 0x08);
        assert_eq!(o::FLAGS, 0x0C);
        assert_eq!(o::ATTRIBUTE_ID, 0x0E);
        // Resident vs non-resident bodies both begin at 0x10.
        assert_eq!(o::RES_CONTENT_LENGTH, 0x10);
        assert_eq!(o::NR_START_VCN, 0x10);
        assert_eq!(o::NR_REAL_SIZE, 0x30);
        assert!(o::TYPE < o::LENGTH && o::LENGTH < o::NON_RESIDENT);
        assert!(o::NR_RUNS_OFFSET < o::NR_ALLOCATED_SIZE);
    }

    #[test]
    fn attribute_flags_are_single_bits() {
        for f in [
            attr_flags::COMPRESSED,
            attr_flags::ENCRYPTED,
            attr_flags::SPARSE,
        ] {
            assert_eq!(f.count_ones(), 1, "flag must be a single bit: {f:#06x}");
        }
    }

    #[test]
    fn boot_offsets_match_bpb_layout() {
        use boot_offsets as b;
        assert_eq!(b::OEM_ID, 0x03);
        assert_eq!(b::BYTES_PER_SECTOR, 0x0B);
        assert_eq!(b::SECTORS_PER_CLUSTER, 0x0D);
        assert_eq!(b::MFT_LCN, 0x30);
        assert_eq!(b::MFTMIRR_LCN, 0x38);
        assert_eq!(b::CLUSTERS_PER_RECORD, 0x40);
        assert_eq!(b::VOLUME_SERIAL, 0x48);
    }
}
