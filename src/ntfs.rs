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
        assert_eq!(attribute_type_name(attr_types::STANDARD_INFORMATION), Some("$STANDARD_INFORMATION"));
        assert_eq!(attribute_type_name(attr_types::FILE_NAME), Some("$FILE_NAME"));
        assert_eq!(attribute_type_name(attr_types::DATA), Some("$DATA"));
        assert_eq!(attribute_type_name(attr_types::INDEX_ROOT), Some("$INDEX_ROOT"));
        assert_eq!(attribute_type_name(attr_types::LOGGED_UTILITY_STREAM), Some("$LOGGED_UTILITY_STREAM"));
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
        assert_eq!(mft_record_name(mft_records::ROOT), Some(". (root directory)"));
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
        assert_eq!(filename_namespace::name(filename_namespace::DOS), Some("DOS"));
        assert_eq!(filename_namespace::name(9), None);
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
