//! Expert Witness Format (EWF / E01 / Ex01 / L01) constants.
//!
//! Single source of truth for the file signatures and section-type vocabulary of
//! the dominant professional forensic-acquisition container: EWF1 (`.E01`),
//! EWF2/Ex01, and the logical-evidence variants (`.L01`/`.Lx01`).
//!
//! Source: libewf documentation (EWF & EWF2 file format specs)
//!   <https://github.com/libyal/libewf/tree/main/documentation>

/// Length of every EWF file signature.
pub const SIGNATURE_LEN: usize = 8;

/// EWF1 file signature at offset 0: `"EVF"` + `0x09 0x0D 0x0A 0xFF 0x00`. (`.E01`)
pub const EVF1_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00];
/// EWF2 / Ex01 physical-evidence signature: `"EVF2"` + `0x0D 0x0A 0x81 0x00`.
pub const EVF2_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0D, 0x0A, 0x81, 0x00];
/// EWF2 / Lx01 logical-evidence signature: `"LEF2"` + `0x0D 0x0A 0x81 0x00`.
pub const LEF2_SIGNATURE: [u8; 8] = [0x4C, 0x45, 0x46, 0x32, 0x0D, 0x0A, 0x81, 0x00];

/// The EWF1 section-type vocabulary (the NUL-padded type string at the start of
/// each 76-byte section descriptor). Source: libewf `documentation/Expert Witness
/// Compression Format (EWF).asciidoc`.
pub const EWF1_SECTION_TYPES: &[&str] = &[
    "header", "header2", "volume", "disk", "table", "table2", "sectors", "data", "digest", "hash",
    "error2", "session", "next", "done",
];

/// `compression_level` byte values stored in the volume/data section.
pub const COMPRESSION_NONE: u8 = 0;
pub const COMPRESSION_FAST: u8 = 1;
pub const COMPRESSION_BEST: u8 = 2;

/// In an EWF1 chunk-offset table, the most-significant bit of each 32-bit offset
/// flags a zlib-compressed chunk; the remaining 31 bits are the file offset.
pub const TABLE_ENTRY_COMPRESSED_FLAG: u32 = 0x8000_0000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evf1_signature() {
        // "EVF" + 0x09 0x0D 0x0A 0xFF 0x00 — the classic E01 signature at offset 0.
        assert_eq!(
            EVF1_SIGNATURE,
            [0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00]
        );
        assert_eq!(&EVF1_SIGNATURE[0..3], b"EVF");
    }

    #[test]
    fn evf2_and_lef2_signatures() {
        assert_eq!(
            EVF2_SIGNATURE,
            [0x45, 0x56, 0x46, 0x32, 0x0D, 0x0A, 0x81, 0x00]
        );
        assert_eq!(
            LEF2_SIGNATURE,
            [0x4C, 0x45, 0x46, 0x32, 0x0D, 0x0A, 0x81, 0x00]
        );
        assert_eq!(&EVF2_SIGNATURE[0..4], b"EVF2");
        assert_eq!(&LEF2_SIGNATURE[0..4], b"LEF2");
    }

    #[test]
    fn signatures_are_eight_bytes() {
        assert_eq!(SIGNATURE_LEN, 8);
        assert_eq!(EVF1_SIGNATURE.len(), SIGNATURE_LEN);
    }

    #[test]
    fn ewf1_section_types_present() {
        for s in [
            "header", "header2", "volume", "disk", "table", "sectors", "done", "next",
        ] {
            assert!(EWF1_SECTION_TYPES.contains(&s), "missing section type {s}");
        }
    }

    #[test]
    fn compression_levels() {
        assert_eq!(COMPRESSION_NONE, 0);
        assert_eq!(COMPRESSION_FAST, 1);
        assert_eq!(COMPRESSION_BEST, 2);
    }

    #[test]
    fn table_entry_compressed_flag() {
        // In an EWF1 table, the top bit of a 32-bit chunk offset marks compression.
        assert_eq!(TABLE_ENTRY_COMPRESSED_FLAG, 0x8000_0000);
    }
}
