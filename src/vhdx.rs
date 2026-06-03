//! Microsoft VHDX disk-image format constants and offset layouts.
//!
//! Single source of truth for the magic identifiers, fixed section offsets, and
//! header geometry of the Hyper-V VHDX format (Windows 8+, WSL2, Azure).
//!
//! Source: [MS-VHDX] Virtual Hard Disk v2 File Format
//!   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/

/// 8-byte file type identifier at offset 0: ASCII `"vhdxfile"`.
pub const FILE_IDENTIFIER: &[u8; 8] = b"vhdxfile";
pub const FILE_IDENTIFIER_OFFSET: u64 = 0;

/// 4-byte signature `"head"` at the start of each header block.
pub const HEADER_SIGNATURE: &[u8; 4] = b"head";
/// Each header block occupies a 4 KiB-aligned 64 KiB slot but the structure is 4096 bytes.
pub const HEADER_SIZE: usize = 4096;

/// 4-byte signature `"regi"` at the start of each region table.
pub const REGION_TABLE_SIGNATURE: &[u8; 4] = b"regi";

// Fixed section offsets within the first 1 MiB "header section" (MS-VHDX §2.1).
pub const HEADER1_OFFSET: u64 = 0x0001_0000; // 64 KiB
pub const HEADER2_OFFSET: u64 = 0x0002_0000; // 128 KiB
pub const REGION_TABLE1_OFFSET: u64 = 0x0003_0000; // 192 KiB
pub const REGION_TABLE2_OFFSET: u64 = 0x0004_0000; // 256 KiB

/// VHDX checksums are CRC-32C (Castagnoli); this is the reversed polynomial.
pub const CRC32C_POLYNOMIAL: u32 = 0x82F6_3B78;

/// The two well-known region GUIDs that locate the Block Allocation Table and the
/// Metadata region (16-byte little-endian GUIDs). Source: MS-VHDX §2.3.
pub const REGION_GUIDS: &[(&str, [u8; 16])] = &[
    (
        "BAT",
        [
            0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD,
            0x4A, 0x08,
        ],
    ),
    (
        "Metadata",
        [
            0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F,
            0x88, 0x6E,
        ],
    ),
];

/// Block Allocation Table entry state values (low 3 bits of each 64-bit BAT entry).
/// Source: MS-VHDX §2.5.2.
pub const PAYLOAD_BLOCK_NOT_PRESENT: u64 = 0;
pub const PAYLOAD_BLOCK_UNDEFINED: u64 = 1;
pub const PAYLOAD_BLOCK_ZERO: u64 = 2;
pub const PAYLOAD_BLOCK_UNMAPPED: u64 = 3;
pub const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;
pub const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u64 = 7;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_identifier_is_vhdxfile() {
        assert_eq!(FILE_IDENTIFIER, b"vhdxfile");
        assert_eq!(FILE_IDENTIFIER_OFFSET, 0);
    }

    #[test]
    fn header_signature_and_size() {
        assert_eq!(HEADER_SIGNATURE, b"head");
        assert_eq!(HEADER_SIZE, 4096);
    }

    #[test]
    fn fixed_section_offsets() {
        assert_eq!(HEADER1_OFFSET, 0x0001_0000); // 64 KiB
        assert_eq!(HEADER2_OFFSET, 0x0002_0000); // 128 KiB
        assert_eq!(REGION_TABLE1_OFFSET, 0x0003_0000); // 192 KiB
        assert_eq!(REGION_TABLE2_OFFSET, 0x0004_0000); // 256 KiB
        assert_eq!(REGION_TABLE_SIGNATURE, b"regi");
    }

    #[test]
    fn crc32c_polynomial() {
        // VHDX checksums use CRC-32C (Castagnoli), reversed polynomial 0x82F63B78.
        assert_eq!(CRC32C_POLYNOMIAL, 0x82F6_3B78);
    }

    #[test]
    fn known_region_guids_present() {
        assert_eq!(REGION_GUIDS.len(), 2);
        assert!(REGION_GUIDS.iter().any(|(name, _)| *name == "BAT"));
        assert!(REGION_GUIDS.iter().any(|(name, _)| *name == "Metadata"));
    }

    #[test]
    fn block_state_values() {
        assert_eq!(PAYLOAD_BLOCK_NOT_PRESENT, 0);
        assert_eq!(PAYLOAD_BLOCK_FULLY_PRESENT, 6);
        assert_eq!(PAYLOAD_BLOCK_PARTIALLY_PRESENT, 7);
    }
}
