//! Microsoft VHDX disk-image format constants and offset layouts.
//!
//! Single source of truth for the magic identifiers, fixed section offsets, and
//! header geometry of the Hyper-V VHDX format (Windows 8+, WSL2, Azure).
//!
//! Source: [MS-VHDX] Virtual Hard Disk v2 File Format
//!   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/

// (implementation added in the GREEN commit)

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
