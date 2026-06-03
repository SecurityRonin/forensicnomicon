//! Legacy Microsoft VHD (Virtual PC / Hyper-V Gen-1) format constants.
//!
//! Single source of truth for the cookies, footer geometry, and disk-type values
//! of the legacy VHD format: a 512-byte footer at end-of-file (`"conectix"`),
//! plus a `"cxsparse"` dynamic-disk header for sparse/differencing variants.
//!
//! Source: Microsoft Virtual Hard Disk Image Format Specification (VHD)
//!   https://www.microsoft.com/en-us/download/details.aspx?id=23850

// (implementation added in the GREEN commit)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footer_cookie_and_size() {
        assert_eq!(FOOTER_COOKIE, b"conectix");
        assert_eq!(FOOTER_SIZE, 512);
    }

    #[test]
    fn dynamic_header_cookie() {
        assert_eq!(DYNAMIC_HEADER_COOKIE, b"cxsparse");
        assert_eq!(DYNAMIC_HEADER_SIZE, 1024);
    }

    #[test]
    fn current_version() {
        assert_eq!(CURRENT_VERSION, 0x0001_0000);
    }

    #[test]
    fn footer_offsets() {
        assert_eq!(FOOTER_OFFSETS.cookie, 0x00);
        assert_eq!(FOOTER_OFFSETS.features, 0x08);
        assert_eq!(FOOTER_OFFSETS.file_format_version, 0x0C);
        assert_eq!(FOOTER_OFFSETS.data_offset, 0x10);
        assert_eq!(FOOTER_OFFSETS.current_size, 0x30);
        assert_eq!(FOOTER_OFFSETS.disk_type, 0x3C);
        assert_eq!(FOOTER_OFFSETS.checksum, 0x40);
    }

    #[test]
    fn disk_type_values() {
        assert_eq!(DISK_TYPE_FIXED, 2);
        assert_eq!(DISK_TYPE_DYNAMIC, 3);
        assert_eq!(DISK_TYPE_DIFFERENCING, 4);
    }

    #[test]
    fn fixed_disk_data_offset_sentinel() {
        // A fixed VHD has no dynamic header; its data_offset is all-ones.
        assert_eq!(FIXED_DATA_OFFSET, u64::MAX);
    }
}
