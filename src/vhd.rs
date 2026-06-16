//! Legacy Microsoft VHD (Virtual PC / Hyper-V Gen-1) format constants.
//!
//! Single source of truth for the cookies, footer geometry, and disk-type values
//! of the legacy VHD format: a 512-byte footer at end-of-file (`"conectix"`),
//! plus a `"cxsparse"` dynamic-disk header for sparse/differencing variants.
//!
//! Source: Microsoft Virtual Hard Disk Image Format Specification (VHD)
//!   https://www.microsoft.com/en-us/download/details.aspx?id=23850

/// 8-byte footer cookie `"conectix"` (present at end-of-file on every VHD; also
/// mirrored at offset 0 for dynamic/differencing disks).
pub const FOOTER_COOKIE: &[u8; 8] = b"conectix";
/// The footer is exactly 512 bytes.
pub const FOOTER_SIZE: usize = 512;

/// 8-byte cookie `"cxsparse"` at the start of the dynamic-disk header.
pub const DYNAMIC_HEADER_COOKIE: &[u8; 8] = b"cxsparse";
/// The dynamic header is exactly 1024 bytes.
pub const DYNAMIC_HEADER_SIZE: usize = 1024;

/// `fileFormatVersion` value for VHD 1.0 (`0x00010000`).
pub const CURRENT_VERSION: u32 = 0x0001_0000;

/// A fixed VHD has no dynamic header; its `dataOffset` field is all-ones.
pub const FIXED_DATA_OFFSET: u64 = u64::MAX;

/// Disk-type values (`diskType` at footer offset 0x3C).
pub const DISK_TYPE_FIXED: u32 = 2;
pub const DISK_TYPE_DYNAMIC: u32 = 3;
pub const DISK_TYPE_DIFFERENCING: u32 = 4;

/// Field offsets within the 512-byte VHD footer (all big-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VhdFooterOffsets {
    pub cookie: u64,              // 0x00  "conectix"
    pub features: u64,            // 0x08
    pub file_format_version: u64, // 0x0C  0x00010000
    pub data_offset: u64,         // 0x10  dynamic header offset (u64::MAX if fixed)
    pub timestamp: u64,           // 0x18  seconds since 2000-01-01
    pub current_size: u64,        // 0x30  virtual disk size in bytes
    pub disk_geometry: u64,       // 0x38  CHS
    pub disk_type: u64,           // 0x3C  2 | 3 | 4
    pub checksum: u64,            // 0x40  one's-complement of the footer
    pub unique_id: u64,           // 0x44  16-byte GUID
}

pub const FOOTER_OFFSETS: VhdFooterOffsets = VhdFooterOffsets {
    cookie: 0x00,
    features: 0x08,
    file_format_version: 0x0C,
    data_offset: 0x10,
    timestamp: 0x18,
    current_size: 0x30,
    disk_geometry: 0x38,
    disk_type: 0x3C,
    checksum: 0x40,
    unique_id: 0x44,
};

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
