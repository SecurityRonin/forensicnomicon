//! QEMU QCOW2 disk-image format constants and offset layouts.
//!
//! Single source of truth for the magic, version, header field offsets, and
//! feature flags of the QCOW2 v2/v3 format (QEMU / KVM / libvirt). All multi-byte
//! header fields are big-endian.
//!
//! Source: QEMU `docs/interop/qcow2.txt`
//!   https://github.com/qemu/qemu/blob/master/docs/interop/qcow2.txt

/// Magic `"QFI\xfb"` read as a big-endian `u32` at offset 0.
pub const MAGIC: u32 = 0x5146_49FB;

/// Supported header versions.
pub const VERSION_MIN: u32 = 2;
pub const VERSION_MAX: u32 = 3;
/// Length of the fixed v2 header (v3 extends it; this is the minimum to parse).
pub const V2_HEADER_SIZE: usize = 72;

/// `cluster_bits` valid range (QEMU `MIN_CLUSTER_BITS`..=`MAX_CLUSTER_BITS`):
/// 512 B (2^9) to 2 MiB (2^21) clusters.
pub const CLUSTER_BITS_MIN: u32 = 9;
pub const CLUSTER_BITS_MAX: u32 = 21;

/// `crypt_method` values (header offset 0x20).
pub const CRYPT_NONE: u32 = 0;
pub const CRYPT_AES: u32 = 1;
pub const CRYPT_LUKS: u32 = 2;

/// Incompatible feature bits (`incompatible_features`, header offset 0x48, v3+).
/// A reader that does not understand a set bit must refuse the image.
pub const INCOMPAT_DIRTY: u64 = 1 << 0;
pub const INCOMPAT_CORRUPT: u64 = 1 << 1;
pub const INCOMPAT_EXTERNAL_DATA: u64 = 1 << 2;
pub const INCOMPAT_COMPRESSION_TYPE: u64 = 1 << 3;
pub const INCOMPAT_EXTENDED_L2: u64 = 1 << 4;

/// L1/L2 table entry flags.
/// Bit 63 (`COPIED`): the referenced cluster has refcount exactly 1.
/// Bit 62 (`COMPRESSED`): the L2 entry points to a zlib-compressed cluster.
pub const L1_ENTRY_COPIED: u64 = 1 << 63;
pub const L2_ENTRY_COMPRESSED: u64 = 1 << 62;

/// Field offsets within the QCOW2 header (all big-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Qcow2HeaderOffsets {
    pub magic: u64,                 // 0x00 u32
    pub version: u64,               // 0x04 u32  2 | 3
    pub backing_file_offset: u64,   // 0x08 u64
    pub backing_file_size: u64,     // 0x10 u32
    pub cluster_bits: u64,          // 0x14 u32
    pub size: u64,                  // 0x18 u64  virtual disk size in bytes
    pub crypt_method: u64,          // 0x20 u32
    pub l1_size: u64,               // 0x24 u32  number of L1 entries
    pub l1_table_offset: u64,       // 0x28 u64
    pub refcount_table_offset: u64, // 0x30 u64
    pub incompatible_features: u64, // 0x48 u64  (v3)
}

pub const HEADER_OFFSETS: Qcow2HeaderOffsets = Qcow2HeaderOffsets {
    magic: 0x00,
    version: 0x04,
    backing_file_offset: 0x08,
    backing_file_size: 0x10,
    cluster_bits: 0x14,
    size: 0x18,
    crypt_method: 0x20,
    l1_size: 0x24,
    l1_table_offset: 0x28,
    refcount_table_offset: 0x30,
    incompatible_features: 0x48,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_is_qfi_big_endian() {
        // "QFI\xfb" read as a big-endian u32.
        assert_eq!(MAGIC, 0x5146_49FB);
        assert_eq!(&MAGIC.to_be_bytes(), b"QFI\xfb");
    }

    #[test]
    fn supported_versions_and_min_header() {
        assert_eq!(VERSION_MIN, 2);
        assert_eq!(VERSION_MAX, 3);
        assert_eq!(V2_HEADER_SIZE, 72);
    }

    #[test]
    fn cluster_bits_range() {
        assert_eq!(CLUSTER_BITS_MIN, 9);
        assert_eq!(CLUSTER_BITS_MAX, 21);
    }

    #[test]
    fn header_offsets() {
        assert_eq!(HEADER_OFFSETS.magic, 0x00);
        assert_eq!(HEADER_OFFSETS.version, 0x04);
        assert_eq!(HEADER_OFFSETS.backing_file_offset, 0x08);
        assert_eq!(HEADER_OFFSETS.backing_file_size, 0x10);
        assert_eq!(HEADER_OFFSETS.cluster_bits, 0x14);
        assert_eq!(HEADER_OFFSETS.size, 0x18);
        assert_eq!(HEADER_OFFSETS.crypt_method, 0x20);
        assert_eq!(HEADER_OFFSETS.l1_size, 0x24);
        assert_eq!(HEADER_OFFSETS.l1_table_offset, 0x28);
        assert_eq!(HEADER_OFFSETS.refcount_table_offset, 0x30);
        assert_eq!(HEADER_OFFSETS.incompatible_features, 0x48);
    }

    #[test]
    fn crypt_methods() {
        assert_eq!(CRYPT_NONE, 0);
        assert_eq!(CRYPT_AES, 1);
        assert_eq!(CRYPT_LUKS, 2);
    }

    #[test]
    fn incompatible_feature_bits() {
        assert_eq!(INCOMPAT_DIRTY, 1 << 0);
        assert_eq!(INCOMPAT_CORRUPT, 1 << 1);
        assert_eq!(INCOMPAT_EXTERNAL_DATA, 1 << 2);
        assert_eq!(INCOMPAT_COMPRESSION_TYPE, 1 << 3);
        assert_eq!(INCOMPAT_EXTENDED_L2, 1 << 4);
    }

    #[test]
    fn l1_l2_entry_flags() {
        // Bit 63 marks a copied (refcount == 1) entry; bit 62 marks a compressed cluster.
        assert_eq!(L1_ENTRY_COPIED, 1 << 63);
        assert_eq!(L2_ENTRY_COMPRESSED, 1 << 62);
    }
}
