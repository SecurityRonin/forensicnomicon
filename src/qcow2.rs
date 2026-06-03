//! QEMU QCOW2 disk-image format constants and offset layouts.
//!
//! Single source of truth for the magic, version, header field offsets, and
//! feature flags of the QCOW2 v2/v3 format (QEMU / KVM / libvirt). All multi-byte
//! header fields are big-endian.
//!
//! Source: QEMU `docs/interop/qcow2.txt`
//!   https://github.com/qemu/qemu/blob/master/docs/interop/qcow2.txt

// (implementation added in the GREEN commit)

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
