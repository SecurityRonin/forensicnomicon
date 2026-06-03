//! VMware VMDK disk-image format constants and offset layouts.
//!
//! Single source of truth for the magic numbers, header field offsets, version
//! values, and grain-encoding rules of every VMDK variant: the VMDK4 sparse
//! format (`monolithicSparse`, `streamOptimized`), the ESXi COWD format
//! (`vmfsSparse`/`vmfsThin`), and the vSphere 6.5+ seSparse format. Parser crates
//! (e.g. SecurityRonin's `vmdk` reader) and carvers re-export from here rather
//! than defining their own copies.
//!
//! Source: VMware Virtual Disk Format 1.1 (libyal reconstruction)
//!   https://github.com/libyal/libvmdk/blob/main/documentation/VMware%20Virtual%20Disk%20Format%20(VMDK).asciidoc
//! Source: QEMU `block/vmdk.c`
//!   https://github.com/qemu/qemu/blob/master/block/vmdk.c

// (implementation added in the GREEN commit)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmdk4_magic_is_kdmv() {
        // On disk the VMDK4 sparse header starts with "KDMV" (little-endian "VMDK").
        assert_eq!(VMDK4_MAGIC, 0x564D_444B);
        assert_eq!(&VMDK4_MAGIC.to_le_bytes(), b"KDMV");
    }

    #[test]
    fn cowd_magic_is_cowd_big_endian() {
        // COWD (ESXi vmfsSparse/vmfsThin) magic is stored big-endian: bytes "COWD".
        assert_eq!(COWD_MAGIC, 0x434F_5744);
        assert_eq!(&COWD_MAGIC.to_be_bytes(), b"COWD");
    }

    #[test]
    fn sesparse_magics_and_version() {
        assert_eq!(SESPARSE_CONST_MAGIC, 0x0000_0000_CAFE_BABE);
        assert_eq!(SESPARSE_VOLATILE_MAGIC, 0x0000_0000_CAFE_CAFE);
        assert_eq!(SESPARSE_VERSION, 0x0000_0002_0000_0001);
    }

    #[test]
    fn header_versions() {
        assert_eq!(VERSION_BASE, 1);
        assert_eq!(VERSION_ZEROED_GRAIN, 2);
        assert_eq!(VERSION_STREAM_OPTIMIZED, 3);
    }

    #[test]
    fn sector_size_and_gd_at_end_sentinel() {
        assert_eq!(SECTOR_SIZE, 512);
        assert_eq!(GD_AT_END, u64::MAX);
    }

    #[test]
    fn vmdk4_header_offsets() {
        assert_eq!(VMDK4_HEADER_OFFSETS.magic, 0x00);
        assert_eq!(VMDK4_HEADER_OFFSETS.version, 0x04);
        assert_eq!(VMDK4_HEADER_OFFSETS.flags, 0x08);
        assert_eq!(VMDK4_HEADER_OFFSETS.capacity, 0x0C);
        assert_eq!(VMDK4_HEADER_OFFSETS.grain_size, 0x14);
        assert_eq!(VMDK4_HEADER_OFFSETS.descriptor_offset, 0x1C);
        assert_eq!(VMDK4_HEADER_OFFSETS.descriptor_size, 0x24);
        assert_eq!(VMDK4_HEADER_OFFSETS.num_gtes_per_gt, 0x2C);
        assert_eq!(VMDK4_HEADER_OFFSETS.rgd_offset, 0x30);
        assert_eq!(VMDK4_HEADER_OFFSETS.gd_offset, 0x38);
        assert_eq!(VMDK4_HEADER_OFFSETS.overhead, 0x40);
        assert_eq!(VMDK4_HEADER_OFFSETS.compress_algorithm, 0x4D);
    }

    #[test]
    fn vmdk4_flags_and_compression() {
        assert_eq!(VMDK4_FLAG_VALID_NEWLINE, 0x0000_0001);
        assert_eq!(VMDK4_FLAG_USE_RGD, 0x0000_0002);
        assert_eq!(VMDK4_FLAG_ZERO_GRAIN, 0x0000_0004);
        assert_eq!(VMDK4_FLAG_COMPRESSED, 0x0001_0000);
        assert_eq!(VMDK4_FLAG_MARKERS, 0x0002_0000);
        assert_eq!(COMPRESSION_NONE, 0);
        assert_eq!(COMPRESSION_DEFLATE, 1);
    }

    #[test]
    fn grain_marker_layout() {
        // streamOptimized grain marker: u64 LBA + u32 dataSize, then the zlib payload.
        assert_eq!(GRAIN_MARKER_HEADER_SIZE, 12);
        assert_eq!(GRAIN_MARKER_OFFSETS.lba, 0x00);
        assert_eq!(GRAIN_MARKER_OFFSETS.data_size, 0x08);
    }

    #[test]
    fn grain_table_entry_sentinels() {
        assert_eq!(GTE_SPARSE, 0);
        assert_eq!(GTE_ZEROED, 1);
    }

    #[test]
    fn cowd_layout() {
        assert_eq!(COWD_HEADER_OFFSETS.magic, 0x00);
        assert_eq!(COWD_HEADER_OFFSETS.version, 0x04);
        assert_eq!(COWD_HEADER_OFFSETS.capacity, 0x0C);
        assert_eq!(COWD_HEADER_OFFSETS.grain_size, 0x10);
        assert_eq!(COWD_HEADER_OFFSETS.gd_offset, 0x14);
        assert_eq!(COWD_HEADER_OFFSETS.gd_entries, 0x18);
        assert_eq!(COWD_GRAIN_DIRECTORY_SECTOR, 4);
        assert_eq!(COWD_GTES_PER_GRAIN_TABLE, 4096);
    }

    #[test]
    fn sesparse_const_header_layout() {
        assert_eq!(SESPARSE_HEADER_OFFSETS.magic, 0x00);
        assert_eq!(SESPARSE_HEADER_OFFSETS.version, 0x08);
        assert_eq!(SESPARSE_HEADER_OFFSETS.capacity, 0x10);
        assert_eq!(SESPARSE_HEADER_OFFSETS.grain_size, 0x18);
        assert_eq!(SESPARSE_HEADER_OFFSETS.grain_table_size, 0x20);
        assert_eq!(SESPARSE_HEADER_OFFSETS.grain_dir_offset, 0x80);
        assert_eq!(SESPARSE_HEADER_OFFSETS.grain_tables_offset, 0x90);
        assert_eq!(SESPARSE_HEADER_OFFSETS.grains_offset, 0xC0);
        // Fixed geometry per the format.
        assert_eq!(SESPARSE_GRAIN_SECTORS, 8);
        assert_eq!(SESPARSE_GRAIN_TABLE_SECTORS, 64);
        assert_eq!(SESPARSE_GTES_PER_GRAIN_TABLE, 4096);
    }

    #[test]
    fn sesparse_grain_directory_encoding() {
        // High 32 bits of an allocated L1/GD entry must be 0x10000000.
        assert_eq!(SESPARSE_GD_ALLOC_MASK, 0xFFFF_FFFF_0000_0000);
        assert_eq!(SESPARSE_GD_ALLOC_FLAG, 0x1000_0000_0000_0000);
        assert_eq!(SESPARSE_GD_INDEX_MASK, 0x0000_0000_FFFF_FFFF);
    }

    #[test]
    fn sesparse_grain_table_entry_types() {
        assert_eq!(SESPARSE_GTE_TYPE_MASK, 0xF000_0000_0000_0000);
        assert_eq!(SESPARSE_GTE_UNALLOCATED, 0x0000_0000_0000_0000);
        assert_eq!(SESPARSE_GTE_SCSI_UNMAPPED, 0x1000_0000_0000_0000);
        assert_eq!(SESPARSE_GTE_ZERO, 0x2000_0000_0000_0000);
        assert_eq!(SESPARSE_GTE_ALLOCATED, 0x3000_0000_0000_0000);
    }

    #[test]
    fn sesparse_grain_index_bit_rotation_round_trips() {
        // The allocated-grain index is split across the entry: top 12 bits become the
        // low 12 bits, the low 48 bits shift up by 12. Decoding must round-trip.
        for idx in [0u64, 1, 42, 0xFFF, 0x1000, 0x000F_FFFF, 0x0FFF_FFFF_FFFF] {
            let entry = sesparse_encode_allocated_grain(idx);
            assert_eq!(entry & SESPARSE_GTE_TYPE_MASK, SESPARSE_GTE_ALLOCATED);
            assert_eq!(sesparse_decode_grain_index(entry), idx, "idx {idx:#x}");
        }
    }

    #[test]
    fn create_type_enumeration_is_complete() {
        // The full VMware/QEMU/libvmdk createType set (18 values).
        assert_eq!(CREATE_TYPES.len(), 18);
        for t in [
            "monolithicSparse",
            "monolithicFlat",
            "twoGbMaxExtentSparse",
            "twoGbMaxExtentFlat",
            "vmfs",
            "vmfsPreallocated",
            "vmfsEagerZeroedThick",
            "vmfsSparse",
            "vmfsThin",
            "seSparse",
            "streamOptimized",
            "vmfsRDM",
            "vmfsRaw",
            "vmfsRawDeviceMap",
            "vmfsPassthroughRawDeviceMap",
            "fullDevice",
            "partitionedDevice",
            "custom",
        ] {
            assert!(CREATE_TYPES.contains(&t), "missing createType {t}");
        }
    }

    #[test]
    fn extent_type_and_access_enumeration() {
        for t in ["FLAT", "VMFS", "VMFSRAW", "ZERO", "SPARSE", "VMFSSPARSE", "SESPARSE"] {
            assert!(EXTENT_TYPES.contains(&t), "missing extent type {t}");
        }
        assert_eq!(EXTENT_ACCESS_MODES, &["RW", "RDONLY", "NOACCESS"]);
    }
}
