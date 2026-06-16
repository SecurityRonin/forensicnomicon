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

/// Sector size used throughout the format (all sector fields multiply by this).
pub const SECTOR_SIZE: u64 = 512;

// ── VMDK4 sparse header (monolithicSparse / streamOptimized) ──────────────────

/// VMDK4 sparse extent magic, read as a little-endian `u32` at offset 0.
/// On disk the four bytes are `"KDMV"` (the ASCII of "VMDK" reversed).
/// Source: https://github.com/libyal/libvmdk (VMDK 4 `_VMDK_SPARSE_EXTENT_HEADER`)
pub const VMDK4_MAGIC: u32 = 0x564D_444B;

/// Header version 1 — base monolithicSparse.
pub const VERSION_BASE: u32 = 1;
/// Header version 2 — adds the zeroed-grain feature (GTE == 1 → explicit zero).
pub const VERSION_ZEROED_GRAIN: u32 = 2;
/// Header version 3 — streamOptimized (compressed grains + markers).
pub const VERSION_STREAM_OPTIMIZED: u32 = 3;

/// Sentinel `gdOffset` value in a streamOptimized *primary* header; the real grain
/// directory offset lives in the *footer* header at `file_end - 1024` (VDF 1.1 §4.6).
pub const GD_AT_END: u64 = u64::MAX;

/// Header flag bits (`flags` field at offset 0x08).
/// Source: QEMU `block/vmdk.c` (`VMDK4_FLAG_*`).
pub const VMDK4_FLAG_VALID_NEWLINE: u32 = 0x0000_0001;
pub const VMDK4_FLAG_USE_RGD: u32 = 0x0000_0002;
pub const VMDK4_FLAG_ZERO_GRAIN: u32 = 0x0000_0004;
pub const VMDK4_FLAG_COMPRESSED: u32 = 0x0001_0000;
pub const VMDK4_FLAG_MARKERS: u32 = 0x0002_0000;

/// `compressAlgorithm` field values (offset 0x4D, `u16`).
pub const COMPRESSION_NONE: u16 = 0;
/// DEFLATE. NB: VDF 1.1 §4.4 calls this RFC 1951 (raw DEFLATE), but VMware and QEMU
/// actually emit RFC 1950 (zlib: 2-byte header + DEFLATE + Adler-32) — use a zlib
/// decoder, not a raw-DEFLATE decoder. Source: QEMU `block/vmdk.c` decompress path.
pub const COMPRESSION_DEFLATE: u16 = 1;

/// Grain-table entry sentinels (each entry is a `u32` sector number).
/// `0` = unallocated (sparse → read parent or zeros); `1` = explicitly zeroed
/// (only meaningful when `VMDK4_FLAG_ZERO_GRAIN` is set); otherwise a sector offset.
pub const GTE_SPARSE: u32 = 0;
pub const GTE_ZEROED: u32 = 1;

/// streamOptimized grain marker header size: `u64 lba` + `u32 dataSize`.
pub const GRAIN_MARKER_HEADER_SIZE: u64 = 12;

/// Field offsets within the 512-byte VMDK4 sparse extent header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Vmdk4HeaderOffsets {
    pub magic: u64,              // 0x00 u32  "KDMV"
    pub version: u64,            // 0x04 u32  1 | 2 | 3
    pub flags: u64,              // 0x08 u32
    pub capacity: u64,           // 0x0C u64  virtual size in sectors
    pub grain_size: u64,         // 0x14 u64  grain size in sectors
    pub descriptor_offset: u64,  // 0x1C u64  embedded descriptor (sectors)
    pub descriptor_size: u64,    // 0x24 u64
    pub num_gtes_per_gt: u64,    // 0x2C u32  grain-table entries per table
    pub rgd_offset: u64,         // 0x30 u64  redundant grain directory (sectors)
    pub gd_offset: u64,          // 0x38 u64  primary grain directory (sectors)
    pub overhead: u64,           // 0x40 u64  metadata overhead / first grain sector
    pub compress_algorithm: u64, // 0x4D u16
}

pub const VMDK4_HEADER_OFFSETS: Vmdk4HeaderOffsets = Vmdk4HeaderOffsets {
    magic: 0x00,
    version: 0x04,
    flags: 0x08,
    capacity: 0x0C,
    grain_size: 0x14,
    descriptor_offset: 0x1C,
    descriptor_size: 0x24,
    num_gtes_per_gt: 0x2C,
    rgd_offset: 0x30,
    gd_offset: 0x38,
    overhead: 0x40,
    compress_algorithm: 0x4D,
};

/// Field offsets within the 12-byte streamOptimized grain marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GrainMarkerOffsets {
    pub lba: u64,       // 0x00 u64  virtual sector of this grain
    pub data_size: u64, // 0x08 u32  compressed payload length (zlib)
}

pub const GRAIN_MARKER_OFFSETS: GrainMarkerOffsets = GrainMarkerOffsets {
    lba: 0x00,
    data_size: 0x08,
};

// ── COWD (ESXi vmfsSparse / vmfsThin redo-log) ────────────────────────────────

/// COWD sparse extent magic, read as a *big-endian* `u32` at offset 0: bytes `"COWD"`.
/// All other COWD fields are little-endian `u32`. Source: libvmdk `cowd_sparse_file_header.h`.
pub const COWD_MAGIC: u32 = 0x434F_5744;

/// The grain directory always begins at sector 4 in a COWD file.
pub const COWD_GRAIN_DIRECTORY_SECTOR: u32 = 4;
/// COWD grain tables hold a fixed 4096 entries (vs the configurable VMDK4 default of 512).
pub const COWD_GTES_PER_GRAIN_TABLE: u32 = 4096;

/// Field offsets within the COWD sparse header (all little-endian `u32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CowdHeaderOffsets {
    pub magic: u64,      // 0x00 u32  big-endian "COWD"
    pub version: u64,    // 0x04 u32  always 1
    pub flags: u64,      // 0x08 u32
    pub capacity: u64,   // 0x0C u32  max data sectors (32-bit)
    pub grain_size: u64, // 0x10 u32  sectors per grain
    pub gd_offset: u64,  // 0x14 u32  grain-directory sector (always 4)
    pub gd_entries: u64, // 0x18 u32  number of grain-directory entries
    pub next_free: u64,  // 0x1C u32  next free sector
}

pub const COWD_HEADER_OFFSETS: CowdHeaderOffsets = CowdHeaderOffsets {
    magic: 0x00,
    version: 0x04,
    flags: 0x08,
    capacity: 0x0C,
    grain_size: 0x10,
    gd_offset: 0x14,
    gd_entries: 0x18,
    next_free: 0x1C,
};

// ── seSparse (vSphere 6.5+ VMFS6 space-efficient sparse) ──────────────────────

/// seSparse *constant* header magic (`u64` little-endian at offset 0).
pub const SESPARSE_CONST_MAGIC: u64 = 0x0000_0000_CAFE_BABE;
/// seSparse *volatile* header magic (sector 1 of the extent).
pub const SESPARSE_VOLATILE_MAGIC: u64 = 0x0000_0000_CAFE_CAFE;
/// The only accepted seSparse version value. Source: QEMU `check_se_sparse_const_header`.
pub const SESPARSE_VERSION: u64 = 0x0000_0002_0000_0001;

/// seSparse grain size is fixed at 8 sectors (4 KiB).
pub const SESPARSE_GRAIN_SECTORS: u64 = 8;
/// seSparse grain table size is fixed at 64 sectors …
pub const SESPARSE_GRAIN_TABLE_SECTORS: u64 = 64;
/// … which is exactly 4096 eight-byte entries (64 × 512 ÷ 8).
pub const SESPARSE_GTES_PER_GRAIN_TABLE: u64 = 4096;

/// Field offsets within the 512-byte seSparse constant header (all `u64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SeSparseHeaderOffsets {
    pub magic: u64,               // 0x00  0xCAFEBABE
    pub version: u64,             // 0x08  0x0000000200000001
    pub capacity: u64,            // 0x10  virtual size in sectors
    pub grain_size: u64,          // 0x18  must be 8
    pub grain_table_size: u64,    // 0x20  must be 64
    pub grain_dir_offset: u64,    // 0x80  grain directory (sectors)
    pub grain_tables_offset: u64, // 0x90  grain tables region (sectors)
    pub grains_offset: u64,       // 0xC0  grain data region (sectors)
}

pub const SESPARSE_HEADER_OFFSETS: SeSparseHeaderOffsets = SeSparseHeaderOffsets {
    magic: 0x00,
    version: 0x08,
    capacity: 0x10,
    grain_size: 0x18,
    grain_table_size: 0x20,
    grain_dir_offset: 0x80,
    grain_tables_offset: 0x90,
    grains_offset: 0xC0,
};

/// seSparse L1 (grain directory) entry encoding.
/// An allocated entry's high 32 bits must equal `0x10000000`; its low 32 bits are the
/// grain-table index (GT sector = `grain_tables_offset + index * grain_table_size`).
pub const SESPARSE_GD_ALLOC_MASK: u64 = 0xFFFF_FFFF_0000_0000;
pub const SESPARSE_GD_ALLOC_FLAG: u64 = 0x1000_0000_0000_0000;
pub const SESPARSE_GD_INDEX_MASK: u64 = 0x0000_0000_FFFF_FFFF;

/// seSparse L2 (grain table) entry types — the top nibble selects the type.
pub const SESPARSE_GTE_TYPE_MASK: u64 = 0xF000_0000_0000_0000;
pub const SESPARSE_GTE_UNALLOCATED: u64 = 0x0000_0000_0000_0000;
pub const SESPARSE_GTE_SCSI_UNMAPPED: u64 = 0x1000_0000_0000_0000; // read as zero
pub const SESPARSE_GTE_ZERO: u64 = 0x2000_0000_0000_0000; // read as zero
pub const SESPARSE_GTE_ALLOCATED: u64 = 0x3000_0000_0000_0000;

/// Decode the bit-rotated grain index from an *allocated* seSparse L2 entry.
///
/// The 60-bit grain index is stored split: the top 12 bits (entry bits 48..60)
/// become the low 12 bits, and the low 48 bits shift up by 12.
/// Source: QEMU `block/vmdk.c` `vmdk_get_cluster_offset` (sesparse branch).
#[must_use]
pub const fn sesparse_decode_grain_index(entry: u64) -> u64 {
    ((entry & 0x0FFF_0000_0000_0000) >> 48) | ((entry & 0x0000_FFFF_FFFF_FFFF) << 12)
}

/// Build an *allocated* seSparse L2 entry for `grain_index` (inverse of
/// [`sesparse_decode_grain_index`]); the `0x3` type nibble is set.
#[must_use]
pub const fn sesparse_encode_allocated_grain(grain_index: u64) -> u64 {
    let lo12 = grain_index & 0x0000_0000_0000_0FFF;
    let hi = (grain_index >> 12) & 0x0000_FFFF_FFFF_FFFF;
    SESPARSE_GTE_ALLOCATED | (lo12 << 48) | hi
}

// ── createType / extent-type enumeration ──────────────────────────────────────

/// Every VMDK `createType` defined by VMware / QEMU / libvmdk (18 values).
pub const CREATE_TYPES: &[&str] = &[
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
];

/// Extent type keywords used in a descriptor's extent lines.
pub const EXTENT_TYPES: &[&str] = &[
    "FLAT",
    "VMFS",
    "VMFSRAW",
    "ZERO",
    "SPARSE",
    "VMFSSPARSE",
    "SESPARSE",
];

/// Extent access modes: `RW` (read-write), `RDONLY`, `NOACCESS` (inaccessible hole).
pub const EXTENT_ACCESS_MODES: &[&str] = &["RW", "RDONLY", "NOACCESS"];

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
        for t in [
            "FLAT",
            "VMFS",
            "VMFSRAW",
            "ZERO",
            "SPARSE",
            "VMFSSPARSE",
            "SESPARSE",
        ] {
            assert!(EXTENT_TYPES.contains(&t), "missing extent type {t}");
        }
        assert_eq!(EXTENT_ACCESS_MODES, &["RW", "RDONLY", "NOACCESS"]);
    }
}
