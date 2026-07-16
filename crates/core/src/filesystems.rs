//! Filesystem superblock / boot-sector magic signatures.
//!
//! Single source of truth mapping a `(offset, magic-bytes)` pair to a filesystem
//! name, for forensic tools that fingerprint a partition's content. Each entry
//! cites the authoritative on-disk-format reference for its offset and magic.
//!
//! Offsets are absolute byte offsets from the start of the partition/volume.
//!
//! General references:
//! - Wikipedia, "List of file signatures": <https://en.wikipedia.org/wiki/List_of_file_signatures>
//! - The `file`/libmagic database (`magic/Magdir/filesystems`):
//!   <https://github.com/file/file/blob/master/magic/Magdir/filesystems>

/// One filesystem magic signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FsSignature {
    /// Filesystem name.
    pub name: &'static str,
    /// Absolute byte offset of the magic within the volume.
    pub offset: usize,
    /// The magic bytes expected at `offset`.
    pub magic: &'static [u8],
}

/// Well-known filesystem magic signatures.
///
/// Per-entry sources:
/// - **ext2/3/4** — superblock magic `0xEF53` (LE `53 EF`) at offset `0x438`:
///   Linux kernel `fs/ext4/ext4.h` `EXT4_SUPER_MAGIC`; Wikipedia "Ext4".
/// - **NTFS** — OEM ID `"NTFS    "` at offset `3`: Microsoft NTFS docs; Wikipedia "NTFS".
/// - **exFAT** — OEM name `"EXFAT   "` at offset `3`: Microsoft exFAT specification.
/// - **XFS** — superblock magic `"XFSB"` at offset `0`: XFS Algorithms & Data
///   Structures (SGI/Red Hat).
/// - **LUKS1** — magic `"LUKS\xba\xbe"` at offset `0`: LUKS On-Disk Format Spec.
/// - **FAT32** — `BS_FilSysType` `"FAT32   "` at offset `0x52`: Microsoft FAT
///   Specification (`fatgen103`).
/// - **FAT16/FAT12** — `BS_FilSysType` `"FAT16   "` / `"FAT12   "` at offset `0x36`:
///   Microsoft FAT Specification.
/// - **Linux swap** — `"SWAPSPACE2"` at offset `0xFF6` (page end − 10): `mkswap(8)` / kernel.
/// - **ISO 9660** — `"CD001"` at offset `0x8001` (sector 16): ECMA-119.
/// - **HFS+** — signature `"H+"` at offset `0x400`: Apple Technical Note TN1150.
/// - **APFS** — container superblock `nx_magic` `"NXSB"` at offset `32` (after the
///   32-byte `obj_phys_t` header): Apple File System Reference; util-linux
///   `libblkid/src/superblocks/apfs.c` (`.magic = "NXSB", .sboff = 32`).
/// - **Btrfs** — superblock magic `"_BHRfS_M"` at offset `65600` (`0x10040`; the
///   superblock is at 64 KiB and `magic` is at `+0x40`): util-linux
///   `libblkid/src/superblocks/btrfs.c` (`.kboff = 64, .sboff = 0x40`).
/// - **LVM2 PV** — label `"LABELONE"` at the start of the PV label sector, which
///   is sector 0 **or** sector 1 (offset `0` or `512`; the default is sector 1):
///   util-linux `libblkid/src/superblocks/lvm.c` (checks `buf` and `buf + 512`);
///   libvslvm "Logical Volume Manager (LVM) format".
pub const FILESYSTEM_SIGNATURES: &[FsSignature] = &[
    FsSignature {
        name: "ext2/3/4",
        offset: 0x438,
        magic: &[0x53, 0xEF],
    },
    FsSignature {
        name: "NTFS",
        offset: 3,
        magic: b"NTFS    ",
    },
    FsSignature {
        name: "exFAT",
        offset: 3,
        magic: b"EXFAT   ",
    },
    FsSignature {
        name: "XFS",
        offset: 0,
        magic: b"XFSB",
    },
    FsSignature {
        name: "LUKS",
        offset: 0,
        magic: b"LUKS\xba\xbe",
    },
    FsSignature {
        name: "APFS",
        offset: 32,
        magic: b"NXSB",
    },
    FsSignature {
        name: "FAT32",
        offset: 0x52,
        magic: b"FAT32   ",
    },
    FsSignature {
        name: "FAT16",
        offset: 0x36,
        magic: b"FAT16   ",
    },
    FsSignature {
        name: "FAT12",
        offset: 0x36,
        magic: b"FAT12   ",
    },
    FsSignature {
        name: "Linux swap",
        offset: 0xFF6,
        magic: b"SWAPSPACE2",
    },
    FsSignature {
        name: "LVM2",
        offset: 0,
        magic: b"LABELONE",
    },
    FsSignature {
        name: "LVM2",
        offset: 512,
        magic: b"LABELONE",
    },
    FsSignature {
        name: "ISO 9660",
        offset: 0x8001,
        magic: b"CD001",
    },
    FsSignature {
        name: "HFS+",
        offset: 0x400,
        magic: b"H+",
    },
    FsSignature {
        name: "Btrfs",
        offset: 65600,
        magic: b"_BHRfS_M",
    },
];

/// Identify the filesystem from a volume's leading bytes, returning the first
/// matching signature's name. Returns `None` when nothing matches (the slice may
/// simply be too short to reach a deeper magic).
#[must_use]
pub fn detect_name(data: &[u8]) -> Option<&'static str> {
    FILESYSTEM_SIGNATURES.iter().find_map(|sig| {
        let end = sig.offset.checked_add(sig.magic.len())?;
        (data.len() >= end && &data[sig.offset..end] == sig.magic).then_some(sig.name)
    })
}

/// Canonical identity of a filesystem, content-addressed by a stable lowercase
/// name.
///
/// A newtype over `&'static str` (not an enum) so the set is **open**: adding a
/// filesystem is a new `const` here, never a breaking change to a downstream
/// contract crate. Every filesystem is a uniform `const` — none is a
/// first-class variant and none is a stringly-typed `Other`.
///
/// Intended as the single source of the identity that `forensic-vfs::FsKind`
/// re-exports, retiring its named-variants-plus-`Other` enum.
///
/// The names here are the canonical *identity* labels; they intentionally
/// differ from the human-facing detection names in [`FILESYSTEM_SIGNATURES`]
/// (e.g. identity `ext` vs. the signature label `ext2/3/4`). Identity and
/// detection are kept as two separate concerns; this type carries no magics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FsKind(&'static str);

impl FsKind {
    /// NTFS.
    pub const NTFS: FsKind = FsKind("ntfs");
    /// FAT (FAT12/16/32 family).
    pub const FAT: FsKind = FsKind("fat");
    /// exFAT.
    pub const EXFAT: FsKind = FsKind("exfat");
    /// ext2/3/4 family.
    pub const EXT: FsKind = FsKind("ext");
    /// XFS.
    pub const XFS: FsKind = FsKind("xfs");
    /// Apple APFS.
    pub const APFS: FsKind = FsKind("apfs");
    /// Apple HFS+.
    pub const HFS_PLUS: FsKind = FsKind("hfsplus");
    /// ISO 9660 optical filesystem.
    pub const ISO9660: FsKind = FsKind("iso9660");
    /// UDF optical filesystem.
    pub const UDF: FsKind = FsKind("udf");
    /// Btrfs.
    pub const BTRFS: FsKind = FsKind("btrfs");
    /// ZFS.
    pub const ZFS: FsKind = FsKind("zfs");
    /// UFS/FFS.
    pub const UFS: FsKind = FsKind("ufs");
    /// Microsoft ReFS.
    pub const REFS: FsKind = FsKind("refs");
    /// ZIP archive-as-container.
    pub const ZIP: FsKind = FsKind("zip");
    /// AccessData AD1 logical-image container.
    pub const AD1: FsKind = FsKind("ad1");
    /// DAR (Disk ARchive) container.
    pub const DAR: FsKind = FsKind("dar");

    /// Documented fallback for a name outside [`known`](FsKind::known). A
    /// runtime string cannot be promoted to a `&'static str` without leaking, so
    /// deserializing an unrecognized name collapses to this single sentinel
    /// (the first registered kind) rather than allocating or panicking. Callers
    /// needing strict validation compare the input against
    /// [`known`](FsKind::known) before trusting a deserialized value.
    pub const UNKNOWN_FALLBACK: FsKind = FsKind::NTFS;

    /// The stable lowercase identifier — round-trips, safe for logs / JSON / URIs.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }

    /// Construct from a compile-time name. Returns a kind wrapping the given
    /// static string; pass one of the const names to get a registered kind.
    #[must_use]
    pub const fn from_name(name: &'static str) -> FsKind {
        FsKind(name)
    }

    /// All registered kinds — lets consumers enumerate/validate without a closed
    /// enum.
    #[must_use]
    pub const fn known() -> &'static [FsKind] {
        KNOWN
    }
}

static KNOWN: &[FsKind] = &[
    FsKind::NTFS,
    FsKind::FAT,
    FsKind::EXFAT,
    FsKind::EXT,
    FsKind::XFS,
    FsKind::APFS,
    FsKind::HFS_PLUS,
    FsKind::ISO9660,
    FsKind::UDF,
    FsKind::BTRFS,
    FsKind::ZFS,
    FsKind::UFS,
    FsKind::REFS,
    FsKind::ZIP,
    FsKind::AD1,
    FsKind::DAR,
];

impl core::fmt::Display for FsKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl core::fmt::Debug for FsKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("FsKind").field(&self.0).finish()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for FsKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for FsKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Borrow the bare string; resolve it against the registered kinds so the
        // result holds a `&'static str`, never runtime-owned memory. An
        // unrecognized name maps to `UNKNOWN_FALLBACK` (see its docs).
        let name: &str = <&str as serde::Deserialize>::deserialize(deserializer)?;
        Ok(KNOWN
            .iter()
            .copied()
            .find(|k| k.0 == name)
            .unwrap_or(FsKind::UNKNOWN_FALLBACK))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf_with(offset: usize, magic: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; offset + magic.len() + 4];
        v[offset..offset + magic.len()].copy_from_slice(magic);
        v
    }

    #[test]
    fn detects_ext_at_0x438() {
        assert_eq!(
            detect_name(&buf_with(0x438, &[0x53, 0xEF])),
            Some("ext2/3/4")
        );
    }

    #[test]
    fn detects_ntfs_and_exfat_oem() {
        assert_eq!(detect_name(&buf_with(3, b"NTFS    ")), Some("NTFS"));
        assert_eq!(detect_name(&buf_with(3, b"EXFAT   ")), Some("exFAT"));
    }

    #[test]
    fn detects_luks_and_xfs_at_zero() {
        assert_eq!(detect_name(&buf_with(0, b"LUKS\xba\xbe")), Some("LUKS"));
        assert_eq!(detect_name(&buf_with(0, b"XFSB")), Some("XFS"));
    }

    #[test]
    fn detects_apfs_at_offset_32() {
        // libblkid: NXSB at sboff 32 (after the 32-byte obj_phys header).
        assert_eq!(detect_name(&buf_with(32, b"NXSB")), Some("APFS"));
        // NXSB at offset 0 is NOT APFS (the common off-by-32 mistake).
        assert_eq!(detect_name(&buf_with(0, b"NXSB")), None);
    }

    #[test]
    fn detects_btrfs_at_65600() {
        // libblkid: _BHRfS_M at kboff 64 + sboff 0x40 = 65600.
        assert_eq!(detect_name(&buf_with(65600, b"_BHRfS_M")), Some("Btrfs"));
        assert_eq!(detect_name(&buf_with(65536, b"_BHRfS_M")), None);
    }

    #[test]
    fn detects_lvm_at_sector_0_or_1() {
        assert_eq!(detect_name(&buf_with(0, b"LABELONE")), Some("LVM2"));
        // The default PV label is in sector 1 (offset 512) — the case mbr missed.
        assert_eq!(detect_name(&buf_with(512, b"LABELONE")), Some("LVM2"));
    }

    #[test]
    fn detects_ufs1_at_9564() {
        // libblkid `ufs.c`: `fs_magic` (offset 1372 in `struct fs`) checked at
        // superblock KiB positions {0,8,64,256}. The canonical UFS1 primary
        // superblock is at 8192 (`SBLOCK_UFS1`), so `fs_magic` = 8192 + 1372 =
        // 9564. Magic `UFS_MAGIC = 0x00011954`, little-endian on disk.
        assert_eq!(
            detect_name(&buf_with(9564, &[0x54, 0x19, 0x01, 0x00])),
            Some("UFS1")
        );
        // Same magic at the wrong offset (e.g. the superblock start, not
        // `fs_magic`) must not match.
        assert_eq!(
            detect_name(&buf_with(8192, &[0x54, 0x19, 0x01, 0x00])),
            None
        );
    }

    #[test]
    fn detects_ufs2_at_66908() {
        // libblkid `ufs.c`: UFS2 primary superblock at 65536 (`SBLOCK_UFS2`), so
        // `fs_magic` = 65536 + 1372 = 66908. Magic `UFS2_MAGIC = 0x19540119`, LE.
        assert_eq!(
            detect_name(&buf_with(66908, &[0x19, 0x01, 0x54, 0x19])),
            Some("UFS2")
        );
        assert_eq!(
            detect_name(&buf_with(65536, &[0x19, 0x01, 0x54, 0x19])),
            None
        );
    }

    #[test]
    fn detects_refs_at_zero() {
        // libblkid `refs.c`: magic `"\0\0\0ReFS\0"` (len 8) at offset 0 — the
        // OEM-ID field (offset 3, zeroed by NTFS/FAT) holds NUL-framed "ReFS".
        assert_eq!(
            detect_name(&buf_with(0, b"\x00\x00\x00ReFS\x00")),
            Some("ReFS")
        );
        // "ReFS" at offset 3 WITHOUT the trailing NUL frame (e.g. a stray string)
        // must not match the full 8-byte pattern.
        assert_eq!(detect_name(&buf_with(3, b"ReFSxxxx")), None);
    }

    #[test]
    fn detects_udf_nsr02_nsr03_at_0x8801() {
        // libblkid `udf.c` / ECMA-167: the Volume Recognition Sequence begins at
        // sector 16 (0x8000); each 2048-byte descriptor is `structType`(1) +
        // `stdIdent[5]`. The UDF-defining NSR descriptor sits at sector 17, so its
        // 5-byte id is at 0x8000 + 2048 + 1 = 0x8801 (34817). Verified on a real
        // macOS `newfs_udf` image (NSR03 at 0x8801).
        assert_eq!(detect_name(&buf_with(0x8801, b"NSR02")), Some("UDF"));
        assert_eq!(detect_name(&buf_with(0x8801, b"NSR03")), Some("UDF"));
        // A bare "NSR" prefix or wrong id at the same offset must not match.
        assert_eq!(detect_name(&buf_with(0x8801, b"NSRxx")), None);
    }

    #[test]
    fn empty_and_unknown_are_none() {
        assert_eq!(detect_name(&[]), None);
        assert_eq!(detect_name(&[0u8; 512]), None);
    }

    #[test]
    fn short_slice_does_not_panic() {
        // A slice shorter than a deep magic's offset must simply not match.
        assert_eq!(detect_name(&[0u8; 8]), None);
    }

    #[test]
    fn signatures_are_well_formed() {
        for s in FILESYSTEM_SIGNATURES {
            assert!(!s.magic.is_empty(), "{} has empty magic", s.name);
            assert!(!s.name.is_empty());
        }
    }

    #[test]
    fn fskind_as_str_is_canonical_lowercase() {
        assert_eq!(FsKind::XFS.as_str(), "xfs");
        assert_eq!(FsKind::HFS_PLUS.as_str(), "hfsplus");
        assert_eq!(FsKind::ISO9660.as_str(), "iso9660");
    }

    #[test]
    fn fskind_from_name_round_trips_every_const() {
        for &k in FsKind::known() {
            assert_eq!(FsKind::from_name(k.as_str()), k);
        }
    }

    #[test]
    fn fskind_known_has_every_const_and_no_duplicate_name() {
        let expected = [
            FsKind::NTFS,
            FsKind::FAT,
            FsKind::EXFAT,
            FsKind::EXT,
            FsKind::XFS,
            FsKind::APFS,
            FsKind::HFS_PLUS,
            FsKind::ISO9660,
            FsKind::UDF,
            FsKind::BTRFS,
            FsKind::ZFS,
            FsKind::UFS,
            FsKind::REFS,
            FsKind::ZIP,
            FsKind::AD1,
            FsKind::DAR,
        ];
        for k in expected {
            assert!(FsKind::known().contains(&k), "known() missing {k}");
        }
        assert_eq!(FsKind::known().len(), expected.len());
        let mut names: Vec<&str> = FsKind::known().iter().map(FsKind::as_str).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate as_str in known()");
    }

    #[test]
    fn fskind_display_writes_as_str() {
        assert_eq!(FsKind::BTRFS.to_string(), "btrfs");
        assert_eq!(format!("{}", FsKind::ZFS), "zfs");
    }

    #[test]
    fn fskind_debug_is_readable() {
        let s = format!("{:?}", FsKind::APFS);
        assert!(s.contains("FsKind"), "{s}");
        assert!(s.contains("apfs"), "{s}");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn fskind_serde_round_trips_bare_string() {
        assert_eq!(serde_json::to_string(&FsKind::BTRFS).unwrap(), "\"btrfs\"");
        let back: FsKind = serde_json::from_str("\"btrfs\"").unwrap();
        assert_eq!(back, FsKind::BTRFS);
        for &k in FsKind::known() {
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, format!("\"{}\"", k.as_str()));
            assert_eq!(serde_json::from_str::<FsKind>(&json).unwrap(), k);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn fskind_deserialize_unknown_name_maps_to_sentinel() {
        let back: FsKind = serde_json::from_str("\"nonesuch-fs\"").unwrap();
        assert_eq!(back, FsKind::UNKNOWN_FALLBACK);
    }
}
