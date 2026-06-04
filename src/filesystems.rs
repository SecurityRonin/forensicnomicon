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
pub const FILESYSTEM_SIGNATURES: &[FsSignature] = &[
    FsSignature { name: "ext2/3/4", offset: 0x438, magic: &[0x53, 0xEF] },
    FsSignature { name: "NTFS", offset: 3, magic: b"NTFS    " },
    FsSignature { name: "exFAT", offset: 3, magic: b"EXFAT   " },
    FsSignature { name: "XFS", offset: 0, magic: b"XFSB" },
    FsSignature { name: "LUKS", offset: 0, magic: b"LUKS\xba\xbe" },
    FsSignature { name: "FAT32", offset: 0x52, magic: b"FAT32   " },
    FsSignature { name: "FAT16", offset: 0x36, magic: b"FAT16   " },
    FsSignature { name: "FAT12", offset: 0x36, magic: b"FAT12   " },
    FsSignature { name: "Linux swap", offset: 0xFF6, magic: b"SWAPSPACE2" },
    FsSignature { name: "ISO 9660", offset: 0x8001, magic: b"CD001" },
    FsSignature { name: "HFS+", offset: 0x400, magic: b"H+" },
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
        assert_eq!(detect_name(&buf_with(0x438, &[0x53, 0xEF])), Some("ext2/3/4"));
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
}
