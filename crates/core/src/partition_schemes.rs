//! Disk partitioning-scheme detection from on-disk magic numbers.
//!
//! Single source of truth for the magics that identify which partitioning
//! scheme a disk uses, for tools (e.g. the `disk-forensic` orchestrator) that
//! must pick the right parser before they know the layout.
//!
//! Sources:
//! - UEFI Specification 2.10, §5.3 "GUID Partition Table (GPT) Disk Layout" —
//!   the GPT Header Signature is the 8 bytes `"EFI PART"` (`0x5452415020494645`),
//!   located in the logical block after the protective MBR (LBA 1).
//!   <https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html>
//! - The legacy MBR boot signature `0x55 0xAA` at byte offset 510 (IBM PC /
//!   MS-DOS master boot record), present on both classic MBR and the GPT
//!   protective MBR.
//! - Apple, "Inside Macintosh: Devices" — the Driver Descriptor Record at block
//!   0 begins with the signature `"ER"` (`sbSig = 0x4552`).
//!   See also Wikipedia, "Apple Partition Map":
//!   <https://en.wikipedia.org/wiki/Apple_Partition_Map>

/// A disk partitioning scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Scheme {
    /// Master Boot Record (legacy BIOS partitioning).
    Mbr,
    /// GUID Partition Table (advertised by a protective MBR).
    Gpt,
    /// Apple Partition Map.
    Apm,
}

/// MBR boot signature `0x55 0xAA` at byte offset 510 of LBA 0.
pub const MBR_BOOT_SIGNATURE: [u8; 2] = [0x55, 0xAA];
/// Byte offset of [`MBR_BOOT_SIGNATURE`] within LBA 0.
pub const MBR_BOOT_SIGNATURE_OFFSET: usize = 510;
/// GPT header signature, found at the start of LBA 1 (offset 512 on a
/// 512-byte-sector disk).
pub const GPT_HEADER_MAGIC: &[u8; 8] = b"EFI PART";
/// Apple Partition Map Driver Descriptor Record signature at offset 0.
pub const APM_DDR_MAGIC: &[u8; 2] = b"ER";

/// Classify the partitioning scheme from a disk's boot area (LBA 0 and, for the
/// GPT sub-check, LBA 1 — at least the first 1024 bytes on a 512-byte-sector
/// disk).
///
/// Returns `None` when no known scheme magic is present. The MBR boot signature
/// is authoritative over a stray `"ER"`, so a disk carrying both is reported as
/// MBR-family, never APM.
///
/// The GPT sub-classification assumes 512-byte logical sectors (it looks for the
/// header at offset 512); a 4Kn GPT disk is reported as [`Scheme::Mbr`] here, and
/// the protective-MBR parse still surfaces the real GPT.
#[must_use]
pub fn detect_scheme(boot_area: &[u8]) -> Option<Scheme> {
    if boot_area.len() >= MBR_BOOT_SIGNATURE_OFFSET + 2
        && boot_area[MBR_BOOT_SIGNATURE_OFFSET] == MBR_BOOT_SIGNATURE[0]
        && boot_area[MBR_BOOT_SIGNATURE_OFFSET + 1] == MBR_BOOT_SIGNATURE[1]
    {
        if boot_area.len() >= 520 && &boot_area[512..520] == GPT_HEADER_MAGIC {
            return Some(Scheme::Gpt);
        }
        // A FAT/NTFS/exFAT volume boot record shares the 0x55AA signature but is
        // a filesystem, not a partition table — do not mis-report it as MBR.
        if looks_like_vbr(boot_area) {
            return None;
        }
        return Some(Scheme::Mbr);
    }
    if boot_area.len() >= 2 && &boot_area[0..2] == APM_DDR_MAGIC {
        return Some(Scheme::Apm);
    }
    None
}

/// `true` when `sector0` is a FAT/NTFS/exFAT **volume boot record** rather than
/// a Master Boot Record. These filesystems' VBRs share the `0x55AA` boot
/// signature at offset 510, so distinguishing them prevents a superfloppy
/// (filesystem written directly to the device) from being mis-parsed as MBR —
/// the bytes a partition table would occupy (446–510) are really BPB/boot code.
///
/// A VBR opens with an x86 jump (`0xEB`/`0xE9`) and carries a filesystem magic
/// at a VBR-specific offset: `"NTFS    "` / `"EXFAT   "` at offset 3, or the FAT
/// `BS_FilSysType` string `"FAT12   "`/`"FAT16   "` at 54 / `"FAT32   "` at 82.
#[must_use]
pub fn looks_like_vbr(sector0: &[u8]) -> bool {
    if sector0.len() < 512 || sector0[510] != 0x55 || sector0[511] != 0xAA {
        return false;
    }
    if sector0[0] != 0xEB && sector0[0] != 0xE9 {
        return false;
    }
    let oem = &sector0[3..11];
    if oem == b"NTFS    " || oem == b"EXFAT   " {
        return true;
    }
    if &sector0[54..62] == b"FAT12   " || &sector0[54..62] == b"FAT16   " {
        return true;
    }
    &sector0[82..90] == b"FAT32   "
}

#[cfg(test)]
mod tests {

    #[test]
    fn detect_scheme_covers_gpt_mbr_apm_vbr_and_none() {
        // Protective MBR signature + GPT header magic at offset 512 -> Gpt.
        let mut gpt = vec![0u8; 520];
        gpt[MBR_BOOT_SIGNATURE_OFFSET] = MBR_BOOT_SIGNATURE[0];
        gpt[MBR_BOOT_SIGNATURE_OFFSET + 1] = MBR_BOOT_SIGNATURE[1];
        gpt[512..520].copy_from_slice(GPT_HEADER_MAGIC);
        assert_eq!(detect_scheme(&gpt), Some(Scheme::Gpt));

        // 0x55AA present, no GPT, not a filesystem VBR -> Mbr.
        let mut mbr = vec![0u8; 512];
        mbr[MBR_BOOT_SIGNATURE_OFFSET] = 0x55;
        mbr[MBR_BOOT_SIGNATURE_OFFSET + 1] = 0xAA;
        assert_eq!(detect_scheme(&mbr), Some(Scheme::Mbr));

        // 0x55AA present but it is an NTFS volume boot record -> None.
        let mut vbr = vec![0u8; 512];
        vbr[0] = 0xEB;
        vbr[3..11].copy_from_slice(b"NTFS    ");
        vbr[510] = 0x55;
        vbr[511] = 0xAA;
        assert_eq!(detect_scheme(&vbr), None);

        // Apple Partition Map DDR "ER" at offset 0, no MBR signature -> Apm.
        let mut apm = vec![0u8; 8];
        apm[0..2].copy_from_slice(APM_DDR_MAGIC);
        assert_eq!(detect_scheme(&apm), Some(Scheme::Apm));

        // Unrecognized and too-short inputs -> None.
        assert_eq!(detect_scheme(&[0u8; 4]), None);
        assert_eq!(detect_scheme(&[]), None);
    }

    #[test]
    fn looks_like_vbr_accepts_ntfs_exfat_fat_and_rejects_others() {
        let mut ntfs = vec![0u8; 512];
        ntfs[0] = 0xEB;
        ntfs[3..11].copy_from_slice(b"NTFS    ");
        ntfs[510] = 0x55;
        ntfs[511] = 0xAA;
        assert!(looks_like_vbr(&ntfs));

        let mut exfat = vec![0u8; 512];
        exfat[0] = 0xE9;
        exfat[3..11].copy_from_slice(b"EXFAT   ");
        exfat[510] = 0x55;
        exfat[511] = 0xAA;
        assert!(looks_like_vbr(&exfat));

        let mut fat16 = vec![0u8; 512];
        fat16[0] = 0xEB;
        fat16[54..62].copy_from_slice(b"FAT16   ");
        fat16[510] = 0x55;
        fat16[511] = 0xAA;
        assert!(looks_like_vbr(&fat16));

        let mut fat32 = vec![0u8; 512];
        fat32[0] = 0xEB;
        fat32[82..90].copy_from_slice(b"FAT32   ");
        fat32[510] = 0x55;
        fat32[511] = 0xAA;
        assert!(looks_like_vbr(&fat32));

        // No 0x55AA -> false; jump byte missing -> false; too short -> false.
        assert!(!looks_like_vbr(&[0u8; 512]));
        let mut nojump = vec![0u8; 512];
        nojump[510] = 0x55;
        nojump[511] = 0xAA;
        assert!(!looks_like_vbr(&nojump));
        assert!(!looks_like_vbr(&[0x55, 0xAA]));
    }
    use super::*;

    #[test]
    fn magics_have_expected_values() {
        assert_eq!(MBR_BOOT_SIGNATURE, [0x55, 0xAA]);
        assert_eq!(GPT_HEADER_MAGIC, b"EFI PART");
        assert_eq!(APM_DDR_MAGIC, b"ER");
    }
}
