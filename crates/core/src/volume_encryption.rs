//! Volume full-disk-encryption detection from a volume boot record.
//!
//! Complements [`crate::filesystems`]: where that identifies a plaintext filesystem, this
//! identifies a **BitLocker** volume, which a filesystem detector cannot — a BitLocker To Go
//! volume presents a genuine FAT/exFAT boot record and looks like an ordinary FAT volume.
//!
//! Detection is scheme- and bus-agnostic: it reads the volume boot record, so it is identical
//! whether the volume is reached over USB, FireWire, Thunderbolt, or SATA, and whether the
//! partition table is MBR, GPT, or APM.
//!
//! Reference: libbde, *BitLocker Drive Encryption (BDE) format* (Joachim Metz),
//! <https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc>
//! — volume-header tables.

/// A detected volume-encryption type. LUKS and other encrypted-filesystem magics are surfaced
/// by [`crate::filesystems::detect_name`]; this enum covers the Microsoft FVE volumes that a
/// filesystem-signature scan cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum VolumeEncryption {
    /// BitLocker on a **fixed drive** (or an NTFS-on-removable volume): the boot record's OEM
    /// identifier at offset 3 is the documented `-FVE-FS-` signature (Windows Vista `EB 52 90`
    /// / 7-10 `EB 58 90`).
    BitLocker,
    /// **BitLocker To Go** on removable media: the discovery volume presents a real FAT/exFAT
    /// boot record (an ordinary OEM identifier at offset 3), so it is identified only by the
    /// BitLocker identifier GUID carried in the volume header, not by `-FVE-FS-`.
    BitLockerToGo,
}

/// The `-FVE-FS-` filesystem signature at volume-header offset 3 (fixed-drive BitLocker).
const FVE_SIGNATURE: &[u8; 8] = b"-FVE-FS-";

/// The BitLocker identifier GUID `4967D63B-2E29-4AD8-8399-F6A339E3D001`, in the mixed-endian
/// byte order it is stored in a volume header (`Data1`-`Data3` little-endian, `Data4`
/// big-endian). The volume header carries it in both layouts — offset 160 (fixed drive) and
/// offset 424 (To Go) — so callers scan for it rather than reading a fixed offset.
pub const BITLOCKER_IDENTIFIER_GUID: [u8; 16] = [
    0x3B, 0xD6, 0x67, 0x49, 0x29, 0x2E, 0xD8, 0x4A, 0x83, 0x99, 0xF6, 0xA3, 0x39, 0xE3, 0xD0, 0x01,
];

/// Detect BitLocker volume encryption from a volume's leading bytes (its boot record).
///
/// - `-FVE-FS-` at offset 3 → [`VolumeEncryption::BitLocker`] (fixed drive; Vista/7/8/10).
/// - otherwise, the [`BITLOCKER_IDENTIFIER_GUID`] present anywhere in the volume header →
///   [`VolumeEncryption::BitLockerToGo`] (a FAT/exFAT discovery volume carrying the GUID).
///
/// `None` for a plaintext volume. Scanning the header for the 16-byte GUID (rather than a
/// fixed offset) catches every BitLocker layout version and is effectively false-positive-free.
#[must_use]
pub fn detect_encryption(volume: &[u8]) -> Option<VolumeEncryption> {
    if volume.len() >= 11 && &volume[3..11] == FVE_SIGNATURE {
        return Some(VolumeEncryption::BitLocker);
    }
    if volume
        .windows(BITLOCKER_IDENTIFIER_GUID.len())
        .any(|w| w == BITLOCKER_IDENTIFIER_GUID)
    {
        return Some(VolumeEncryption::BitLockerToGo);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Offset of the BitLocker identifier GUID in a To Go volume header (libbde).
    const TO_GO_GUID_OFFSET: usize = 424;

    #[test]
    fn fixed_drive_bitlocker_is_detected_by_the_fve_signature() {
        let mut vbr = vec![0u8; 512];
        vbr[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]); // Win7+ boot entry
        vbr[3..11].copy_from_slice(b"-FVE-FS-");
        assert_eq!(detect_encryption(&vbr), Some(VolumeEncryption::BitLocker));
    }

    #[test]
    fn bitlocker_to_go_is_detected_by_the_identifier_guid_on_a_fat_volume() {
        // A real FAT32 discovery volume: MSWIN4.1 OEM id, FAT32 signature — no -FVE-FS- — but
        // carrying the BitLocker identifier GUID at the To Go offset.
        let mut vbr = vec![0u8; 512];
        vbr[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        vbr[3..11].copy_from_slice(b"MSWIN4.1");
        vbr[0x52..0x5A].copy_from_slice(b"FAT32   ");
        vbr[TO_GO_GUID_OFFSET..TO_GO_GUID_OFFSET + 16].copy_from_slice(&BITLOCKER_IDENTIFIER_GUID);
        assert_eq!(
            detect_encryption(&vbr),
            Some(VolumeEncryption::BitLockerToGo)
        );
    }

    #[test]
    fn the_fve_signature_takes_precedence_over_the_guid() {
        // A fixed-drive BitLocker volume carries both -FVE-FS- and the GUID (at offset 160);
        // it classifies as BitLocker, not To Go.
        let mut vbr = vec![0u8; 512];
        vbr[3..11].copy_from_slice(b"-FVE-FS-");
        vbr[160..176].copy_from_slice(&BITLOCKER_IDENTIFIER_GUID);
        assert_eq!(detect_encryption(&vbr), Some(VolumeEncryption::BitLocker));
    }

    #[test]
    fn a_plaintext_fat_volume_is_not_flagged() {
        // A real FAT32 boot record with no FVE signature and no GUID → not encrypted (the
        // non-false-positive control).
        let mut vbr = vec![0u8; 512];
        vbr[3..11].copy_from_slice(b"MSDOS5.0");
        vbr[0x52..0x5A].copy_from_slice(b"FAT32   ");
        assert_eq!(detect_encryption(&vbr), None);
    }

    #[test]
    fn a_plaintext_ntfs_volume_is_not_flagged() {
        let mut vbr = vec![0u8; 512];
        vbr[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(detect_encryption(&vbr), None);
    }

    #[test]
    fn a_short_slice_does_not_panic() {
        assert_eq!(detect_encryption(&[]), None);
        assert_eq!(detect_encryption(&[0u8; 4]), None);
        assert_eq!(detect_encryption(b"-FVE-FS"), None); // one byte short of the signature
    }
}
