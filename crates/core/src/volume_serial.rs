//! Volume serial-number extraction from a volume boot record.
//!
//! The volume serial is a forensic join key: a FAT `BS_VolID` matches the serial that
//! `EMDMgmt` (ReadyBoost) and Windows Shell Links record for the same volume; an NTFS volume
//! serial appears in its own artifacts. Like [`crate::volume_encryption`], this reads the
//! boot record, so it is independent of the bus and of the MBR/GPT/APM partition table.
//!
//! Field offsets are from the Microsoft FAT specification (`fatgen103`), the Microsoft exFAT
//! specification, and the NTFS boot-sector layout.

/// A volume serial number, tagged by width so a 4-byte serial cannot be confused with an
/// 8-byte one (they render differently and join different artifacts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum VolumeSerial {
    /// A 4-byte serial — FAT `BS_VolID` or exFAT `VolumeSerialNumber`. Rendered `XXXX-XXXX`,
    /// the form Shell Links and `EMDMgmt` record.
    Short(u32),
    /// The 8-byte NTFS volume serial. Rendered `XXXXXXXX-XXXXXXXX`; by width it cannot collide
    /// with a 4-byte serial.
    Long(u64),
}

impl VolumeSerial {
    /// The canonical hex rendering: `XXXX-XXXX` for a 4-byte serial, `XXXXXXXX-XXXXXXXX` for
    /// the 8-byte NTFS serial.
    #[must_use]
    pub fn display(self) -> String {
        match self {
            Self::Short(v) => format!("{:04X}-{:04X}", v >> 16, v & 0xFFFF),
            Self::Long(v) => format!("{:08X}-{:08X}", (v >> 32) as u32, (v & 0xFFFF_FFFF) as u32),
        }
    }
}

/// Extract the volume serial from a volume's boot record, keyed off the filesystem signature:
///
/// - NTFS (`"NTFS    "` at offset 3) → 8-byte serial at offset `0x48`.
/// - exFAT (`"EXFAT   "` at offset 3) → 4-byte `VolumeSerialNumber` at offset `0x64`.
/// - FAT32 (`"FAT32   "` at offset `0x52`) → 4-byte `BS_VolID` at offset `0x43`.
/// - FAT12/16 (`"FAT"` at offset `0x36`) → 4-byte `BS_VolID` at offset `0x27`.
///
/// `None` for any other volume, or a slice too short to reach the field. Panic-free.
#[must_use]
pub fn volume_serial(volume: &[u8]) -> Option<VolumeSerial> {
    if volume.get(3..11) == Some(b"NTFS    ") {
        return u64_le(volume, 0x48).map(VolumeSerial::Long);
    }
    if volume.get(3..11) == Some(b"EXFAT   ") {
        return u32_le(volume, 0x64).map(VolumeSerial::Short);
    }
    if volume.get(0x52..0x5A) == Some(b"FAT32   ") {
        return u32_le(volume, 0x43).map(VolumeSerial::Short);
    }
    if volume.get(0x36..0x39) == Some(b"FAT") {
        return u32_le(volume, 0x27).map(VolumeSerial::Short);
    }
    None
}

/// Read a little-endian `u32` at `off`; `None` if the slice is too short. Panic-free.
fn u32_le(b: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let bytes: [u8; 4] = b.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Read a little-endian `u64` at `off`; `None` if the slice is too short. Panic-free.
fn u64_le(b: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let bytes: [u8; 8] = b.get(off..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat32_reads_bs_volid_at_0x43() {
        let mut vbr = vec![0u8; 512];
        vbr[0x52..0x5A].copy_from_slice(b"FAT32   ");
        vbr[0x43..0x47].copy_from_slice(&0xB4D8_5399u32.to_le_bytes());
        assert_eq!(volume_serial(&vbr), Some(VolumeSerial::Short(0xB4D8_5399)));
        assert_eq!(VolumeSerial::Short(0xB4D8_5399).display(), "B4D8-5399");
    }

    #[test]
    fn fat16_reads_bs_volid_at_0x27() {
        let mut vbr = vec![0u8; 512];
        vbr[0x36..0x39].copy_from_slice(b"FAT");
        vbr[0x27..0x2B].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        assert_eq!(volume_serial(&vbr), Some(VolumeSerial::Short(0x1234_5678)));
    }

    #[test]
    fn ntfs_reads_the_8_byte_serial_at_0x48() {
        let mut vbr = vec![0u8; 512];
        vbr[3..11].copy_from_slice(b"NTFS    ");
        vbr[0x48..0x50].copy_from_slice(&0x0011_2233_4455_6677u64.to_le_bytes());
        assert_eq!(
            volume_serial(&vbr),
            Some(VolumeSerial::Long(0x0011_2233_4455_6677))
        );
        assert_eq!(
            VolumeSerial::Long(0x0011_2233_4455_6677).display(),
            "00112233-44556677"
        );
    }

    #[test]
    fn exfat_reads_the_serial_at_0x64() {
        let mut vbr = vec![0u8; 512];
        vbr[3..11].copy_from_slice(b"EXFAT   ");
        vbr[0x64..0x68].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert_eq!(volume_serial(&vbr), Some(VolumeSerial::Short(0xDEAD_BEEF)));
    }

    #[test]
    fn an_unrecognized_or_short_volume_has_no_serial() {
        assert_eq!(volume_serial(&[0xABu8; 512]), None);
        assert_eq!(volume_serial(&[]), None);
        // NTFS OEM present but the slice ends before the serial field → None, not a panic.
        let mut short = vec![0u8; 0x48];
        short[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(volume_serial(&short), None);
    }
}
