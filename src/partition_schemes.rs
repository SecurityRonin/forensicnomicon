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
        return Some(Scheme::Mbr);
    }
    if boot_area.len() >= 2 && &boot_area[0..2] == APM_DDR_MAGIC {
        return Some(Scheme::Apm);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magics_have_expected_values() {
        assert_eq!(MBR_BOOT_SIGNATURE, [0x55, 0xAA]);
        assert_eq!(GPT_HEADER_MAGIC, b"EFI PART");
        assert_eq!(APM_DDR_MAGIC, b"ER");
    }
}
