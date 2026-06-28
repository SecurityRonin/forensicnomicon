//! MBR partition type codes (the 1-byte type field in an MBR partition entry).
//!
//! Single source of truth mapping the 1-byte MBR partition type code to a
//! human-readable name, for forensic tools that parse MBR partition tables
//! (e.g. the `mbr-forensic` crate).
//!
//! Sources:
//! - Andries Brouwer, "List of partition identifiers for PCs":
//!   <https://www.win.tue.nl/~aeb/partitions/partition_types-1.html>
//! - Wikipedia, "Partition type":
//!   <https://en.wikipedia.org/wiki/Partition_type>

/// An MBR partition type code and its human-readable name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MbrPartitionType {
    /// The 1-byte type code.
    pub code: u8,
    /// Human-readable name.
    pub name: &'static str,
}

/// Well-known MBR partition type codes. Sourced from the references above.
pub const PARTITION_TYPES: &[MbrPartitionType] = &[
    MbrPartitionType {
        code: 0x00,
        name: "Empty",
    },
    MbrPartitionType {
        code: 0x01,
        name: "FAT12",
    },
    MbrPartitionType {
        code: 0x04,
        name: "FAT16 <32 MB",
    },
    MbrPartitionType {
        code: 0x05,
        name: "Extended (CHS)",
    },
    MbrPartitionType {
        code: 0x06,
        name: "FAT16",
    },
    MbrPartitionType {
        code: 0x07,
        name: "NTFS / exFAT / IFS",
    },
    MbrPartitionType {
        code: 0x08,
        name: "FAT32 (EISA / AIX)",
    },
    MbrPartitionType {
        code: 0x0A,
        name: "OS/2 Boot Manager",
    },
    MbrPartitionType {
        code: 0x0B,
        name: "FAT32 (CHS)",
    },
    MbrPartitionType {
        code: 0x0C,
        name: "FAT32 (LBA)",
    },
    MbrPartitionType {
        code: 0x0E,
        name: "FAT16 (LBA)",
    },
    MbrPartitionType {
        code: 0x0F,
        name: "Extended (LBA)",
    },
    MbrPartitionType {
        code: 0x11,
        name: "Hidden FAT12",
    },
    MbrPartitionType {
        code: 0x12,
        name: "Compaq diagnostics / OEM",
    },
    MbrPartitionType {
        code: 0x14,
        name: "Hidden FAT16 <32 MB",
    },
    MbrPartitionType {
        code: 0x16,
        name: "Hidden FAT16",
    },
    MbrPartitionType {
        code: 0x17,
        name: "Hidden NTFS / IFS",
    },
    MbrPartitionType {
        code: 0x1B,
        name: "Hidden FAT32 (CHS)",
    },
    MbrPartitionType {
        code: 0x1C,
        name: "Hidden FAT32 (LBA)",
    },
    MbrPartitionType {
        code: 0x1E,
        name: "Hidden FAT16 (LBA)",
    },
    MbrPartitionType {
        code: 0x27,
        name: "Windows Recovery / Hidden NTFS",
    },
    MbrPartitionType {
        code: 0x39,
        name: "Plan 9",
    },
    MbrPartitionType {
        code: 0x42,
        name: "Windows LDM / Dynamic Disk",
    },
    MbrPartitionType {
        code: 0x82,
        name: "Linux Swap / Solaris",
    },
    MbrPartitionType {
        code: 0x83,
        name: "Linux",
    },
    MbrPartitionType {
        code: 0x84,
        name: "Hibernate (Windows)",
    },
    MbrPartitionType {
        code: 0x85,
        name: "Linux Extended",
    },
    MbrPartitionType {
        code: 0x86,
        name: "Linux LVM (old)",
    },
    MbrPartitionType {
        code: 0x87,
        name: "NTFS Volume Set",
    },
    MbrPartitionType {
        code: 0x8E,
        name: "Linux LVM",
    },
    MbrPartitionType {
        code: 0x9F,
        name: "BSD/OS",
    },
    MbrPartitionType {
        code: 0xA0,
        name: "Laptop hibernation",
    },
    MbrPartitionType {
        code: 0xA5,
        name: "FreeBSD",
    },
    MbrPartitionType {
        code: 0xA6,
        name: "OpenBSD",
    },
    MbrPartitionType {
        code: 0xA8,
        name: "macOS UFS",
    },
    MbrPartitionType {
        code: 0xA9,
        name: "NetBSD",
    },
    MbrPartitionType {
        code: 0xAB,
        name: "macOS Boot",
    },
    MbrPartitionType {
        code: 0xAF,
        name: "macOS HFS+",
    },
    MbrPartitionType {
        code: 0xBE,
        name: "Solaris Boot",
    },
    MbrPartitionType {
        code: 0xBF,
        name: "Solaris",
    },
    MbrPartitionType {
        code: 0xEB,
        name: "BeOS / Haiku",
    },
    MbrPartitionType {
        code: 0xEE,
        name: "GPT Protective MBR",
    },
    MbrPartitionType {
        code: 0xEF,
        name: "EFI System Partition (FAT)",
    },
    MbrPartitionType {
        code: 0xFB,
        name: "VMware VMFS",
    },
    MbrPartitionType {
        code: 0xFC,
        name: "VMware Swap",
    },
    MbrPartitionType {
        code: 0xFD,
        name: "Linux RAID",
    },
    MbrPartitionType {
        code: 0xFE,
        name: "Linux LAF / IBM IML",
    },
];

/// Look up an MBR partition type code's human-readable name.
///
/// Returns `None` for codes not in the table.
#[must_use]
pub fn type_name(code: u8) -> Option<&'static str> {
    PARTITION_TYPES
        .iter()
        .find(|t| t.code == code)
        .map(|t| t.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_resolve() {
        assert_eq!(type_name(0x00), Some("Empty"));
        assert_eq!(type_name(0x07), Some("NTFS / exFAT / IFS"));
        assert_eq!(type_name(0x83), Some("Linux"));
        assert_eq!(type_name(0xEE), Some("GPT Protective MBR"));
    }

    #[test]
    fn unknown_code_is_none() {
        assert_eq!(type_name(0xCC), None);
        assert_eq!(type_name(0xCD), None);
    }

    #[test]
    fn codes_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for t in PARTITION_TYPES {
            assert!(seen.insert(t.code), "duplicate code {:#04X}", t.code);
            assert!(!t.name.is_empty());
        }
    }
}
