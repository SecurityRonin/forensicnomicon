//! GUID Partition Table (GPT) partition-type GUIDs.
//!
//! Single source of truth mapping GPT partition **type GUIDs** to human-readable
//! names, for forensic tools that parse GPT disks (e.g. the `gpt-forensic`
//! crate). GUIDs are stored in their canonical string form
//! (`XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`, the form a parser produces after
//! reversing GPT's mixed-endian on-disk byte order), so lookup is endianness-free.
//!
//! Sources:
//! - UEFI Specification 2.10, §5.3.3 "GPT Partition Entry Array":
//!   <https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html>
//! - Wikipedia, "GUID Partition Table — Partition type GUIDs":
//!   <https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs>
//! - UAPI Group, "Discoverable Partitions Specification":
//!   <https://uapi-group.org/specifications/specs/discoverable_partitions_specification/>

/// A GPT partition-type GUID and its human-readable name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GptType {
    /// Canonical uppercase GUID string.
    pub guid: &'static str,
    /// Human-readable partition-type name.
    pub name: &'static str,
}

/// The unused / empty partition-type GUID (all zeros).
pub const UNUSED_GUID: &str = "00000000-0000-0000-0000-000000000000";

/// Well-known GPT partition-type GUIDs. Sourced from the references above.
pub const PARTITION_TYPE_GUIDS: &[GptType] = &[
    GptType {
        guid: UNUSED_GUID,
        name: "Unused entry",
    },
    // ── Firmware / boot ──────────────────────────────────────────────────────
    GptType {
        guid: "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
        name: "EFI System Partition",
    },
    GptType {
        guid: "21686148-6449-6E6F-744E-656564454649",
        name: "BIOS Boot Partition",
    },
    GptType {
        guid: "024DEE41-33E7-11D3-9D69-0008C781F39F",
        name: "MBR Partition Scheme",
    },
    GptType {
        guid: "BC13C2FF-59E6-4262-A352-B275FD6F7172",
        name: "Extended Boot Loader (XBOOTLDR)",
    },
    // ── Microsoft Windows ────────────────────────────────────────────────────
    GptType {
        guid: "E3C9E316-0B5C-4DB8-817D-F92DF00215AE",
        name: "Microsoft Reserved (MSR)",
    },
    GptType {
        guid: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
        name: "Microsoft Basic Data",
    },
    GptType {
        guid: "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3",
        name: "Windows LDM metadata",
    },
    GptType {
        guid: "AF9B60A0-1431-4F62-BC68-3311714A69AD",
        name: "Windows LDM data",
    },
    GptType {
        guid: "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC",
        name: "Windows Recovery Environment",
    },
    GptType {
        guid: "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D",
        name: "Storage Spaces",
    },
    // ── Linux ────────────────────────────────────────────────────────────────
    GptType {
        guid: "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
        name: "Linux filesystem data",
    },
    GptType {
        guid: "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F",
        name: "Linux swap",
    },
    GptType {
        guid: "E6D6D379-F507-44C2-A23C-238F2A3DF928",
        name: "Linux LVM",
    },
    GptType {
        guid: "A19D880F-05FC-4D3B-A006-743F0F84911E",
        name: "Linux RAID",
    },
    GptType {
        guid: "CA7D7CCB-63ED-4C53-861C-1742536059CC",
        name: "Linux LUKS",
    },
    GptType {
        guid: "933AC7E1-2EB4-4F13-B844-0E14E2AEF915",
        name: "Linux /home",
    },
    GptType {
        guid: "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709",
        name: "Linux root (x86-64)",
    },
    GptType {
        guid: "8DA63339-0007-60C0-C436-083AC8230908",
        name: "Linux reserved",
    },
    // ── Apple macOS ──────────────────────────────────────────────────────────
    GptType {
        guid: "48465300-0000-11AA-AA11-00306543ECAC",
        name: "Apple HFS+",
    },
    GptType {
        guid: "7C3457EF-0000-11AA-AA11-00306543ECAC",
        name: "Apple APFS",
    },
    GptType {
        guid: "55465300-0000-11AA-AA11-00306543ECAC",
        name: "Apple UFS",
    },
    GptType {
        guid: "426F6F74-0000-11AA-AA11-00306543ECAC",
        name: "Apple Boot (Recovery HD)",
    },
    GptType {
        guid: "52414944-0000-11AA-AA11-00306543ECAC",
        name: "Apple RAID",
    },
    // ── BSD ──────────────────────────────────────────────────────────────────
    GptType {
        guid: "516E7CB4-6ECF-11D6-8FF8-00022D09712B",
        name: "FreeBSD data",
    },
    GptType {
        guid: "83BD6B9D-7F41-11DC-BE0B-001560B84F0F",
        name: "FreeBSD boot",
    },
    GptType {
        guid: "516E7CB5-6ECF-11D6-8FF8-00022D09712B",
        name: "FreeBSD swap",
    },
    // ── ChromeOS ─────────────────────────────────────────────────────────────
    GptType {
        guid: "FE3A2A5D-4F32-41A7-B725-ACCC3285A309",
        name: "ChromeOS kernel",
    },
    GptType {
        guid: "3CB8E202-3B7E-47DD-8A3C-7FF2A13CFCEC",
        name: "ChromeOS root",
    },
];

/// GPT partition-entry attribute flag bit positions and their meanings.
///
/// Bits 0–2 are defined for all partitions; bits 48–63 are type-specific and the
/// constants here are the Microsoft Basic Data interpretation (the most common,
/// and the one with forensic-relevant `hidden` / `no-automount` flags).
///
/// Sources:
/// - UEFI Specification 2.10, §5.3.3, Table "Defined GPT Partition Entry —
///   Partition Attributes": <https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html>
/// - Microsoft, `PARTITION_INFORMATION_GPT` / `GPT_BASIC_DATA_ATTRIBUTE_*`:
///   <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-partition_information_gpt>
pub mod attributes {
    /// Bit 0 — Required Partition (platform must not delete it).
    pub const REQUIRED: u64 = 1 << 0;
    /// Bit 1 — No Block IO Protocol (EFI firmware ignores the partition).
    pub const NO_BLOCK_IO: u64 = 1 << 1;
    /// Bit 2 — Legacy BIOS Bootable.
    pub const LEGACY_BIOS_BOOTABLE: u64 = 1 << 2;
    /// Bit 60 — (MS Basic Data) Read-only.
    pub const MS_READ_ONLY: u64 = 1 << 60;
    /// Bit 61 — (MS Basic Data) Shadow copy of another partition.
    pub const MS_SHADOW_COPY: u64 = 1 << 61;
    /// Bit 62 — (MS Basic Data) Hidden.
    pub const MS_HIDDEN: u64 = 1 << 62;
    /// Bit 63 — (MS Basic Data) No default drive letter (no automount).
    pub const MS_NO_DRIVE_LETTER: u64 = 1 << 63;
}

/// Decode a partition-entry `attributes` bitfield into human-readable flag names
/// (in bit order). Unset bits are omitted; an all-zero field yields an empty vec.
#[must_use]
pub fn attribute_names(attrs: u64) -> Vec<&'static str> {
    use attributes as a;
    let table: &[(u64, &str)] = &[
        (a::REQUIRED, "required"),
        (a::NO_BLOCK_IO, "no-block-io"),
        (a::LEGACY_BIOS_BOOTABLE, "legacy-bios-bootable"),
        (a::MS_READ_ONLY, "read-only"),
        (a::MS_SHADOW_COPY, "shadow-copy"),
        (a::MS_HIDDEN, "hidden"),
        (a::MS_NO_DRIVE_LETTER, "no-automount"),
    ];
    table
        .iter()
        .filter(|(bit, _)| attrs & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// Look up a partition-type GUID's human-readable name (case-insensitive).
///
/// Returns `None` for unknown GUIDs.
#[must_use]
pub fn type_name(guid: &str) -> Option<&'static str> {
    PARTITION_TYPE_GUIDS
        .iter()
        .find(|t| t.guid.eq_ignore_ascii_case(guid))
        .map(|t| t.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_guids_resolve() {
        assert_eq!(
            type_name("C12A7328-F81F-11D2-BA4B-00A0C93EC93B"),
            Some("EFI System Partition")
        );
        assert_eq!(
            type_name("0FC63DAF-8483-4772-8E79-3D69D8477DE4"),
            Some("Linux filesystem data")
        );
        assert_eq!(type_name(UNUSED_GUID), Some("Unused entry"));
    }

    #[test]
    fn lookup_is_case_insensitive() {
        assert_eq!(
            type_name("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
            Some("EFI System Partition")
        );
    }

    #[test]
    fn unknown_guid_is_none() {
        assert_eq!(type_name("DEADBEEF-0000-0000-0000-000000000000"), None);
    }

    #[test]
    fn attribute_names_decode_in_bit_order() {
        assert!(attribute_names(0).is_empty());
        assert_eq!(attribute_names(attributes::REQUIRED), vec!["required"]);
        // Hidden + no-automount = a concealment-flag combination.
        let attrs = attributes::MS_HIDDEN | attributes::MS_NO_DRIVE_LETTER;
        assert_eq!(attribute_names(attrs), vec!["hidden", "no-automount"]);
    }

    #[test]
    fn table_guids_are_well_formed() {
        for t in PARTITION_TYPE_GUIDS {
            assert_eq!(t.guid.len(), 36, "GUID must be 36 chars: {}", t.guid);
            assert_eq!(
                t.guid.matches('-').count(),
                4,
                "GUID needs 4 dashes: {}",
                t.guid
            );
            assert!(!t.name.is_empty());
        }
    }
}
