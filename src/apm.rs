//! Apple Partition Map (APM) partition-type strings.
//!
//! Single source of truth for the well-known `pmPartType` strings used in an
//! Apple Partition Map, for forensic tools that parse APM disks (e.g. the
//! `apm-forensic` crate). The partition map describes itself with an entry of
//! type [`PARTITION_MAP_TYPE`]; an unrecognised type may indicate a custom or
//! hidden partition.
//!
//! Sources:
//! - Apple, "Inside Macintosh: Devices", ch. 3 "SCSI Manager" / "Disk Drivers"
//!   (the Partition Map and `pmPartType` definitions).
//! - Wikipedia, "Apple Partition Map":
//!   <https://en.wikipedia.org/wiki/Apple_Partition_Map>
//! - GNU parted, `libparted/labels/mac.c` (the partition-type strings it writes).

/// The type string of the entry that describes the partition map itself.
pub const PARTITION_MAP_TYPE: &str = "Apple_partition_map";

/// Well-known APM `pmPartType` strings. Sourced from the references above.
pub const APM_PARTITION_TYPES: &[&str] = &[
    "Apple_partition_map", // the partition map itself
    "Apple_Driver",        // device driver
    "Apple_Driver43",      // SCSI Manager 4.3 driver
    "Apple_Driver43_CD",   // SCSI CD-ROM driver
    "Apple_Driver_ATA",    // ATA driver
    "Apple_Driver_ATAPI",  // ATAPI driver
    "Apple_Driver_IOKit",  // IOKit driver
    "Apple_Patches",       // patch partition
    "Apple_Free",          // unused/free space
    "Apple_HFS",           // HFS / HFS+ filesystem
    "Apple_HFSX",          // HFSX (case-sensitive HFS+)
    "Apple_UFS",           // UFS (Rhapsody / early Mac OS X)
    "Apple_UNIX_SVR2",     // A/UX UNIX filesystem
    "Apple_PRODOS",        // ProDOS filesystem
    "Apple_Boot",          // Mac OS X booter
    "Apple_Bootstrap",     // secondary bootstrap (yaboot, PPC Linux)
    "Apple_Loader",        // secondary boot loader
    "Apple_Rhapsody_UFS",  // Rhapsody UFS
    "Apple_Scratch",       // empty / scratch
    "Apple_Second",        // secondary loader
    "Apple_Void",          // dummy partition
];

/// `true` when `type_name` is a recognised APM partition type.
#[must_use]
pub fn is_known_type(type_name: &str) -> bool {
    APM_PARTITION_TYPES.contains(&type_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_types_recognised() {
        assert!(is_known_type("Apple_HFS"));
        assert!(is_known_type("Apple_partition_map"));
        assert!(is_known_type("Apple_Free"));
    }

    #[test]
    fn unknown_type_is_not_recognised() {
        assert!(!is_known_type("Totally_Bogus"));
        assert!(!is_known_type(""));
    }

    #[test]
    fn partition_map_type_is_in_table() {
        assert!(is_known_type(PARTITION_MAP_TYPE));
    }
}
