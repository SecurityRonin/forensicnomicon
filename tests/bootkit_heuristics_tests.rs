//! Signature-free bootkit-detection knowledge (stash sectors, entropy
//! thresholds, expected BIOS interrupt vectors).

use forensicnomicon::bootkit::{
    stash_sectors_at, EXPECTED_BOOT_INTERRUPT_VECTORS, ORIGINAL_MBR_STASH_SECTORS,
    PACKED_BOOT_CODE_ENTROPY_STRONG, PACKED_BOOT_CODE_ENTROPY_SUSPECT, TRACK0_GAP,
};

#[test]
fn mebroot_stashes_original_mbr_at_sector_62() {
    assert!(stash_sectors_at(62)
        .any(|s| s.family.contains("Mebroot") && s.note.contains("original MBR")));
}

#[test]
fn petya_original_mbr_sector_is_documented() {
    assert!(stash_sectors_at(56).any(|s| s.family.contains("Petya")));
}

#[test]
fn track0_gap_covers_the_classic_stash_region() {
    assert!(TRACK0_GAP.contains(&62)); // Mebroot's original-MBR sector
    assert!(!TRACK0_GAP.contains(&63)); // first aligned partition — not the gap
    assert!(!TRACK0_GAP.contains(&0)); // the live MBR — not the gap
}

#[test]
fn entropy_thresholds_are_ordered_packer_triage_values() {
    const _: () = assert!(PACKED_BOOT_CODE_ENTROPY_SUSPECT < PACKED_BOOT_CODE_ENTROPY_STRONG);
    assert!((PACKED_BOOT_CODE_ENTROPY_SUSPECT - 7.0).abs() < f64::EPSILON);
    assert!((PACKED_BOOT_CODE_ENTROPY_STRONG - 7.5).abs() < f64::EPSILON);
}

#[test]
fn expected_interrupts_are_the_anssi_set() {
    assert_eq!(EXPECTED_BOOT_INTERRUPT_VECTORS, &[0x10, 0x13, 0x18, 0x1a]);
}

#[test]
fn stash_table_is_non_empty() {
    assert!(!ORIGINAL_MBR_STASH_SECTORS.is_empty());
}
