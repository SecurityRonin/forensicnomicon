#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Partition-scheme detection from a disk's boot area.

use forensicnomicon::partition_schemes::{detect_scheme, Scheme};

fn mbr_boot_area() -> Vec<u8> {
    let mut b = vec![0u8; 1024];
    b[510] = 0x55;
    b[511] = 0xAA;
    b
}

#[test]
fn detects_classic_mbr() {
    assert_eq!(detect_scheme(&mbr_boot_area()), Some(Scheme::Mbr));
}

#[test]
fn detects_gpt_via_efi_part_at_lba1() {
    let mut b = mbr_boot_area();
    b[512..520].copy_from_slice(b"EFI PART");
    assert_eq!(detect_scheme(&b), Some(Scheme::Gpt));
}

#[test]
fn detects_apm_via_ddr_magic() {
    let mut b = vec![0u8; 1024];
    b[0] = b'E';
    b[1] = b'R';
    assert_eq!(detect_scheme(&b), Some(Scheme::Apm));
}

#[test]
fn mbr_signature_takes_precedence_over_stray_er() {
    // A disk with both 0x55AA@510 and "ER"@0 is MBR-family, not APM.
    let mut b = mbr_boot_area();
    b[0] = b'E';
    b[1] = b'R';
    assert_eq!(detect_scheme(&b), Some(Scheme::Mbr));
}

#[test]
fn unrecognised_boot_area_is_none() {
    assert_eq!(detect_scheme(&[0u8; 1024]), None);
    assert_eq!(detect_scheme(&[]), None);
}

// ── VBR vs MBR disambiguation ────────────────────────────────────────────────
// A FAT/NTFS/exFAT volume boot record also ends in 0x55AA at offset 510, so a
// superfloppy (filesystem written directly to the device) must NOT be reported
// as an MBR — bytes 446–510 are BPB/boot code, not a partition table.

use forensicnomicon::partition_schemes::looks_like_vbr;

fn fat16_vbr() -> Vec<u8> {
    let mut b = vec![0u8; 1024];
    b[0] = 0xEB; // jump
    b[1] = 0x3C;
    b[2] = 0x90;
    b[3..11].copy_from_slice(b"MSDOS5.0"); // OEM
    b[54..62].copy_from_slice(b"FAT16   "); // BS_FilSysType
    b[510] = 0x55;
    b[511] = 0xAA;
    b
}

fn ntfs_vbr() -> Vec<u8> {
    let mut b = vec![0u8; 1024];
    b[0] = 0xEB;
    b[1] = 0x52;
    b[2] = 0x90;
    b[3..11].copy_from_slice(b"NTFS    ");
    b[510] = 0x55;
    b[511] = 0xAA;
    b
}

#[test]
fn fat_vbr_is_not_classified_as_mbr() {
    assert_eq!(detect_scheme(&fat16_vbr()), None);
    assert!(looks_like_vbr(&fat16_vbr()));
}

#[test]
fn ntfs_vbr_is_not_classified_as_mbr() {
    assert_eq!(detect_scheme(&ntfs_vbr()), None);
    assert!(looks_like_vbr(&ntfs_vbr()));
}

#[test]
fn real_mbr_is_not_mistaken_for_a_vbr() {
    // An MBR with a partition entry but no jump/FS magic at offset 0/3.
    assert!(!looks_like_vbr(&mbr_boot_area()));
    assert_eq!(detect_scheme(&mbr_boot_area()), Some(Scheme::Mbr));
}
