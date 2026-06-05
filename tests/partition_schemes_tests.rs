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
