//! MBR boot-code (bootloader) fingerprints.
//!
//! Single source of truth identifying the bootloader occupying an MBR's 446-byte
//! boot-code area, for forensic tools (e.g. `mbr-forensic`). Each signature is a
//! set of `(offset, expected-bytes)` constraints; **all** must match.
//!
//! Signatures are evaluated in table order, so more specific entries
//! (Windows 7+ before Vista — they share the same stub and differ only in the
//! offset of the `"BOOTMGR"` string) come first.
//!
//! Sources:
//! - Windows Vista/7+ MBR — entry stub `33 C0 8E D0 BC 00 7C`
//!   (`xor ax,ax; mov ss,ax; mov sp,7C00h`) plus the `"BOOTMGR"` string; the
//!   string offset is 418 on Windows 7+ and 424 on Vista. Ref: Geoff Chappell,
//!   "The MBR" / "BOOTMGR"; Microsoft boot process docs.
//! - GRUB 2 `boot.img` — begins `EB 63 90` (`jmp .+0x65; nop`):
//!   GRUB source `grub-core/boot/i386/pc/boot.S`.
//! - GRUB Legacy `stage1` — begins `EB 48 90`: GRUB Legacy `stage1/stage1.S`.
//! - Syslinux MBR — `"SYSLINUX"` at offset 3: Syslinux `mbr/mbr.S`.

/// A bootloader fingerprint: a `name` and the `(offset, bytes)` constraints that
/// must all hold within the boot-code area.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BootCodeSignature {
    /// Bootloader name.
    pub name: &'static str,
    /// `(offset, expected-bytes)` constraints; all must match.
    pub patterns: &'static [(usize, &'static [u8])],
}

/// Windows entry stub shared by Vista and 7+ (`xor ax,ax; mov ss,ax; mov sp,7C00h`).
const WIN_STUB: &[u8] = &[0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C];

/// Known MBR boot-code signatures, in evaluation order.
pub const BOOT_CODE_SIGNATURES: &[BootCodeSignature] = &[
    BootCodeSignature { name: "Windows 7+", patterns: &[(0, WIN_STUB), (418, b"BOOTMGR")] },
    BootCodeSignature { name: "Windows Vista", patterns: &[(0, WIN_STUB), (424, b"BOOTMGR")] },
    BootCodeSignature { name: "Syslinux", patterns: &[(3, b"SYSLINUX")] },
    BootCodeSignature { name: "GRUB Legacy", patterns: &[(0, &[0xEB, 0x48, 0x90])] },
    BootCodeSignature { name: "GRUB 2", patterns: &[(0, &[0xEB, 0x63, 0x90])] },
];

/// Identify the bootloader from a boot-code area, returning the first matching
/// signature's name. Returns `None` when nothing matches.
#[must_use]
pub fn identify_loader(code: &[u8]) -> Option<&'static str> {
    BOOT_CODE_SIGNATURES
        .iter()
        .find(|sig| matches_all(code, sig.patterns))
        .map(|sig| sig.name)
}

/// `true` when every `(offset, bytes)` constraint holds within `code`.
fn matches_all(code: &[u8], patterns: &[(usize, &[u8])]) -> bool {
    patterns.iter().all(|(offset, pattern)| {
        offset
            .checked_add(pattern.len())
            .is_some_and(|end| code.len() >= end && &code[*offset..end] == *pattern)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot_with(stub: &[u8], at: usize, s: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 446];
        b[..stub.len()].copy_from_slice(stub);
        b[at..at + s.len()].copy_from_slice(s);
        b
    }

    #[test]
    fn identifies_windows7_by_bootmgr_offset_418() {
        assert_eq!(identify_loader(&boot_with(WIN_STUB, 418, b"BOOTMGR")), Some("Windows 7+"));
    }

    #[test]
    fn identifies_windows_vista_by_bootmgr_offset_424() {
        assert_eq!(identify_loader(&boot_with(WIN_STUB, 424, b"BOOTMGR")), Some("Windows Vista"));
    }

    #[test]
    fn identifies_grub2_and_syslinux() {
        let mut grub = vec![0u8; 446];
        grub[0..3].copy_from_slice(&[0xEB, 0x63, 0x90]);
        assert_eq!(identify_loader(&grub), Some("GRUB 2"));

        let mut sys = vec![0u8; 446];
        sys[3..11].copy_from_slice(b"SYSLINUX");
        assert_eq!(identify_loader(&sys), Some("Syslinux"));
    }

    #[test]
    fn unknown_and_short_are_none() {
        assert_eq!(identify_loader(&[0u8; 446]), None);
        assert_eq!(identify_loader(&[0u8; 4]), None); // too short, no panic
    }
}
