//! Boot-sector / MBR malware plaintext markers.
//!
//! Single source of truth for documented boot-sector-malware byte markers, for
//! forensic tools that scan an MBR/VBR boot-code area (e.g. `mbr-forensic`).
//! Markers are matched as substrings anywhere in the boot code, so each needs
//! only the literal bytes — no fragile fixed offsets.
//!
//! The seed set is deliberately limited to **publicly-documented historical
//! markers** so that no pattern here is fabricated. Operators extend
//! [`BOOTKIT_MARKERS`] with vetted markers from their own threat intel.
//!
//! Sources:
//! - "Stoned" boot-sector virus (1987) — taunt strings `"Your PC is now Stoned!"`
//!   and `"LEGALISE MARIJUANA"`: F-Secure / virus encyclopedia descriptions;
//!   <https://en.wikipedia.org/wiki/Stoned_(computer_virus)>

/// One boot-sector-malware marker: a family `name` and the literal `needle`
/// bytes that, if present anywhere in the boot code, identify it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BootkitMarker {
    /// Malware family / variant name reported on a match.
    pub name: &'static str,
    /// Literal bytes searched for anywhere in the boot-code area.
    pub needle: &'static [u8],
}

/// Seed table of documented boot-sector-malware markers (see module docs).
pub const BOOTKIT_MARKERS: &[BootkitMarker] = &[
    BootkitMarker {
        name: "Stoned",
        needle: b"Your PC is now Stoned!",
    },
    BootkitMarker {
        name: "Stoned",
        needle: b"LEGALISE MARIJUANA",
    },
];

/// Scan `boot_code` for every known marker, returning the distinct family names
/// that matched, in table order (each family reported at most once).
#[must_use]
pub fn scan(boot_code: &[u8]) -> Vec<&'static str> {
    let mut hits: Vec<&'static str> = Vec::new();
    for m in BOOTKIT_MARKERS {
        if contains(boot_code, m.needle) && !hits.contains(&m.name) {
            hits.push(m.name);
        }
    }
    hits
}

/// `true` when `needle` occurs anywhere in `haystack`. Empty needles never match.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

// ── Signature-free heuristic knowledge ───────────────────────────────────────
//
// The authoritative open reference (ANSSI `bootcode_parser`) detects MBR/VBR
// bootkits by hash-whitelisting known-good boot code and falling back to
// HEURISTICS, not per-family byte signatures — the significant families (TDL4,
// Rovnix) are polymorphic by design, so robust detection is signature-free. The
// constants below are the cited knowledge those heuristics consume; the
// detection logic itself lives in the consuming crate (e.g. `mbr-forensic`).
//
// Sources:
// - ANSSI `bootcode_parser` (hash-whitelist + heuristics; the expected-interrupt
//   set): <https://github.com/ANSSI-FR/bootcode_parser>
// - Mebroot/Sinowal — original MBR at sector 62, payload sectors 60/61; INT 13h
//   read-spoofing: Florio & Kasslin, Virus Bulletin 2008, "Your computer is now
//   stoned (…again!)":
//   <https://www.virusbulletin.com/virusbulletin/2008/04/your-computer-now-stoned-again>
// - Petya (Red) — original MBR (XOR 0x37) at sector 56, repeating-0x37
//   verification sector 55: Kaspersky Securelist, "Petya: the two-in-one trojan"
//   <https://securelist.com/petya-the-two-in-one-trojan/74609/>
// - NotPetya — sector-0 backup at sector 34: Fortinet, "Petya's Master Boot
//   Record Infection"
//   <https://www.fortinet.com/blog/threat-research/petya-s-master-boot-record-infection>
// - TDL4 — original MBR in an end-of-disk RC4 container (no fixed LBA): Kaspersky
//   Securelist, "TDL4 – Top Bot" <https://securelist.com/tdl4-top-bot/36152/>
// - Boot-code entropy 7.0 (suspect) / 7.5 (strong): general packer-detection
//   figures borrowed by analogy (no MBR-specific authority) — Lyda & Hamrock,
//   IEEE S&P 2007, "Using Entropy Analysis to Find Encrypted and Packed Malware".
//   Self-decrypting stubs can sit below these, so treat as triage, not proof.

/// A sector where a documented MBR bootkit stashes the original MBR or a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct StashSector {
    /// LBA of the stash, on a 512-byte-sector disk.
    pub lba: u64,
    /// Malware family that uses this location.
    pub family: &'static str,
    /// What is stored there.
    pub note: &'static str,
}

/// LBAs where documented MBR bootkits stash the original MBR or payload sectors.
///
/// A structurally-MBR-like sector (ending in `0x55AA`) found at one of these — or
/// anywhere in [`TRACK0_GAP`] or the disk's final sectors — that is NOT the live
/// MBR at LBA 0 is the strongest signature-free bootkit indicator. (TDL4 and
/// Guntior instead stash at the disk's end, which has no fixed LBA and must be
/// scanned by offset from the last sector.)
pub const ORIGINAL_MBR_STASH_SECTORS: &[StashSector] = &[
    StashSector {
        lba: 60,
        family: "Mebroot/Sinowal",
        note: "kernel patcher",
    },
    StashSector {
        lba: 61,
        family: "Mebroot/Sinowal",
        note: "payload loader",
    },
    StashSector {
        lba: 62,
        family: "Mebroot/Sinowal",
        note: "original MBR",
    },
    StashSector {
        lba: 56,
        family: "Petya (Red)",
        note: "original MBR, XOR 0x37",
    },
    StashSector {
        lba: 55,
        family: "Petya (Red)",
        note: "verification sector (repeating 0x37)",
    },
    StashSector {
        lba: 34,
        family: "NotPetya",
        note: "original sector-0 backup",
    },
];

/// The legacy 'track-0 gap' — LBAs 1..=62, between the MBR (LBA 0) and the first
/// conventionally-aligned partition at LBA 63. A classic stash region; any hidden
/// MBR-shaped sector here is suspicious.
pub const TRACK0_GAP: core::ops::RangeInclusive<u64> = 1..=62;

/// Boot-code Shannon entropy (bits/byte) above which the 446-byte code area is
/// *suspected* packed/encrypted (triage only — borrowed from general packer
/// literature; self-decrypting stubs can sit below it).
pub const PACKED_BOOT_CODE_ENTROPY_SUSPECT: f64 = 7.0;
/// Entropy above which packing/encryption is *strongly* indicated.
pub const PACKED_BOOT_CODE_ENTROPY_STRONG: f64 = 7.5;

/// BIOS real-mode interrupt vectors a legitimate MBR/VBR boot stub is expected to
/// invoke: video `0x10`, disk `0x13`, blocking `0x18`, time `0x1a`. An `int` to
/// any other vector in disassembled boot code is a suspicious indicator (ANSSI).
pub const EXPECTED_BOOT_INTERRUPT_VECTORS: &[u8] = &[0x10, 0x13, 0x18, 0x1a];

/// Documented stash entries whose `lba` equals `lba` (a sector may be used by
/// more than one family / for more than one purpose). The returned iterator is
/// lazy — collect or inspect it.
pub fn stash_sectors_at(lba: u64) -> impl Iterator<Item = &'static StashSector> {
    ORIGINAL_MBR_STASH_SECTORS
        .iter()
        .filter(move |s| s.lba == lba)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_stoned_marker() {
        let mut boot = vec![0u8; 446];
        boot[0x100..0x100 + 22].copy_from_slice(b"Your PC is now Stoned!");
        assert_eq!(scan(&boot), vec!["Stoned"]);
    }

    #[test]
    fn dedups_repeated_family() {
        let mut boot = vec![0u8; 446];
        boot[0x10..0x10 + 22].copy_from_slice(b"Your PC is now Stoned!");
        boot[0x80..0x80 + 18].copy_from_slice(b"LEGALISE MARIJUANA");
        assert_eq!(scan(&boot), vec!["Stoned"]);
    }

    #[test]
    fn clean_boot_code_finds_nothing() {
        assert!(scan(&[0u8; 446]).is_empty());
    }

    #[test]
    fn table_is_non_empty() {
        assert!(!BOOTKIT_MARKERS.is_empty());
    }
}
