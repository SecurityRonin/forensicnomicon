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
    BootkitMarker { name: "Stoned", needle: b"Your PC is now Stoned!" },
    BootkitMarker { name: "Stoned", needle: b"LEGALISE MARIJUANA" },
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
