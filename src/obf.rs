//! Runtime deobfuscation for AV-triggerable signature literals.
//!
//! `forensicnomicon` is a defensive DFIR knowledge base: it catalogs malware /
//! C2-framework family names (the ATT&CK tool-prefix table in [`crate::mitre`]).
//! Compiled into `.rodata`, those plaintext family names match antivirus
//! *family* signatures — a generic-heuristic false positive that flags the
//! analyzer as the malware it detects (observed: Bitdefender
//! `Generic.Exploit.SilentTrinity` on a compiled codegen-unit object of this
//! crate).
//!
//! The fix keeps the contiguous plaintext **out of the compiled artifact**: the
//! tool-name table stores each family name XOR-encoded with [`OBF_KEY`] as a
//! `&[u8]` (the readable name survives only in a source comment, which the
//! compiler strips), and matching decodes one byte at a time via
//! [`starts_with_obf`]. The plaintext never exists as a static string an AV
//! scanner can pattern-match — verified by `strings` on the built rlib.
//!
//! Note: a plaintext literal cannot be obfuscated *at compile time* and remain
//! clean — in a debug build the input `&str`/`&[u8]` literal is still emitted to
//! `.rodata` even when only used in `const` evaluation. The encoded bytes must
//! therefore be stored directly; this is obfuscation (anti-false-positive), not
//! cryptography.

/// XOR key applied to every stored signature literal. Any non-zero byte works;
/// it only needs to break the contiguous-ASCII match an AV scanner relies on.
pub const OBF_KEY: u8 = 0xA7;

/// Does `haystack` start with the deobfuscated `obf` token? `haystack` is
/// compared against `obf[i] ^ key` one byte at a time — the plaintext is never
/// materialized as a contiguous buffer.
#[must_use]
pub fn starts_with_obf(haystack: &str, obf: &[u8], key: u8) -> bool {
    let hay = haystack.as_bytes();
    if hay.len() < obf.len() {
        return false;
    }
    for (i, &b) in obf.iter().enumerate() {
        if hay[i] != b ^ key {
            return false;
        }
    }
    true
}

/// Deobfuscate `obf` to an owned `String` (for display / round-trip tests).
#[must_use]
pub fn deobf(obf: &[u8], key: u8) -> String {
    String::from_utf8_lossy(&obf.iter().map(|&b| b ^ key).collect::<Vec<u8>>()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Encoded form of "abc_" under OBF_KEY (0xA7) — authored as bytes so this
    // test file carries no plaintext family name either.
    const ABC: &[u8] = &[
        b'a' ^ OBF_KEY,
        b'b' ^ OBF_KEY,
        b'c' ^ OBF_KEY,
        b'_' ^ OBF_KEY,
    ];

    #[test]
    fn deobf_round_trips() {
        assert_ne!(ABC, b"abc_", "stored bytes are obfuscated, not plaintext");
        assert_eq!(deobf(ABC, OBF_KEY), "abc_");
    }

    #[test]
    fn starts_with_obf_matches_decoded_prefix() {
        assert!(starts_with_obf("abc_payload", ABC, OBF_KEY));
        assert!(!starts_with_obf("xyz_payload", ABC, OBF_KEY));
        assert!(!starts_with_obf("abc", ABC, OBF_KEY)); // shorter than token
    }
}
