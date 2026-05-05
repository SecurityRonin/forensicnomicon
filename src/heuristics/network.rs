//! Network address and DGA heuristics.

// ── IPv4 classification ───────────────────────────────────────────────────────

/// Returns `true` if the IPv4 address is RFC 1918 private.
/// Ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
#[must_use]
pub fn is_private_ipv4(ip: [u8; 4]) -> bool {
    // 10.0.0.0/8
    if ip[0] == 10 {
        return true;
    }
    // 172.16.0.0/12 — second octet 16..=31
    if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
        return true;
    }
    // 192.168.0.0/16
    if ip[0] == 192 && ip[1] == 168 {
        return true;
    }
    false
}

/// Returns `true` if the IPv4 address is loopback (127.0.0.0/8).
#[must_use]
pub fn is_loopback_ipv4(ip: [u8; 4]) -> bool {
    ip[0] == 127
}

/// Returns `true` if the IPv4 address is link-local (169.254.0.0/16).
#[must_use]
pub fn is_link_local_ipv4(ip: [u8; 4]) -> bool {
    ip[0] == 169 && ip[1] == 254
}

/// Returns `true` if the IPv4 address is multicast (224.0.0.0/4).
#[must_use]
pub fn is_multicast_ipv4(ip: [u8; 4]) -> bool {
    ip[0] >= 224 && ip[0] <= 239
}

/// Returns `true` if the address is public (not private, loopback, link-local, or multicast).
/// Public IPv4 addresses reaching external infrastructure indicate potential C2/exfil.
#[must_use]
pub fn is_public_ipv4(ip: [u8; 4]) -> bool {
    !is_private_ipv4(ip) && !is_loopback_ipv4(ip) && !is_link_local_ipv4(ip) && !is_multicast_ipv4(ip)
}

// ── IPv6 classification ───────────────────────────────────────────────────────

/// Returns `true` if the IPv6 address is in the private ULA range (fc00::/7).
#[must_use]
pub fn is_private_ipv6(ip: [u8; 16]) -> bool {
    ip[0] & 0xFE == 0xFC
}

/// Returns `true` if the IPv6 address is an IPv4-mapped address (::ffff:x.x.x.x).
#[must_use]
pub fn is_ipv4_mapped_v6(ip: [u8; 16]) -> bool {
    ip[..10] == [0u8; 10] && ip[10] == 0xFF && ip[11] == 0xFF
}

/// Returns `true` if the IPv6 address is loopback (::1).
#[must_use]
pub fn is_loopback_ipv6(ip: [u8; 16]) -> bool {
    ip[..15] == [0u8; 15] && ip[15] == 1
}

// ── DGA (Domain Generation Algorithm) detection ───────────────────────────────

/// Minimum subdomain length to consider for DGA analysis.
pub const DGA_MIN_LENGTH: usize = 12;

/// Maximum vowel ratio (parts-per-thousand) in a DGA candidate subdomain.
/// DGA domains are consonant-heavy; legitimate domains have more vowels.
pub const DGA_MAX_VOWEL_RATIO_PPT: u32 = 200; // < 20 %

/// Minimum consecutive consonant run length that raises suspicion.
pub const DGA_MIN_CONSONANT_RUN: u8 = 4;

/// Returns the ratio of vowels to alphabetic characters in parts-per-thousand.
/// Returns 0 if there are no alphabetic characters.
#[must_use]
pub fn vowel_ratio_ppt(s: &str) -> u32 {
    let mut alpha: u32 = 0;
    let mut vowels: u32 = 0;
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            alpha += 1;
            if matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u') {
                vowels += 1;
            }
        }
    }
    if alpha == 0 {
        return 0;
    }
    vowels * 1000 / alpha
}

/// Returns the length of the longest consecutive consonant run in `s`.
#[must_use]
pub fn consonant_run_max(s: &str) -> u8 {
    let mut max_run: u8 = 0;
    let mut cur_run: u8 = 0;
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            if !matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u') {
                cur_run = cur_run.saturating_add(1);
                if cur_run > max_run {
                    max_run = cur_run;
                }
            } else {
                cur_run = 0;
            }
        } else {
            cur_run = 0;
        }
    }
    max_run
}

/// Returns `true` if the subdomain looks like a DGA-generated name:
/// - length >= DGA_MIN_LENGTH
/// - vowel_ratio_ppt < DGA_MAX_VOWEL_RATIO_PPT
/// - consonant_run_max >= DGA_MIN_CONSONANT_RUN
#[must_use]
pub fn is_likely_dga(subdomain: &str) -> bool {
    subdomain.len() >= DGA_MIN_LENGTH
        && vowel_ratio_ppt(subdomain) < DGA_MAX_VOWEL_RATIO_PPT
        && consonant_run_max(subdomain) >= DGA_MIN_CONSONANT_RUN
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── IPv4 private ──────────────────────────────────────────────────────────

    #[test]
    fn private_10_x_x_x_is_private() {
        assert!(is_private_ipv4([10, 0, 0, 1]));
        assert!(is_private_ipv4([10, 255, 255, 255]));
    }

    #[test]
    fn private_172_16_x_x_is_private() {
        assert!(is_private_ipv4([172, 16, 0, 1]));
    }

    #[test]
    fn private_172_31_x_x_is_private() {
        assert!(is_private_ipv4([172, 31, 255, 254]));
    }

    #[test]
    fn private_172_15_x_x_is_not_private() {
        // 172.15.x.x is just outside the 172.16.0.0/12 range
        assert!(!is_private_ipv4([172, 15, 0, 1]));
    }

    #[test]
    fn private_192_168_x_x_is_private() {
        assert!(is_private_ipv4([192, 168, 1, 1]));
        assert!(is_private_ipv4([192, 168, 255, 255]));
    }

    #[test]
    fn public_8_8_8_8_is_not_private() {
        assert!(!is_private_ipv4([8, 8, 8, 8]));
    }

    // ── IPv4 loopback ─────────────────────────────────────────────────────────

    #[test]
    fn loopback_127_0_0_1() {
        assert!(is_loopback_ipv4([127, 0, 0, 1]));
    }

    #[test]
    fn loopback_127_1_2_3() {
        assert!(is_loopback_ipv4([127, 1, 2, 3]));
    }

    #[test]
    fn non_loopback_126_x_x_x() {
        assert!(!is_loopback_ipv4([126, 0, 0, 1]));
    }

    // ── IPv4 link-local ───────────────────────────────────────────────────────

    #[test]
    fn link_local_169_254_x_x() {
        assert!(is_link_local_ipv4([169, 254, 1, 1]));
        assert!(is_link_local_ipv4([169, 254, 0, 0]));
    }

    // ── IPv4 multicast ────────────────────────────────────────────────────────

    #[test]
    fn multicast_224_x_x_x() {
        assert!(is_multicast_ipv4([224, 0, 0, 1]));
    }

    #[test]
    fn multicast_239_x_x_x() {
        assert!(is_multicast_ipv4([239, 255, 255, 255]));
    }

    #[test]
    fn non_multicast_240_x_x_x() {
        // 240.0.0.0 is reserved, not multicast (224–239 is the multicast range)
        assert!(!is_multicast_ipv4([240, 0, 0, 1]));
    }

    // ── IPv4 public ───────────────────────────────────────────────────────────

    #[test]
    fn public_1_1_1_1_is_public() {
        assert!(is_public_ipv4([1, 1, 1, 1]));
    }

    #[test]
    fn private_address_is_not_public() {
        assert!(!is_public_ipv4([10, 0, 0, 1]));
        assert!(!is_public_ipv4([192, 168, 0, 1]));
    }

    #[test]
    fn loopback_is_not_public() {
        assert!(!is_public_ipv4([127, 0, 0, 1]));
    }

    // ── IPv6 ─────────────────────────────────────────────────────────────────

    #[test]
    fn fc_prefix_is_private_ipv6() {
        let mut ip = [0u8; 16];
        ip[0] = 0xFC;
        assert!(is_private_ipv6(ip));
    }

    #[test]
    fn fd_prefix_is_private_ipv6() {
        // fd00:: is within fc00::/7
        let mut ip = [0u8; 16];
        ip[0] = 0xFD;
        assert!(is_private_ipv6(ip));
    }

    #[test]
    fn _2001_db8_is_not_private_ipv6() {
        let mut ip = [0u8; 16];
        ip[0] = 0x20;
        ip[1] = 0x01;
        ip[2] = 0x0D;
        ip[3] = 0xB8;
        assert!(!is_private_ipv6(ip));
    }

    #[test]
    fn ipv4_mapped_ffff_prefix() {
        let ip: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 93, 184, 216, 34];
        assert!(is_ipv4_mapped_v6(ip));
    }

    #[test]
    fn loopback_v6_is_loopback() {
        let mut ip = [0u8; 16];
        ip[15] = 1;
        assert!(is_loopback_ipv6(ip));
    }

    // ── DGA: vowel_ratio_ppt ──────────────────────────────────────────────────

    #[test]
    fn vowel_ratio_all_vowels_is_1000ppt() {
        assert_eq!(vowel_ratio_ppt("aeiou"), 1000);
    }

    #[test]
    fn vowel_ratio_no_vowels_is_0() {
        assert_eq!(vowel_ratio_ppt("bcdfgh"), 0);
    }

    #[test]
    fn vowel_ratio_mixed() {
        // "abcd" — 1 vowel out of 4 alpha = 250 ppt
        assert_eq!(vowel_ratio_ppt("abcd"), 250);
    }

    // ── DGA: consonant_run_max ────────────────────────────────────────────────

    #[test]
    fn consonant_run_typical() {
        // "xkcd" → run of 4 consonants
        assert_eq!(consonant_run_max("xkcd"), 4);
    }

    #[test]
    fn consonant_run_empty_is_zero() {
        assert_eq!(consonant_run_max(""), 0);
    }

    // ── DGA: is_likely_dga ────────────────────────────────────────────────────

    #[test]
    fn dga_short_domain_not_flagged() {
        // len < DGA_MIN_LENGTH (12)
        assert!(!is_likely_dga("xkcdwplqrst")); // 11 chars
    }

    #[test]
    fn dga_high_vowel_ratio_not_flagged() {
        // long but vowel-rich → legitimate-looking
        assert!(!is_likely_dga("aeioumicrosofting")); // vowel-heavy
    }

    #[test]
    fn dga_typical_legitimate_domain_not_flagged() {
        // "microsoft" is 9 chars — shorter than DGA_MIN_LENGTH
        assert!(!is_likely_dga("microsoft"));
    }

    #[test]
    fn dga_suspicious_long_consonant_heavy() {
        // 16 chars, no vowels, long consonant run → DGA
        assert!(is_likely_dga("xkcdwplqrstvmnbf"));
    }

    // ── DGA: constants ────────────────────────────────────────────────────────

    #[test]
    fn dga_constants_correct() {
        assert_eq!(DGA_MIN_LENGTH, 12);
        assert_eq!(DGA_MAX_VOWEL_RATIO_PPT, 200);
        assert_eq!(DGA_MIN_CONSONANT_RUN, 4);
    }
}
