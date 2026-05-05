//! Shannon entropy for packed/encrypted data detection.

/// Packed PE section threshold: entropy above this is likely compressed/encrypted.
pub const PACKED_SECTION_THRESHOLD: f32 = 6.8;

/// High entropy threshold for arbitrary byte buffers.
pub const HIGH_ENTROPY_THRESHOLD: f32 = 7.0;

/// Maximum possible entropy (uniform distribution over 256 byte values).
pub const MAX_BYTE_ENTROPY: f32 = 8.0;

/// Compute Shannon entropy (bits) of a byte buffer.
///
/// Returns 0.0 for empty or single-value buffers.
/// Maximum is 8.0 (uniform distribution over all 256 byte values).
/// Uses 256-bucket frequency counting — zero deps, no allocator needed beyond the stack array.
#[must_use]
pub fn byte_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut entropy = 0.0f32;
    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Returns `true` if the buffer's entropy exceeds HIGH_ENTROPY_THRESHOLD.
#[must_use]
pub fn is_high_entropy(data: &[u8]) -> bool {
    byte_entropy(data) > HIGH_ENTROPY_THRESHOLD
}

/// Returns `true` if entropy matches a packed PE section (above PACKED_SECTION_THRESHOLD).
#[must_use]
pub fn is_packed_pe_section(entropy: f32) -> bool {
    entropy > PACKED_SECTION_THRESHOLD
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_has_zero_entropy() {
        assert_eq!(byte_entropy(&[]), 0.0f32);
    }

    #[test]
    fn single_byte_repeated_has_zero_entropy() {
        let data = vec![0xABu8; 1024];
        assert_eq!(byte_entropy(&data), 0.0f32);
    }

    #[test]
    fn uniform_256_bytes_has_max_entropy() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = byte_entropy(&data);
        assert!((e - 8.0f32).abs() < 0.01, "expected ~8.0, got {e}");
    }

    #[test]
    fn random_like_data_is_high_entropy() {
        // One of each byte value repeated 4 times — uniform → entropy == 8.0
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        assert!(is_high_entropy(&data));
    }

    #[test]
    fn low_entropy_data_is_not_high() {
        let data = vec![b'A'; 1024];
        assert!(!is_high_entropy(&data));
    }

    #[test]
    fn packed_pe_section_threshold_is_6_8() {
        assert!((PACKED_SECTION_THRESHOLD - 6.8f32).abs() < f32::EPSILON);
    }

    #[test]
    fn high_entropy_threshold_is_7_0() {
        assert!((HIGH_ENTROPY_THRESHOLD - 7.0f32).abs() < f32::EPSILON);
    }

    #[test]
    fn entropy_is_packed_above_threshold() {
        assert!(is_packed_pe_section(6.9));
    }

    #[test]
    fn entropy_is_not_packed_at_threshold() {
        // strict greater-than: 6.8 is NOT above 6.8
        assert!(!is_packed_pe_section(6.8));
    }
}
