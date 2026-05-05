//! Windows virtual address space and VAD/VMA protection heuristics.

// x64 canonical address space: user 0x0..=0x00007FFF_FFFFFFFF,
// kernel 0xFFFF0000_00000000..=0xFFFFFFFF_FFFFFFFF.
// Addresses in between (bits 48-63 not sign-extended) are non-canonical.

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_address_zero_is_user() {
        assert!(is_user_address_x64(0));
    }

    #[test]
    fn user_address_max_boundary() {
        assert!(is_user_address_x64(USER_SPACE_MAX_X64));
    }

    #[test]
    fn user_address_just_above_max() {
        assert!(!is_user_address_x64(USER_SPACE_MAX_X64 + 1));
    }

    #[test]
    fn kernel_address_min_boundary() {
        assert!(is_kernel_address_x64(KERNEL_SPACE_MIN_X64));
    }

    #[test]
    fn kernel_address_max() {
        assert!(is_kernel_address_x64(u64::MAX));
    }

    #[test]
    fn kernel_address_just_below() {
        assert!(!is_kernel_address_x64(KERNEL_SPACE_MIN_X64 - 1));
    }

    #[test]
    fn canonical_user_address() {
        assert!(is_canonical_x64(0x0000_1234_5678_9ABC));
    }

    #[test]
    fn canonical_kernel_address() {
        assert!(is_canonical_x64(0xFFFF_8000_0000_0000));
    }

    #[test]
    fn non_canonical_address() {
        // between user max and kernel min — non-canonical
        assert!(!is_canonical_x64(0x0001_0000_0000_0000));
    }

    #[test]
    fn rwx_page_execute_readwrite() {
        assert!(is_rwx_page(PAGE_EXECUTE_READWRITE));
    }

    #[test]
    fn rwx_page_execute_writecopy() {
        assert!(is_rwx_page(PAGE_EXECUTE_WRITECOPY));
    }

    #[test]
    fn rwx_readonly_is_not_rwx() {
        assert!(!is_rwx_page(0x02));
    }

    #[test]
    fn shellcode_size_below_page() {
        assert!(is_shellcode_candidate_size(1024));
    }

    #[test]
    fn shellcode_size_zero_is_not_candidate() {
        assert!(!is_shellcode_candidate_size(0));
    }

    #[test]
    fn shellcode_size_full_page_is_not_candidate() {
        assert!(!is_shellcode_candidate_size(4096));
    }

    #[test]
    fn large_region_one_gib() {
        assert!(is_large_private_region(1_073_741_824));
    }

    #[test]
    fn large_region_below_gib() {
        assert!(!is_large_private_region(1_073_741_823));
    }
}
