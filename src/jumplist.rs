//! Windows Jump List format constants — RED placeholder (tests precede impl).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destlist_header_offsets_and_size() {
        assert_eq!(DESTLIST_HEADER_FORMAT_VERSION_OFFSET, 0);
        assert_eq!(DESTLIST_HEADER_ENTRY_COUNT_OFFSET, 4);
        assert_eq!(DESTLIST_HEADER_PINNED_COUNT_OFFSET, 8);
        assert_eq!(DESTLIST_HEADER_LAST_ENTRY_NUMBER_OFFSET, 16);
        assert_eq!(DESTLIST_HEADER_LAST_REVISION_OFFSET, 24);
        assert_eq!(DESTLIST_HEADER_SIZE, 32);
    }

    #[test]
    fn destlist_entry_common_prefix_offsets() {
        assert_eq!(DESTLIST_ENTRY_DROID_VOLUME_GUID_OFFSET, 8);
        assert_eq!(DESTLIST_ENTRY_DROID_FILE_GUID_OFFSET, 24);
        assert_eq!(DESTLIST_ENTRY_BIRTH_DROID_VOLUME_GUID_OFFSET, 40);
        assert_eq!(DESTLIST_ENTRY_BIRTH_DROID_FILE_GUID_OFFSET, 56);
        assert_eq!(DESTLIST_ENTRY_HOSTNAME_OFFSET, 72);
        assert_eq!(DESTLIST_ENTRY_HOSTNAME_SIZE, 16);
        assert_eq!(DESTLIST_ENTRY_ENTRY_NUMBER_OFFSET, 88);
        assert_eq!(DESTLIST_ENTRY_LAST_ACCESS_FILETIME_OFFSET, 100);
        assert_eq!(DESTLIST_ENTRY_PIN_STATUS_OFFSET, 108);
    }

    #[test]
    fn destlist_entry_v1_layout() {
        assert_eq!(DESTLIST_ENTRY_V1_PATH_SIZE_OFFSET, 112);
        assert_eq!(DESTLIST_ENTRY_V1_PATH_OFFSET, 114);
    }

    #[test]
    fn destlist_entry_v2_layout_inserts_16_byte_block() {
        assert_eq!(DESTLIST_ENTRY_V2_STATUS_OFFSET, 112);
        assert_eq!(DESTLIST_ENTRY_V2_ACCESS_COUNT_OFFSET, 116);
        assert_eq!(DESTLIST_ENTRY_V2_UNKNOWN_OFFSET, 120);
        assert_eq!(DESTLIST_ENTRY_V2_PATH_SIZE_OFFSET, 128);
        assert_eq!(DESTLIST_ENTRY_V2_PATH_OFFSET, 130);
        assert_eq!(DESTLIST_ENTRY_V2_TRAILING_ALIGNMENT, 4);
    }

    #[test]
    fn pin_status_sentinel() {
        assert_eq!(DESTLIST_PIN_STATUS_UNPINNED, -1);
    }

    #[test]
    fn destlist_format_versions() {
        assert_eq!(DESTLIST_FORMAT_VERSION_WIN7, 1);
        assert_eq!(DESTLIST_FORMAT_VERSION_WIN10, 3);
    }

    #[test]
    fn custom_destinations_constants() {
        assert_eq!(CUSTOM_DESTINATIONS_FORMAT_VERSION, 2);
        assert_eq!(CUSTOM_DESTINATIONS_FOOTER_SIGNATURE, 0xBABF_FBAB);
    }

    #[test]
    fn category_type_mapping() {
        assert_eq!(CategoryType::from_u32(0), Some(CategoryType::Custom));
        assert_eq!(CategoryType::from_u32(1), Some(CategoryType::Known));
        assert_eq!(CategoryType::from_u32(2), Some(CategoryType::UserTasks));
        assert_eq!(CategoryType::from_u32(3), None);
    }

    #[test]
    fn known_category_mapping() {
        assert_eq!(KnownCategory::from_u32(1), Some(KnownCategory::Frequent));
        assert_eq!(KnownCategory::from_u32(2), Some(KnownCategory::Recent));
        assert_eq!(KnownCategory::from_u32(0), None);
    }

    #[test]
    fn lnk_clsid_matches_shlink() {
        assert_eq!(LNK_CLSID, crate::shlink::LINK_CLSID);
    }

    #[test]
    fn appid_poly_value() {
        assert_eq!(APPID_CRC64_POLY, 0x92C6_4265_D321_39A4);
    }

    #[test]
    fn appid_name_resolves_known_and_normalizes_case() {
        assert_eq!(appid_name("1b4dd67f29cb1962"), Some("Windows Explorer"));
        assert_eq!(appid_name("1B4DD67F29CB1962"), Some("Windows Explorer"));
        assert_eq!(appid_name("ffffffffffffffff"), None);
    }

    #[test]
    fn appid_crc64_is_deterministic_and_zero_for_empty() {
        assert_eq!(appid_crc64(&[]), 0);
        assert_ne!(appid_crc64(b"\x01"), 0);
    }
}
