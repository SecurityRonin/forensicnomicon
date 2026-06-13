#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_and_clsid() {
        assert_eq!(HEADER_SIZE, 0x0000_004C);
        assert_eq!(LINK_CLSID, "00021401-0000-0000-C000-000000000046");
    }

    #[test]
    fn link_flags_bit_positions() {
        assert_eq!(LINK_FLAG_HAS_LINK_TARGET_ID_LIST, 1 << 0);
        assert_eq!(LINK_FLAG_HAS_LINK_INFO, 1 << 1);
        assert_eq!(LINK_FLAG_HAS_NAME, 1 << 2);
        assert_eq!(LINK_FLAG_HAS_RELATIVE_PATH, 1 << 3);
        assert_eq!(LINK_FLAG_HAS_WORKING_DIR, 1 << 4);
        assert_eq!(LINK_FLAG_HAS_ARGUMENTS, 1 << 5);
        assert_eq!(LINK_FLAG_HAS_ICON_LOCATION, 1 << 6);
        assert_eq!(LINK_FLAG_IS_UNICODE, 1 << 7);
        assert_eq!(LINK_FLAG_FORCE_NO_LINK_INFO, 1 << 8);
        assert_eq!(LINK_FLAG_HAS_EXP_STRING, 1 << 9);
        assert_eq!(LINK_FLAG_RUN_IN_SEPARATE_PROCESS, 1 << 10);
        assert_eq!(LINK_FLAG_HAS_DARWIN_ID, 1 << 12);
        assert_eq!(LINK_FLAG_RUN_AS_USER, 1 << 13);
        assert_eq!(LINK_FLAG_HAS_EXP_ICON, 1 << 14);
        assert_eq!(LINK_FLAG_NO_PIDL_ALIAS, 1 << 15);
        assert_eq!(LINK_FLAG_RUN_WITH_SHIM_LAYER, 1 << 17);
        assert_eq!(LINK_FLAG_FORCE_NO_LINK_TRACK, 1 << 18);
        assert_eq!(LINK_FLAG_ENABLE_TARGET_METADATA, 1 << 19);
        assert_eq!(LINK_FLAG_DISABLE_LINK_PATH_TRACKING, 1 << 20);
        assert_eq!(LINK_FLAG_DISABLE_KNOWN_FOLDER_TRACKING, 1 << 21);
        assert_eq!(LINK_FLAG_DISABLE_KNOWN_FOLDER_ALIAS, 1 << 22);
        assert_eq!(LINK_FLAG_ALLOW_LINK_TO_LINK, 1 << 23);
        assert_eq!(LINK_FLAG_UNALIAS_ON_SAVE, 1 << 24);
        assert_eq!(LINK_FLAG_PREFER_ENVIRONMENT_PATH, 1 << 25);
        assert_eq!(LINK_FLAG_KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET, 1 << 26);
    }

    #[test]
    fn file_attributes_bit_positions() {
        assert_eq!(FILE_ATTRIBUTE_READONLY, 1 << 0);
        assert_eq!(FILE_ATTRIBUTE_HIDDEN, 1 << 1);
        assert_eq!(FILE_ATTRIBUTE_SYSTEM, 1 << 2);
        assert_eq!(FILE_ATTRIBUTE_DIRECTORY, 1 << 4);
        assert_eq!(FILE_ATTRIBUTE_ARCHIVE, 1 << 5);
        assert_eq!(FILE_ATTRIBUTE_NORMAL, 1 << 7);
        assert_eq!(FILE_ATTRIBUTE_TEMPORARY, 1 << 8);
        assert_eq!(FILE_ATTRIBUTE_SPARSE_FILE, 1 << 9);
        assert_eq!(FILE_ATTRIBUTE_REPARSE_POINT, 1 << 10);
        assert_eq!(FILE_ATTRIBUTE_COMPRESSED, 1 << 11);
        assert_eq!(FILE_ATTRIBUTE_OFFLINE, 1 << 12);
        assert_eq!(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, 1 << 13);
        assert_eq!(FILE_ATTRIBUTE_ENCRYPTED, 1 << 14);
    }

    #[test]
    fn extra_data_block_signatures() {
        assert_eq!(EXTRA_ENVIRONMENT_VARIABLE_DATA_BLOCK, 0xA000_0001);
        assert_eq!(EXTRA_CONSOLE_DATA_BLOCK, 0xA000_0002);
        assert_eq!(EXTRA_TRACKER_DATA_BLOCK, 0xA000_0003);
        assert_eq!(EXTRA_CONSOLE_FE_DATA_BLOCK, 0xA000_0004);
        assert_eq!(EXTRA_SPECIAL_FOLDER_DATA_BLOCK, 0xA000_0005);
        assert_eq!(EXTRA_DARWIN_DATA_BLOCK, 0xA000_0006);
        assert_eq!(EXTRA_ICON_ENVIRONMENT_DATA_BLOCK, 0xA000_0007);
        assert_eq!(EXTRA_SHIM_DATA_BLOCK, 0xA000_0008);
        assert_eq!(EXTRA_PROPERTY_STORE_DATA_BLOCK, 0xA000_0009);
        assert_eq!(EXTRA_VISTA_AND_ABOVE_ID_LIST_DATA_BLOCK, 0xA000_000A);
        assert_eq!(EXTRA_KNOWN_FOLDER_DATA_BLOCK, 0xA000_000B);
    }

    #[test]
    fn extra_data_terminal_block() {
        // A block size < 0x4 terminates the ExtraData section ([MS-SHLLINK] 2.5).
        assert_eq!(EXTRA_DATA_TERMINAL_BLOCK_SIZE, 0x0000_0004);
    }
}
