#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bagmru_registry_paths() {
        assert_eq!(
            NTUSER_BAGMRU_PATH,
            r"Software\Microsoft\Windows\Shell\BagMRU"
        );
        assert_eq!(NTUSER_BAGS_PATH, r"Software\Microsoft\Windows\Shell\Bags");
        assert_eq!(
            USRCLASS_BAGMRU_PATH,
            r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
        );
        assert_eq!(
            USRCLASS_BAGS_PATH,
            r"Local Settings\Software\Microsoft\Windows\Shell\Bags"
        );
    }

    #[test]
    fn class_type_byte_values() {
        assert_eq!(CLASS_ROOT_FOLDER, 0x1F);
        assert_eq!(CLASS_VOLUME_2E, 0x2E);
        assert_eq!(CLASS_VOLUME_2F, 0x2F);
        assert_eq!(CLASS_FILE_ENTRY_DIRECTORY, 0x31);
        assert_eq!(CLASS_FILE_ENTRY_FILE, 0x32);
        assert_eq!(CLASS_FILE_ENTRY_35, 0x35);
        assert_eq!(CLASS_FILE_ENTRY_36, 0x36);
        assert_eq!(CLASS_FILE_ENTRY_UNICODE, 0xB1);
        assert_eq!(CLASS_NETWORK_LOCATION, 0xC3);
    }

    #[test]
    fn class_type_mask_and_major_classes() {
        assert_eq!(CLASS_TYPE_MASK, 0x70);
        assert_eq!(MAJOR_CLASS_CLSID, 0x00);
        assert_eq!(MAJOR_CLASS_ROOT_FOLDER, 0x10);
        assert_eq!(MAJOR_CLASS_VOLUME, 0x20);
        assert_eq!(MAJOR_CLASS_FILE_ENTRY, 0x30);
        assert_eq!(MAJOR_CLASS_NETWORK_LOCATION, 0x40);
        assert_eq!(MAJOR_CLASS_COMPRESSED_FOLDER, 0x50);
        assert_eq!(MAJOR_CLASS_URI, 0x60);
        assert_eq!(MAJOR_CLASS_CONTROL_PANEL, 0x70);
    }

    #[test]
    fn major_class_derived_by_mask() {
        assert_eq!(major_class(CLASS_VOLUME_2E), MAJOR_CLASS_VOLUME);
        assert_eq!(major_class(CLASS_VOLUME_2F), MAJOR_CLASS_VOLUME);
        assert_eq!(major_class(CLASS_FILE_ENTRY_DIRECTORY), MAJOR_CLASS_FILE_ENTRY);
        assert_eq!(major_class(CLASS_FILE_ENTRY_FILE), MAJOR_CLASS_FILE_ENTRY);
        assert_eq!(major_class(CLASS_FILE_ENTRY_35), MAJOR_CLASS_FILE_ENTRY);
        assert_eq!(major_class(CLASS_FILE_ENTRY_36), MAJOR_CLASS_FILE_ENTRY);
        assert_eq!(major_class(CLASS_NETWORK_LOCATION), MAJOR_CLASS_NETWORK_LOCATION);
    }

    #[test]
    fn root_folder_my_computer_guid() {
        assert_eq!(MY_COMPUTER_GUID, "20D04FE0-3AEA-1069-A2D8-08002B30309D");
    }

    #[test]
    fn file_entry_extension_block_signatures() {
        assert_eq!(EXTENSION_BLOCK_0XBEEF0004, 0xBEEF_0004);
        assert_eq!(EXTENSION_BLOCK_0XBEEF0026, 0xBEEF_0026);
    }

    #[test]
    fn is_file_entry_classifier() {
        assert!(is_file_entry(CLASS_FILE_ENTRY_DIRECTORY));
        assert!(is_file_entry(CLASS_FILE_ENTRY_FILE));
        assert!(is_file_entry(CLASS_FILE_ENTRY_UNICODE));
        assert!(!is_file_entry(CLASS_VOLUME_2F));
        assert!(!is_file_entry(CLASS_ROOT_FOLDER));
        assert!(!is_file_entry(CLASS_NETWORK_LOCATION));
    }
}
