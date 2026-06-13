//! ShellBags — `BagMRU` PIDL / shell-item (`ITEMIDLIST`) forensic knowledge.
//!
//! Windows Explorer persists per-folder view preferences (window size,
//! position, sort) keyed by the folder's shell **PIDL** under the `BagMRU` /
//! `Bags` registry hierarchy. The forensic value is the side effect: an entry
//! exists for a folder **because the user navigated to it**, and the entry —
//! and the embedded `ITEMIDLIST` path with its MAC timestamps — **persists
//! after the folder, volume, or removable device is gone**. ShellBags are
//! therefore evidence of folder access that outlives the folder itself.
//!
//! A `BagMRU` value holds an [`ITEMIDLIST`]: a list of variable-length
//! **shell items**, each beginning with a 2-byte size and a 1-byte **class
//! type indicator**. The high nibble of that byte (mask [`CLASS_TYPE_MASK`])
//! selects the *major* class (volume / file entry / network / …); the full
//! byte selects the specific subtype.
//!
//! This module is knowledge only — the registry paths, the class-type byte
//! values + major-class mask, the My-Computer root GUID, and the file-entry
//! extension-block signatures. The PIDL/shell-item parser lives in the
//! consuming reader (`shellbag-core`), per forensicnomicon's knowledge-only
//! charter.
//!
//! # Authoritative sources
//!
//! - libyal `libfwsi`, *Windows Shell Item format* (J. Metz) — the
//!   reverse-engineered reference for the class-type indicator and the per-type
//!   layouts (root 0x1f, volume 0x2e/0x2f, file entry 0x30/0x31/0x32/0xb1,
//!   network 0x40/0xc3, and the 0x70-mask major classes):
//!   <https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc>
//! - dtformats — *Windows Shellbags* — the `NTUSER.DAT` `Shell\BagMRU`+`Bags`
//!   and `UsrClass.dat` `Local Settings\…\Shell\BagMRU` registry layout:
//!   <https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Shellbags.asciidoc>
//! - Eric Zimmerman — *ShellBags Explorer* / *Shellbags in Depth* — the
//!   forensic interpretation (folder access persisting past device removal):
//!   <https://ericzimmerman.github.io/>

/// `NTUSER.DAT` ShellBags MRU subkey — the per-user `BagMRU` PIDL tree.
pub const NTUSER_BAGMRU_PATH: &str = r"Software\Microsoft\Windows\Shell\BagMRU";

/// `NTUSER.DAT` ShellBags view-settings subkey (`Bags`).
pub const NTUSER_BAGS_PATH: &str = r"Software\Microsoft\Windows\Shell\Bags";

/// `UsrClass.dat` ShellBags MRU subkey — where Vista+ stores most navigation
/// (the richer of the two hives).
pub const USRCLASS_BAGMRU_PATH: &str = r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU";

/// `UsrClass.dat` ShellBags view-settings subkey (`Bags`).
pub const USRCLASS_BAGS_PATH: &str = r"Local Settings\Software\Microsoft\Windows\Shell\Bags";

// ── Shell-item class type indicators (libfwsi) ───────────────────────────────

/// Bitmask isolating the *major* class from a class-type indicator byte: the
/// high nibble (`indicator & 0x70`).
pub const CLASS_TYPE_MASK: u8 = 0x70;

/// Major class `0x00` — CLSID/delegate item (e.g. GameExplorer, MTP).
pub const MAJOR_CLASS_CLSID: u8 = 0x00;
/// Major class `0x10` — root folder (My Computer / Network / Recycle Bin, …).
pub const MAJOR_CLASS_ROOT_FOLDER: u8 = 0x10;
/// Major class `0x20` — volume (drive).
pub const MAJOR_CLASS_VOLUME: u8 = 0x20;
/// Major class `0x30` — file entry (directory or file).
pub const MAJOR_CLASS_FILE_ENTRY: u8 = 0x30;
/// Major class `0x40` — network location.
pub const MAJOR_CLASS_NETWORK_LOCATION: u8 = 0x40;
/// Major class `0x50` — compressed folder (zip).
pub const MAJOR_CLASS_COMPRESSED_FOLDER: u8 = 0x50;
/// Major class `0x60` — URI / internet shortcut.
pub const MAJOR_CLASS_URI: u8 = 0x60;
/// Major class `0x70` — control panel.
pub const MAJOR_CLASS_CONTROL_PANEL: u8 = 0x70;

/// Root folder shell item (`0x1F`) — carries a shell-folder GUID (My Computer,
/// Network, …). Note `0x1F & 0x70 == 0x10`.
pub const CLASS_ROOT_FOLDER: u8 = 0x1F;
/// Volume shell item, variant `0x2E`.
pub const CLASS_VOLUME_2E: u8 = 0x2E;
/// Volume shell item, variant `0x2F` (drive letter, e.g. `C:\`).
pub const CLASS_VOLUME_2F: u8 = 0x2F;
/// File entry shell item — **directory** (`0x31`).
pub const CLASS_FILE_ENTRY_DIRECTORY: u8 = 0x31;
/// File entry shell item — **file** (`0x32`).
pub const CLASS_FILE_ENTRY_FILE: u8 = 0x32;
/// File entry shell item variant `0x35`.
pub const CLASS_FILE_ENTRY_35: u8 = 0x35;
/// File entry shell item variant `0x36`.
pub const CLASS_FILE_ENTRY_36: u8 = 0x36;
/// File entry shell item with a Unicode primary name (`0xB1`).
/// Note `0xB1 & 0x70 == 0x30` (still a file entry).
pub const CLASS_FILE_ENTRY_UNICODE: u8 = 0xB1;
/// Network location / share shell item (`0xC3`). Note `0xC3 & 0x70 == 0x40`.
pub const CLASS_NETWORK_LOCATION: u8 = 0xC3;

/// The "My Computer" / "This PC" shell-folder GUID — the canonical root-folder
/// item (`CLSID` display name varies by OS version).
pub const MY_COMPUTER_GUID: &str = "20D04FE0-3AEA-1069-A2D8-08002B30309D";

/// File-entry extension block `0xBEEF0004` — carries the long name and the
/// FAT creation/access timestamps appended after the short name.
pub const EXTENSION_BLOCK_0XBEEF0004: u32 = 0xBEEF_0004;

/// File-entry extension block `0xBEEF0026` — carries 64-bit FILETIME
/// create/modify/access timestamps (Windows 8.1+).
pub const EXTENSION_BLOCK_0XBEEF0026: u32 = 0xBEEF_0026;

/// The *major* class of a shell item, derived from its class-type indicator
/// byte by [`CLASS_TYPE_MASK`].
#[must_use]
pub fn major_class(class_type_indicator: u8) -> u8 {
    class_type_indicator & CLASS_TYPE_MASK
}

/// Whether a class-type indicator denotes a **file entry** (directory or file),
/// i.e. its major class is [`MAJOR_CLASS_FILE_ENTRY`]. Covers `0x31`/`0x32`/
/// `0x35`/`0x36`/`0xB1`.
#[must_use]
pub fn is_file_entry(class_type_indicator: u8) -> bool {
    major_class(class_type_indicator) == MAJOR_CLASS_FILE_ENTRY
}

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
        assert_eq!(
            major_class(CLASS_FILE_ENTRY_DIRECTORY),
            MAJOR_CLASS_FILE_ENTRY
        );
        assert_eq!(major_class(CLASS_FILE_ENTRY_FILE), MAJOR_CLASS_FILE_ENTRY);
        assert_eq!(major_class(CLASS_FILE_ENTRY_35), MAJOR_CLASS_FILE_ENTRY);
        assert_eq!(major_class(CLASS_FILE_ENTRY_36), MAJOR_CLASS_FILE_ENTRY);
        assert_eq!(
            major_class(CLASS_NETWORK_LOCATION),
            MAJOR_CLASS_NETWORK_LOCATION
        );
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
