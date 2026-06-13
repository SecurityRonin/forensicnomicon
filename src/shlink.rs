//! Shell Link (`.LNK`) binary file format constants — `[MS-SHLLINK]`.
//!
//! A shell link (`.lnk`) is a structured binary file Windows uses to reference
//! another data object (file, folder, network share, search). Forensically it
//! is a rich artifact: it records the target path, volume serial, MAC
//! timestamps, machine NetBIOS name, and a distributed-link-tracking droid
//! GUID — evidence of files that may no longer exist.
//!
//! This module is knowledge only — the fixed `HeaderSize`, the `LinkCLSID`, the
//! `LinkFlags` and `FileAttributesFlags` bit definitions, and the `ExtraData`
//! block signatures. The parser (header parse, `LinkTargetIDList` walk,
//! `LinkInfo`/string-data decode, ExtraData dispatch) lives in the consuming
//! reader (`lnk-core`), per forensicnomicon's knowledge-only charter.
//!
//! # Authoritative sources
//!
//! - `[MS-SHLLINK]` — *Shell Link (.LNK) Binary File Format*, the primary spec.
//!   §2.1 ShellLinkHeader (HeaderSize / LinkCLSID), §2.1.1 LinkFlags,
//!   §2.1.2 FileAttributesFlags, §2.5 ExtraData:
//!   <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943>
//! - libyal `liblnk`, *Windows Shortcut File (LNK) format* (J. Metz) — the
//!   reverse-engineered reference; documents every ExtraData block signature
//!   and size:
//!   <https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc>

/// `ShellLinkHeader.HeaderSize` — MUST be `0x0000004C` (`[MS-SHLLINK]` §2.1).
pub const HEADER_SIZE: u32 = 0x0000_004C;

/// `ShellLinkHeader.LinkCLSID` — MUST be this class identifier
/// (`[MS-SHLLINK]` §2.1).
pub const LINK_CLSID: &str = "00021401-0000-0000-C000-000000000046";

// ── LinkFlags (`[MS-SHLLINK]` §2.1.1) ────────────────────────────────────────
// Bit A is the least-significant bit (1 << 0); bits are listed MSB-first in the
// spec table but assigned A→least-significant.

/// A — a `LinkTargetIDList` follows the header.
pub const LINK_FLAG_HAS_LINK_TARGET_ID_LIST: u32 = 1 << 0;
/// B — a `LinkInfo` structure is present.
pub const LINK_FLAG_HAS_LINK_INFO: u32 = 1 << 1;
/// C — the `NAME_STRING` (description) is present.
pub const LINK_FLAG_HAS_NAME: u32 = 1 << 2;
/// D — the `RELATIVE_PATH` string is present.
pub const LINK_FLAG_HAS_RELATIVE_PATH: u32 = 1 << 3;
/// E — the `WORKING_DIR` string is present.
pub const LINK_FLAG_HAS_WORKING_DIR: u32 = 1 << 4;
/// F — the `COMMAND_LINE_ARGUMENTS` string is present.
pub const LINK_FLAG_HAS_ARGUMENTS: u32 = 1 << 5;
/// G — the `ICON_LOCATION` string is present.
pub const LINK_FLAG_HAS_ICON_LOCATION: u32 = 1 << 6;
/// H — string data are UTF-16 (`IsUnicode`); otherwise system code page.
pub const LINK_FLAG_IS_UNICODE: u32 = 1 << 7;
/// I — `LinkInfo` is ignored (`ForceNoLinkInfo`).
pub const LINK_FLAG_FORCE_NO_LINK_INFO: u32 = 1 << 8;
/// J — an `EnvironmentVariableDataBlock` is present (`HasExpString`).
pub const LINK_FLAG_HAS_EXP_STRING: u32 = 1 << 9;
/// K — the target runs in a separate VM (`RunInSeparateProcess`).
pub const LINK_FLAG_RUN_IN_SEPARATE_PROCESS: u32 = 1 << 10;
// L (1 << 11) is Unused1 — reserved, no constant.
/// M — a `DarwinDataBlock` is present (`HasDarwinID`).
pub const LINK_FLAG_HAS_DARWIN_ID: u32 = 1 << 12;
/// N — the target runs as a different user (`RunAsUser`).
pub const LINK_FLAG_RUN_AS_USER: u32 = 1 << 13;
/// O — an `IconEnvironmentDataBlock` is present (`HasExpIcon`).
pub const LINK_FLAG_HAS_EXP_ICON: u32 = 1 << 14;
/// P — the file system location is represented in the shell namespace
/// (`NoPidlAlias`).
pub const LINK_FLAG_NO_PIDL_ALIAS: u32 = 1 << 15;
// Q (1 << 16) is Unused2 — reserved, no constant.
/// R — a `ShimDataBlock` is present (`RunWithShimLayer`).
pub const LINK_FLAG_RUN_WITH_SHIM_LAYER: u32 = 1 << 17;
/// S — the `TrackerDataBlock` is omitted (`ForceNoLinkTrack`).
pub const LINK_FLAG_FORCE_NO_LINK_TRACK: u32 = 1 << 18;
/// T — shell-link target metadata collection is enabled
/// (`EnableTargetMetadata`).
pub const LINK_FLAG_ENABLE_TARGET_METADATA: u32 = 1 << 19;
/// U — the `EnvironmentVariableDataBlock` path is not stored
/// (`DisableLinkPathTracking`).
pub const LINK_FLAG_DISABLE_LINK_PATH_TRACKING: u32 = 1 << 20;
/// V — `SpecialFolderDataBlock`/`KnownFolderDataBlock` tracking is disabled
/// (`DisableKnownFolderTracking`).
pub const LINK_FLAG_DISABLE_KNOWN_FOLDER_TRACKING: u32 = 1 << 21;
/// W — the known-folder alias is not used (`DisableKnownFolderAlias`).
pub const LINK_FLAG_DISABLE_KNOWN_FOLDER_ALIAS: u32 = 1 << 22;
/// X — a link to another link is permitted (`AllowLinkToLink`).
pub const LINK_FLAG_ALLOW_LINK_TO_LINK: u32 = 1 << 23;
/// Y — drop the alias on save (`UnaliasOnSave`).
pub const LINK_FLAG_UNALIAS_ON_SAVE: u32 = 1 << 24;
/// Z — prefer the environment-variable path (`PreferEnvironmentPath`).
pub const LINK_FLAG_PREFER_ENVIRONMENT_PATH: u32 = 1 << 25;
/// AA — keep the local `IDList` for a UNC target
/// (`KeepLocalIDListForUNCTarget`).
pub const LINK_FLAG_KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET: u32 = 1 << 26;

// ── FileAttributesFlags (`[MS-SHLLINK]` §2.1.2) ──────────────────────────────

/// A — `FILE_ATTRIBUTE_READONLY`.
pub const FILE_ATTRIBUTE_READONLY: u32 = 1 << 0;
/// B — `FILE_ATTRIBUTE_HIDDEN`.
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 1 << 1;
/// C — `FILE_ATTRIBUTE_SYSTEM`.
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 1 << 2;
// D (1 << 3) is Reserved1 (MUST be zero) — no constant.
/// E — `FILE_ATTRIBUTE_DIRECTORY`.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 1 << 4;
/// F — `FILE_ATTRIBUTE_ARCHIVE`.
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 1 << 5;
// G (1 << 6) is Reserved2 (MUST be zero) — no constant.
/// H — `FILE_ATTRIBUTE_NORMAL`.
pub const FILE_ATTRIBUTE_NORMAL: u32 = 1 << 7;
/// I — `FILE_ATTRIBUTE_TEMPORARY`.
pub const FILE_ATTRIBUTE_TEMPORARY: u32 = 1 << 8;
/// J — `FILE_ATTRIBUTE_SPARSE_FILE`.
pub const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 1 << 9;
/// K — `FILE_ATTRIBUTE_REPARSE_POINT`.
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 1 << 10;
/// L — `FILE_ATTRIBUTE_COMPRESSED`.
pub const FILE_ATTRIBUTE_COMPRESSED: u32 = 1 << 11;
/// M — `FILE_ATTRIBUTE_OFFLINE`.
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 1 << 12;
/// N — `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`.
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 1 << 13;
/// O — `FILE_ATTRIBUTE_ENCRYPTED`.
pub const FILE_ATTRIBUTE_ENCRYPTED: u32 = 1 << 14;

// ── ExtraData block signatures (`[MS-SHLLINK]` §2.5) ─────────────────────────

/// `EnvironmentVariableDataBlock` signature.
pub const EXTRA_ENVIRONMENT_VARIABLE_DATA_BLOCK: u32 = 0xA000_0001;
/// `ConsoleDataBlock` signature.
pub const EXTRA_CONSOLE_DATA_BLOCK: u32 = 0xA000_0002;
/// `TrackerDataBlock` signature — carries the machine NetBIOS name and the
/// distributed-link-tracking droid/birth GUIDs (key attribution evidence).
pub const EXTRA_TRACKER_DATA_BLOCK: u32 = 0xA000_0003;
/// `ConsoleFEDataBlock` signature (console code page).
pub const EXTRA_CONSOLE_FE_DATA_BLOCK: u32 = 0xA000_0004;
/// `SpecialFolderDataBlock` signature.
pub const EXTRA_SPECIAL_FOLDER_DATA_BLOCK: u32 = 0xA000_0005;
/// `DarwinDataBlock` signature (Windows Installer / Darwin descriptor).
pub const EXTRA_DARWIN_DATA_BLOCK: u32 = 0xA000_0006;
/// `IconEnvironmentDataBlock` signature.
pub const EXTRA_ICON_ENVIRONMENT_DATA_BLOCK: u32 = 0xA000_0007;
/// `ShimDataBlock` signature (application-compatibility shim layer name).
pub const EXTRA_SHIM_DATA_BLOCK: u32 = 0xA000_0008;
/// `PropertyStoreDataBlock` signature (serialized property store).
pub const EXTRA_PROPERTY_STORE_DATA_BLOCK: u32 = 0xA000_0009;
/// `VistaAndAboveIDListDataBlock` signature.
pub const EXTRA_VISTA_AND_ABOVE_ID_LIST_DATA_BLOCK: u32 = 0xA000_000A;
/// `KnownFolderDataBlock` signature.
pub const EXTRA_KNOWN_FOLDER_DATA_BLOCK: u32 = 0xA000_000B;

/// The ExtraData section is terminated by a `BlockSize` strictly less than
/// `0x00000004` (`[MS-SHLLINK]` §2.5); the canonical terminal block is a 4-byte
/// `0x00000000`. This is the smallest size still treated as a TerminalBlock.
pub const EXTRA_DATA_TERMINAL_BLOCK_SIZE: u32 = 0x0000_0004;

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
