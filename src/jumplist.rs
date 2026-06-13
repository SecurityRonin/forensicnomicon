//! Windows Jump List format constants — `*.automaticDestinations-ms` (DestList)
//! and `*.customDestinations-ms`, plus the per-application `AppID`.
//!
//! Jump Lists are the Windows taskbar/Start "recent and pinned" artifact. Each
//! application that participates owns two files under
//! `%APPDATA%\Microsoft\Windows\Recent\(Automatic|Custom)Destinations`, named
//! `<AppID>.automaticDestinations-ms` / `<AppID>.customDestinations-ms`.
//! Forensically they are a rich MRU artifact: the embedded `[MS-SHLLINK]` shell
//! links carry the same target path / volume serial / droid GUID evidence as a
//! standalone `.lnk`, and the `DestList` stream records, per entry, the origin
//! hostname, an access FILETIME, a pin flag, and (Windows 10+) an access count.
//!
//! This module is **knowledge only** — header/entry offset tables, the
//! `CustomDestinations` footer signature and category types, the embedded-LNK
//! `CLSID` boundary, and the `AppID` CRC-64 polynomial + well-known map. The
//! parser (CFB/OLE compound-file decode, `DestList` walk, shell-link extraction)
//! lives in the consuming reader (`lnk-core`), per forensicnomicon's
//! knowledge-only charter.
//!
//! # Authoritative sources
//!
//! - libyal `dtformats`, *Jump lists format* (J. Metz) — the reverse-engineered
//!   reference for the `DestList` header/entry layout and the
//!   `CustomDestinations` file structure:
//!   <https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc>
//! - kacos2000 `Jumplist-Browser` — the community `AppID` → application map
//!   (`AppIdlist.csv`) and per-version `DestList` field notes:
//!   <https://github.com/kacos2000/Jumplist-Browser>
//! - Hexacorn, *Jump to Jump to Jump* — the `AppID` derivation (CRC-64 of the
//!   upper-cased, KNOWNFOLDERID-normalized UTF-16LE executable path):
//!   <https://www.hexacorn.com/blog/2013/04/30/jumplists-file-names-and-appid-calculation/>
//! - `[MS-SHLLINK]` — the embedded shell-link format (see [`crate::shlink`]).

// ── DestList stream header (`*.automaticDestinations-ms`) ─────────────────────
// libyal dtformats §2.1.1 — the header is 32 bytes.

/// `DestList` header `FormatVersion` field offset (`u32`).
pub const DESTLIST_HEADER_FORMAT_VERSION_OFFSET: usize = 0;
/// `DestList` header `NumberOfEntries` field offset (`u32`).
pub const DESTLIST_HEADER_ENTRY_COUNT_OFFSET: usize = 4;
/// `DestList` header `NumberOfPinnedEntries` field offset (`u32`).
pub const DESTLIST_HEADER_PINNED_COUNT_OFFSET: usize = 8;
/// `DestList` header `LastEntryNumber` field offset (`u32`).
pub const DESTLIST_HEADER_LAST_ENTRY_NUMBER_OFFSET: usize = 16;
/// `DestList` header `LastRevisionNumber` field offset (`u32`).
pub const DESTLIST_HEADER_LAST_REVISION_OFFSET: usize = 24;
/// Total size of the `DestList` header in bytes.
pub const DESTLIST_HEADER_SIZE: usize = 32;

/// `DestList` format version used by Windows 7 (the original, v1 layout).
pub const DESTLIST_FORMAT_VERSION_WIN7: u32 = 1;
/// `DestList` format version introduced with Windows 10 (the v2+/extended
/// layout, with the `status`/`access_count`/unknown block before the path).
///
/// libyal documents the wire values `3` (Windows 10) and `4` (later builds) for
/// this extended layout; the reader treats every `FormatVersion >= 2` as the
/// extended entry shape.
pub const DESTLIST_FORMAT_VERSION_WIN10: u32 = 3;

// ── DestList entry — common prefix (both versions) ───────────────────────────
// libyal dtformats §2.1.2. Offsets are relative to the start of an entry.

/// Offset of the `DroidVolumeIdentifier` GUID (16 bytes) in a `DestList` entry.
pub const DESTLIST_ENTRY_DROID_VOLUME_GUID_OFFSET: usize = 8;
/// Offset of the `DroidFileIdentifier` GUID (16 bytes) in a `DestList` entry.
pub const DESTLIST_ENTRY_DROID_FILE_GUID_OFFSET: usize = 24;
/// Offset of the `BirthDroidVolumeIdentifier` GUID (16 bytes).
pub const DESTLIST_ENTRY_BIRTH_DROID_VOLUME_GUID_OFFSET: usize = 40;
/// Offset of the `BirthDroidFileIdentifier` GUID (16 bytes).
pub const DESTLIST_ENTRY_BIRTH_DROID_FILE_GUID_OFFSET: usize = 56;
/// Offset of the `Hostname`/NetBIOS name (16 ASCII bytes, NUL-padded).
pub const DESTLIST_ENTRY_HOSTNAME_OFFSET: usize = 72;
/// Size of the `Hostname` field in bytes.
pub const DESTLIST_ENTRY_HOSTNAME_SIZE: usize = 16;
/// Offset of the `EntryNumber` (`u32`) — also the name of the LNK sub-stream.
pub const DESTLIST_ENTRY_ENTRY_NUMBER_OFFSET: usize = 88;
/// Offset of the last-access `FILETIME` (8 bytes).
pub const DESTLIST_ENTRY_LAST_ACCESS_FILETIME_OFFSET: usize = 100;
/// Offset of the `PinStatus` (`i32`): `-1` unpinned, `>= 0` pinned.
pub const DESTLIST_ENTRY_PIN_STATUS_OFFSET: usize = 108;

/// `PinStatus` sentinel meaning the entry is **not** pinned.
pub const DESTLIST_PIN_STATUS_UNPINNED: i32 = -1;

// ── DestList entry — version 1 (Windows 7) ───────────────────────────────────

/// v1: offset of `PathSize` (`u16`, in UTF-16 characters).
pub const DESTLIST_ENTRY_V1_PATH_SIZE_OFFSET: usize = 112;
/// v1: offset of the `Path` (UTF-16LE, `PathSize` characters, no terminator).
pub const DESTLIST_ENTRY_V1_PATH_OFFSET: usize = 114;

// ── DestList entry — version 2+ (Windows 10/11) ──────────────────────────────
// The extended layout inserts a 16-byte block before the path: a 32-bit status,
// a 32-bit access count, and 8 unknown bytes. After the path there are 4 bytes
// of alignment padding before the next entry.

/// v2+: offset of the `Status` (`u32`) in the inserted 16-byte block.
pub const DESTLIST_ENTRY_V2_STATUS_OFFSET: usize = 112;
/// v2+: offset of the `AccessCount` (`u32`).
pub const DESTLIST_ENTRY_V2_ACCESS_COUNT_OFFSET: usize = 116;
/// v2+: offset of the 8 unknown bytes following `AccessCount`.
pub const DESTLIST_ENTRY_V2_UNKNOWN_OFFSET: usize = 120;
/// v2+: offset of `PathSize` (`u16`, in UTF-16 characters).
pub const DESTLIST_ENTRY_V2_PATH_SIZE_OFFSET: usize = 128;
/// v2+: offset of the `Path` (UTF-16LE, `PathSize` characters, no terminator).
pub const DESTLIST_ENTRY_V2_PATH_OFFSET: usize = 130;
/// v2+: bytes of alignment padding after the path, before the next entry.
pub const DESTLIST_ENTRY_V2_TRAILING_ALIGNMENT: usize = 4;

// ── CustomDestinations file (`*.customDestinations-ms`) ───────────────────────
// libyal dtformats §3.

/// `CustomDestinations` file header `FormatVersion` — MUST be `2`.
pub const CUSTOM_DESTINATIONS_FORMAT_VERSION: u32 = 2;
/// `CustomDestinations` file footer signature (`0xBABFFBAB`).
pub const CUSTOM_DESTINATIONS_FOOTER_SIGNATURE: u32 = 0xBABF_FBAB;

/// `CustomDestinations` category type (libyal dtformats §3.2.1).
///
/// The category-header `CategoryType` selects how a category is laid out: a
/// custom category carries a name + entry array, a known category carries a
/// `KnownCategoryIdentifier`, and a user-tasks category carries an entry array.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CategoryType {
    /// Custom category — a UTF-16 name string then an array of shell objects.
    Custom,
    /// Known category — a `KnownCategoryIdentifier` (see [`KnownCategory`]).
    Known,
    /// User-tasks category — an array of shell objects (the app's task list).
    UserTasks,
}

impl CategoryType {
    /// Map a `CategoryType` wire value (`0`/`1`/`2`) to the typed variant.
    #[must_use]
    pub fn from_u32(value: u32) -> Option<CategoryType> {
        match value {
            0 => Some(CategoryType::Custom),
            1 => Some(CategoryType::Known),
            2 => Some(CategoryType::UserTasks),
            _ => None,
        }
    }
}

/// `CustomDestinations` known-category identifier (libyal dtformats §3.2.2),
/// present only when `CategoryType == Known`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KnownCategory {
    /// `KDC_FREQUENT` — the "Frequent" known category.
    Frequent,
    /// `KDC_RECENT` — the "Recent" known category.
    Recent,
}

impl KnownCategory {
    /// Map a `KnownCategoryIdentifier` wire value (`1`/`2`) to the variant.
    #[must_use]
    pub fn from_u32(value: u32) -> Option<KnownCategory> {
        match value {
            1 => Some(KnownCategory::Frequent),
            2 => Some(KnownCategory::Recent),
            _ => None,
        }
    }
}

/// The `[MS-SHLLINK]` class identifier that prefixes each embedded shell-link
/// entry in a `CustomDestinations` shell-object array — the boundary a reader
/// scans for to split the concatenated LNKs (declared sizes are unreliable).
///
/// Re-exported from [`crate::shlink::LINK_CLSID`] so a Jump List reader has the
/// boundary without depending on the shell-link module's full surface.
pub const LNK_CLSID: &str = crate::shlink::LINK_CLSID;

// ── AppID — per-application Jump List identity ────────────────────────────────

/// The CRC-64 polynomial used to derive a Jump List `AppID`.
///
/// The `AppID` is the lowercase hex of the CRC-64 (this polynomial, the
/// "Jones"/ECMA-182 reflected form) of the application's executable path encoded
/// as **upper-case UTF-16LE** with `KNOWNFOLDERID` path normalization applied
/// (e.g. `C:\Windows\` → its folder GUID) before hashing. Source: Hexacorn,
/// *Jump to Jump to Jump* (the community-confirmed derivation).
pub const APPID_CRC64_POLY: u64 = 0x92C6_4265_D321_39A4;

/// Compute the Jump List `AppID` CRC-64 over an already-normalized byte buffer.
///
/// The caller is responsible for producing the upper-cased, `KNOWNFOLDERID`
/// -normalized UTF-16LE path bytes; this routine performs only the reflected
/// CRC-64 (polynomial [`APPID_CRC64_POLY`], init `0`, no final XOR) so a
/// candidate path can be verified against a filename `AppID`. Returns the raw
/// 64-bit checksum — render it as 16 lowercase hex digits to compare to a
/// filename.
#[must_use]
pub fn appid_crc64(normalized_utf16le: &[u8]) -> u64 {
    let mut crc: u64 = 0;
    for &byte in normalized_utf16le {
        crc ^= u64::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ APPID_CRC64_POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Resolve a well-known Jump List `AppID` (lowercase hex) to the application it
/// identifies, or `None` if it is not in the curated set.
///
/// The map is the representative slice of kacos2000's `AppIdlist.csv`
/// (<https://github.com/kacos2000/Jumplist-Browser>); keys are normalized to
/// lowercase hex. It is a convenience lookup, not exhaustive — an unmapped
/// `AppID` is common and not itself suspicious.
#[must_use]
pub fn appid_name(appid: &str) -> Option<&'static str> {
    // Normalize the candidate to lowercase so callers need not pre-fold.
    let key = appid.to_ascii_lowercase();
    WELL_KNOWN_APPIDS
        .iter()
        .find(|(id, _)| *id == key)
        .map(|(_, name)| *name)
}

/// Curated `AppID` → application map (lowercase hex keys), sourced from
/// kacos2000's `AppIdlist.csv`.
pub static WELL_KNOWN_APPIDS: &[(&str, &str)] = &[
    ("1b4dd67f29cb1962", "Windows Explorer"),
    ("5f7b5f1e01b83767", "Quick Access"),
    ("5d696d521de238c3", "Chrome"),
    ("918e0ecb43d17e23", "Notepad"),
    ("39ce6ede51235ede", "Notepad++"),
    ("469e4a7982cea4d4", "WordPad"),
    ("1bc392b8e104a00e", "Remote Desktop (mstsc)"),
    ("3c3871276e149215", "PowerShell 7"),
    ("9b9cdc69c1c24e2b", "Notepad (Win11)"),
    ("4cb9c5750d51c07f", "Windows PowerShell"),
    ("c8866f9516ac1604", "Internet Explorer (64-bit)"),
    ("aa63b1a90e9050ce", "Word 2016"),
    ("a4a5324453d3e0c2", "Visual Studio 2017"),
    ("e0f5df85162b2e74", "Opera"),
    ("b4866339a794afcf", "Paint.Net"),
    ("1bc9bbbe61f14501", "OneNote"),
    ("1c7a9be1b15a03ba", "Snip & Sketch"),
    ("9c7cc110ff56d1bd", "Microsoft Edge"),
    ("47bf5b94595fb517", "Firefox"),
    ("d64d36b238c843a3", "Excel 2016"),
    ("65009083bfa6a094", "PowerPoint 2016"),
    ("12dc1ea8e34b5a6", "Outlook 2016"),
    ("28c8b86deab549a1", "Internet Explorer (32-bit)"),
    ("271e609288bcd6d", "VLC media player"),
    ("17d3eb086439f9f0", "7-Zip"),
    ("9839aec31243a928", "Microsoft Word 2010"),
    ("4cce4b69dc977dd1", "WinRAR"),
    ("a8c43ef36da523f1", "Adobe Reader 10"),
    ("ff103e2cc310d0d", "Adobe Reader XI"),
    ("fc98c00f85d4ce77", "EditPad Pro 8"),
    ("6274ff22c2061c60", "Google PhotoViewer (Picasa)"),
    ("c9533998e1308d73", "MS Teams x64"),
    ("d67eec451f4b0a17", "MS Teams x64"),
    ("db53b23fd1edbd46", "WinZip64"),
    ("5da8f997fc2e25e", "Wordpad (Win10)"),
    ("d6481c79c4c2afda", "Calculator"),
    ("23646679aaccfae0", "Adobe Photoshop"),
    ("2f8b1eee0fab7d60", "Sublime Text"),
    ("e36b6e3a18d1c9aa", "Visual Studio Code"),
    ("0b3f13480c2785ae", "Paint"),
];

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
        // The path immediately follows its 2-byte size field.
        assert_eq!(
            DESTLIST_ENTRY_V1_PATH_OFFSET,
            DESTLIST_ENTRY_V1_PATH_SIZE_OFFSET + 2
        );
    }

    #[test]
    fn destlist_entry_v2_layout_inserts_16_byte_block() {
        assert_eq!(DESTLIST_ENTRY_V2_STATUS_OFFSET, 112);
        assert_eq!(DESTLIST_ENTRY_V2_ACCESS_COUNT_OFFSET, 116);
        assert_eq!(DESTLIST_ENTRY_V2_UNKNOWN_OFFSET, 120);
        assert_eq!(DESTLIST_ENTRY_V2_PATH_SIZE_OFFSET, 128);
        assert_eq!(DESTLIST_ENTRY_V2_PATH_OFFSET, 130);
        assert_eq!(DESTLIST_ENTRY_V2_TRAILING_ALIGNMENT, 4);
        // v2+ inserts exactly 16 bytes before the path-size field versus v1.
        assert_eq!(
            DESTLIST_ENTRY_V2_PATH_SIZE_OFFSET - DESTLIST_ENTRY_V1_PATH_SIZE_OFFSET,
            16
        );
        // The 16-byte block is status(4) + access_count(4) + unknown(8).
        assert_eq!(
            DESTLIST_ENTRY_V2_UNKNOWN_OFFSET + 8,
            DESTLIST_ENTRY_V2_PATH_SIZE_OFFSET
        );
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
        assert_eq!(KnownCategory::from_u32(99), None);
    }

    #[test]
    fn lnk_clsid_matches_shlink() {
        assert_eq!(LNK_CLSID, crate::shlink::LINK_CLSID);
        assert_eq!(LNK_CLSID, "00021401-0000-0000-C000-000000000046");
    }

    #[test]
    fn appid_poly_value() {
        assert_eq!(APPID_CRC64_POLY, 0x92C6_4265_D321_39A4);
    }

    #[test]
    fn appid_name_resolves_known_and_normalizes_case() {
        assert_eq!(appid_name("1b4dd67f29cb1962"), Some("Windows Explorer"));
        assert_eq!(appid_name("5f7b5f1e01b83767"), Some("Quick Access"));
        assert_eq!(appid_name("5d696d521de238c3"), Some("Chrome"));
        assert_eq!(appid_name("39ce6ede51235ede"), Some("Notepad++"));
        // Case-insensitive: an upper-cased AppID resolves the same.
        assert_eq!(appid_name("1B4DD67F29CB1962"), Some("Windows Explorer"));
        // An unknown AppID is not an error — just absent.
        assert_eq!(appid_name("ffffffffffffffff"), None);
    }

    #[test]
    fn well_known_appids_are_lowercase_and_nonempty() {
        for (id, name) in WELL_KNOWN_APPIDS {
            assert_eq!(*id, id.to_ascii_lowercase(), "AppID key must be lowercase");
            assert!(!name.is_empty(), "AppID name must be non-empty");
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "AppID must be hex");
        }
    }

    #[test]
    fn appid_crc64_is_deterministic_and_zero_for_empty() {
        // Empty input with init 0 and no final XOR yields 0.
        assert_eq!(appid_crc64(&[]), 0);
        // Determinism: same bytes hash to the same value.
        let bytes = b"\x43\x00\x3a\x00"; // "C:" as UTF-16LE-ish bytes
        assert_eq!(appid_crc64(bytes), appid_crc64(bytes));
        // A single non-zero byte produces a non-zero checksum.
        assert_ne!(appid_crc64(b"\x01"), 0);
    }
}
