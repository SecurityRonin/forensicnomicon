//! Chromium **Simple Cache** on-disk format constants.
//!
//! The Simple Cache is one of Chromium's two disk-cache backends (the default on
//! Android, ChromeOS, Linux and macOS, and the backend for `CacheStorage`
//! everywhere). It keeps roughly **one file per cache entry** plus a single
//! `the-real-index` file, which makes it robust against crashes and the reason
//! forensic recovery of Discord/Slack/Teams/Electron cached media so often lands
//! here. Each entry file is bracketed by a fixed header and an EOF trailer; the
//! index is a `base::Pickle` guarded by a checksum.
//!
//! This module is **facts only** — the magic numbers, format versions, the
//! header/EOF/sparse field offsets, and the EOF flag bits. The reader that walks
//! the directory, validates the trailer, and carves the streams lives in the
//! consuming crate (`browser-forensic` / a cache carver), per forensicnomicon's
//! knowledge-only charter (no I/O, no parsing here).
//!
//! # Checksum: CRC-32, NOT Fletcher
//!
//! A common DFIR misconception holds that the Simple Cache index is protected by
//! a **Fletcher** checksum. It is not. The index pickle is checksummed with a
//! standard **CRC-32** (`CalculatePickleCRC` → `simple_util::Crc32`), and each
//! entry stream is likewise protected by the CRC-32 stored in
//! [`FLAG_HAS_CRC32`]-guarded `data_crc32`. There is no Fletcher checksum anywhere
//! in the Simple Cache backend — a mismatch simply triggers an index rebuild by
//! rescanning the entry files.
//!
//! # Authoritative sources
//!
//! - Chromium `net/disk_cache/simple/simple_entry_format.h` — the
//!   `SimpleFileHeader`, `SimpleFileEOF` and `SimpleFileSparseRangeHeader` structs
//!   and the `kSimple*MagicNumber` constants:
//!   <https://github.com/chromium/chromium/blob/main/net/disk_cache/simple/simple_entry_format.h>
//! - Chromium `net/disk_cache/simple/simple_backend_version.h` — `kSimpleVersion`
//!   (fake-index version) and `kSimpleEntryVersionOnDisk`:
//!   <https://github.com/chromium/chromium/blob/main/net/disk_cache/simple/simple_backend_version.h>
//! - Chromium `net/disk_cache/simple/simple_version_upgrade.cc` —
//!   `kMinVersionAbleToUpgrade` and the fake-index rebuild:
//!   <https://github.com/chromium/chromium/blob/main/net/disk_cache/simple/simple_version_upgrade.cc>
//! - Chromium `net/disk_cache/simple/simple_index_file.cc` — `CalculatePickleCRC`
//!   (the CRC-32, refuting the Fletcher claim) and `kSimpleIndexMagicNumber`:
//!   <https://github.com/chromium/chromium/blob/main/net/disk_cache/simple/simple_index_file.cc>
//! - Chromium design doc, *Very Simple Backend*:
//!   <https://www.chromium.org/developers/design-documents/network-stack/disk-cache/very-simple-backend/>

// ── Magic numbers (u64, stored little-endian on disk) ────────────────────────

/// `SimpleFileHeader::initial_magic_number` — the magic that opens every entry
/// file (`kSimpleInitialMagicNumber`).
pub const INITIAL_MAGIC: u64 = 0; // RED

/// `SimpleFileEOF::final_magic_number` — the magic that closes every entry
/// stream trailer (`kSimpleFinalMagicNumber`).
pub const FINAL_MAGIC: u64 = 0; // RED

/// `SimpleFileSparseRangeHeader::sparse_range_magic_number` — opens each sparse
/// range record.
pub const SPARSE_RANGE_MAGIC: u64 = 0; // RED

/// `kSimpleIndexMagicNumber` — the magic in the `the-real-index` pickle header
/// (ASCII `"enter yo"` read as a little-endian u64).
pub const INDEX_MAGIC: u64 = 0; // RED

// ── Versions ─────────────────────────────────────────────────────────────────

/// `kSimpleVersion` — current fake-index / backend format version.
pub const SIMPLE_VERSION: u32 = 0; // RED

/// `kSimpleEntryVersionOnDisk` — version written into each entry file's header.
pub const ENTRY_VERSION_ON_DISK: u32 = 0; // RED

/// `kMinVersionAbleToUpgrade` — the oldest version the backend can migrate.
pub const MIN_VERSION_ABLE_TO_UPGRADE: u32 = 0; // RED

/// `kSimpleEntryStreamCount` — number of data streams stored per entry.
pub const ENTRY_STREAM_COUNT: usize = 0; // RED

// ── SimpleFileHeader field offsets (24-byte struct) ──────────────────────────

/// Byte offset of `initial_magic_number` (u64 LE) in `SimpleFileHeader`.
pub const HEADER_MAGIC_OFFSET: usize = 0;
/// Byte offset of `version` (u32 LE) in `SimpleFileHeader`.
pub const HEADER_VERSION_OFFSET: usize = 8;
/// Byte offset of `key_length` (u32 LE) in `SimpleFileHeader`.
pub const HEADER_KEY_LENGTH_OFFSET: usize = 12;
/// Byte offset of `key_hash` (u32 LE) in `SimpleFileHeader`.
pub const HEADER_KEY_HASH_OFFSET: usize = 16;
/// Total size of `SimpleFileHeader` (incl. `unused_padding`).
pub const HEADER_LEN: usize = 24;

// ── SimpleFileEOF field offsets (24-byte trailer) ────────────────────────────

/// Byte offset of `final_magic_number` (u64 LE) in `SimpleFileEOF`.
pub const EOF_MAGIC_OFFSET: usize = 0;
/// Byte offset of `flags` (u32 LE) in `SimpleFileEOF`.
pub const EOF_FLAGS_OFFSET: usize = 8;
/// Byte offset of `data_crc32` (u32 LE) in `SimpleFileEOF`.
pub const EOF_DATA_CRC32_OFFSET: usize = 12;
/// Byte offset of `stream_size` (u32 LE) in `SimpleFileEOF`.
pub const EOF_STREAM_SIZE_OFFSET: usize = 16;
/// Total size of `SimpleFileEOF` (incl. `unused_padding`).
pub const EOF_LEN: usize = 24;

// ── SimpleFileEOF flag bits ──────────────────────────────────────────────────

/// `SimpleFileEOF::FLAG_HAS_CRC32` — the trailer carries a valid `data_crc32`.
pub const FLAG_HAS_CRC32: u32 = 0; // RED

/// `SimpleFileEOF::FLAG_HAS_KEY_SHA256` — the trailer is followed by a SHA-256 of
/// the key.
pub const FLAG_HAS_KEY_SHA256: u32 = 0; // RED

// ── Sparse range header offsets (32-byte struct) ─────────────────────────────

/// Byte offset of `offset` (u64 LE) in `SimpleFileSparseRangeHeader`.
pub const SPARSE_OFFSET_OFFSET: usize = 8;
/// Byte offset of `length` (u64 LE) in `SimpleFileSparseRangeHeader`.
pub const SPARSE_LENGTH_OFFSET: usize = 16;
/// Byte offset of `data_crc32` (u32 LE) in `SimpleFileSparseRangeHeader`.
pub const SPARSE_DATA_CRC32_OFFSET: usize = 24;
/// Total size of `SimpleFileSparseRangeHeader`.
pub const SPARSE_HEADER_LEN: usize = 32;

/// Which Simple Cache structure a leading magic identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Structure {
    /// An entry file, opened by [`INITIAL_MAGIC`].
    EntryHeader,
    /// An entry-stream trailer, closed by [`FINAL_MAGIC`].
    EntryEof,
    /// A sparse range record, opened by [`SPARSE_RANGE_MAGIC`].
    SparseRange,
    /// The `the-real-index` pickle, opened by [`INDEX_MAGIC`].
    Index,
}

/// Identify which Simple Cache structure a leading 64-bit magic belongs to.
///
/// Returns `None` for any value that is not one of the four documented magics —
/// the caller must fail loud rather than assume a structure.
#[must_use]
pub fn identify_magic(_magic: u64) -> Option<Structure> {
    None // RED
}

/// Whether an EOF `flags` word asserts a valid `data_crc32`.
#[must_use]
pub const fn has_crc32(_flags: u32) -> bool {
    false // RED
}

/// Whether an EOF `flags` word asserts a trailing key SHA-256.
#[must_use]
pub const fn has_key_sha256(_flags: u32) -> bool {
    false // RED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_magics_match_chromium() {
        assert_eq!(INITIAL_MAGIC, 0xfcfb_6d1b_a772_5c30);
        assert_eq!(FINAL_MAGIC, 0xf4fa_6f45_970d_41d8);
        assert_eq!(SPARSE_RANGE_MAGIC, 0xeb97_bf01_6553_676b);
    }

    #[test]
    fn index_magic_is_ascii_enter_yo() {
        assert_eq!(INDEX_MAGIC, 0x656e_7465_7220_796f);
        // Little-endian on disk ⇒ the bytes read "oy retne" but decode to a u64
        // whose big-endian text is "enter yo".
        assert_eq!(INDEX_MAGIC.to_be_bytes(), *b"enter yo");
    }

    #[test]
    fn versions_match_chromium() {
        assert_eq!(SIMPLE_VERSION, 9);
        assert_eq!(ENTRY_VERSION_ON_DISK, 5);
        assert_eq!(MIN_VERSION_ABLE_TO_UPGRADE, 8);
        assert_eq!(ENTRY_STREAM_COUNT, 3);
    }

    #[test]
    fn header_and_eof_offsets_are_contiguous() {
        assert_eq!(HEADER_MAGIC_OFFSET, 0);
        assert_eq!(HEADER_VERSION_OFFSET, 8);
        assert_eq!(HEADER_KEY_LENGTH_OFFSET, 12);
        assert_eq!(HEADER_KEY_HASH_OFFSET, 16);
        assert_eq!(HEADER_LEN, 24);
        assert_eq!(EOF_MAGIC_OFFSET, 0);
        assert_eq!(EOF_FLAGS_OFFSET, 8);
        assert_eq!(EOF_DATA_CRC32_OFFSET, 12);
        assert_eq!(EOF_STREAM_SIZE_OFFSET, 16);
        assert_eq!(EOF_LEN, 24);
    }

    #[test]
    fn sparse_offsets() {
        assert_eq!(SPARSE_OFFSET_OFFSET, 8);
        assert_eq!(SPARSE_LENGTH_OFFSET, 16);
        assert_eq!(SPARSE_DATA_CRC32_OFFSET, 24);
        assert_eq!(SPARSE_HEADER_LEN, 32);
    }

    #[test]
    fn eof_flag_bits() {
        assert_eq!(FLAG_HAS_CRC32, 1 << 0);
        assert_eq!(FLAG_HAS_KEY_SHA256, 1 << 1);
        assert!(has_crc32(FLAG_HAS_CRC32));
        assert!(has_crc32(FLAG_HAS_CRC32 | FLAG_HAS_KEY_SHA256));
        assert!(!has_crc32(0));
        assert!(has_key_sha256(FLAG_HAS_KEY_SHA256));
        assert!(!has_key_sha256(FLAG_HAS_CRC32));
    }

    #[test]
    fn identify_all_four_magics() {
        assert_eq!(identify_magic(INITIAL_MAGIC), Some(Structure::EntryHeader));
        assert_eq!(identify_magic(FINAL_MAGIC), Some(Structure::EntryEof));
        assert_eq!(
            identify_magic(SPARSE_RANGE_MAGIC),
            Some(Structure::SparseRange)
        );
        assert_eq!(identify_magic(INDEX_MAGIC), Some(Structure::Index));
        assert_eq!(identify_magic(0), None);
        assert_eq!(identify_magic(0xdead_beef), None);
    }
}
