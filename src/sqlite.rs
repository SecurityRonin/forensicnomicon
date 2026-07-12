//! SQLite and WAL binary format constants.
//!
//! These constants describe the on-disk layout of SQLite database files
//! and Write-Ahead Log (WAL) files. They are used for forensic carving,
//! integrity checking, and free-page recovery.
//!
//! All multi-byte integer fields in SQLite headers are big-endian.

/// SQLite database file magic bytes (first 16 bytes of any valid SQLite file).
///
/// Reference: SQLite file format spec §1.2
pub static SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

/// Minimum valid SQLite file size in bytes (the 100-byte file header).
pub const SQLITE_HEADER_SIZE: usize = 100;

/// Byte offset of the page size field in the SQLite header.
///
/// 2-byte big-endian unsigned integer. The value 1 is a special encoding for
/// a page size of 65536 bytes.
pub const SQLITE_PAGE_SIZE_OFFSET: usize = 16;

/// Byte offset of the "reserved space per page" field in the SQLite header.
///
/// 1-byte unsigned integer (file-format §1.3). Standard SQLite leaves this 0; a
/// non-zero value is claimed by page-level extensions — encryption (SQLCipher/SEE)
/// or a checksum VFS — and reduces the usable bytes per page.
pub const SQLITE_RESERVED_SPACE_OFFSET: usize = 20;

/// Byte offset of the in-header database size (in pages) in the SQLite header.
///
/// 4-byte big-endian unsigned integer (file-format §1.3). The size of the database
/// file in pages; may be 0 in legacy files, where the size is derived from the
/// file length instead.
pub const SQLITE_DB_SIZE_OFFSET: usize = 28;

/// Byte offset of the freelist trunk page number in the SQLite header.
///
/// 4-byte big-endian unsigned integer. Points to the first freelist trunk page;
/// 0 if no free pages exist. Carving free pages recovers deleted records.
pub const SQLITE_FREELIST_TRUNK_OFFSET: usize = 32;

/// Byte offset of the total freelist page count in the SQLite header.
///
/// 4-byte big-endian unsigned integer (file-format §1.3). The number of pages on
/// the freelist; a claim the trunk-chain walk verifies (a mismatch is a
/// tampering/corruption signal).
pub const SQLITE_FREELIST_COUNT_OFFSET: usize = 36;

/// Byte offset of the database text encoding field in the SQLite header.
///
/// 4-byte big-endian unsigned integer (file-format §1.3): 1 = UTF-8,
/// 2 = UTF-16 little-endian, 3 = UTF-16 big-endian. Determines how TEXT column
/// bytes are decoded.
pub const SQLITE_TEXT_ENCODING_OFFSET: usize = 56;

/// Size of the SQLite WAL file header in bytes.
///
/// The WAL file begins with a 32-byte header followed by zero or more frames.
pub const SQLITE_WAL_HEADER_SIZE: usize = 32;

/// Size of a WAL frame header in bytes.
///
/// Each frame in the WAL file begins with a 24-byte header, followed by
/// `page_size` bytes of page data.
pub const SQLITE_WAL_FRAME_HEADER_SIZE: usize = 24;

/// Firefox mozLz4 session file magic bytes.
///
/// Firefox compresses `sessionstore.jsonlz4` with a custom LZ4 variant
/// preceded by this 8-byte magic header.
pub static MOZLZ4_MAGIC: &[u8] = b"mozLz40\0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_magic_is_16_bytes() {
        assert_eq!(SQLITE_MAGIC.len(), 16);
        assert!(SQLITE_MAGIC.starts_with(b"SQLite format 3"));
    }

    #[test]
    fn mozlz4_magic_is_8_bytes() {
        assert_eq!(MOZLZ4_MAGIC.len(), 8);
    }

    #[test]
    fn sqlite_offsets_are_correct() {
        assert_eq!(SQLITE_PAGE_SIZE_OFFSET, 16);
        assert_eq!(SQLITE_FREELIST_TRUNK_OFFSET, 32);
        const _: () = assert!(SQLITE_HEADER_SIZE >= SQLITE_FREELIST_TRUNK_OFFSET + 4);
    }

    #[test]
    fn sqlite_header_field_offsets_match_the_spec() {
        // File-format §1.3: fixed byte offsets of the page-1 database header fields.
        assert_eq!(SQLITE_RESERVED_SPACE_OFFSET, 20);
        assert_eq!(SQLITE_DB_SIZE_OFFSET, 28);
        assert_eq!(SQLITE_FREELIST_COUNT_OFFSET, 36);
        assert_eq!(SQLITE_TEXT_ENCODING_OFFSET, 56);
        // Every field lies within the 100-byte header.
        const _: () = assert!(SQLITE_RESERVED_SPACE_OFFSET < SQLITE_HEADER_SIZE);
        const _: () = assert!(SQLITE_DB_SIZE_OFFSET + 4 <= SQLITE_HEADER_SIZE);
        const _: () = assert!(SQLITE_FREELIST_COUNT_OFFSET + 4 <= SQLITE_HEADER_SIZE);
        const _: () = assert!(SQLITE_TEXT_ENCODING_OFFSET + 4 <= SQLITE_HEADER_SIZE);
    }

    #[test]
    fn wal_sizes_are_correct() {
        assert_eq!(SQLITE_WAL_HEADER_SIZE, 32);
        assert_eq!(SQLITE_WAL_FRAME_HEADER_SIZE, 24);
    }
}
