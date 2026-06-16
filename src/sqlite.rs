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

/// Byte offset of the freelist trunk page number in the SQLite header.
///
/// 4-byte big-endian unsigned integer. Points to the first freelist trunk page;
/// 0 if no free pages exist. Carving free pages recovers deleted records.
pub const SQLITE_FREELIST_TRUNK_OFFSET: usize = 32;

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
        const { assert!(SQLITE_HEADER_SIZE >= SQLITE_FREELIST_TRUNK_OFFSET + 4) };
    }

    #[test]
    fn wal_sizes_are_correct() {
        assert_eq!(SQLITE_WAL_HEADER_SIZE, 32);
        assert_eq!(SQLITE_WAL_FRAME_HEADER_SIZE, 24);
    }
}
