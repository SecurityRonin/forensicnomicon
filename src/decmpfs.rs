//! HFS+/APFS transparent-compression (`decmpfs`) on-disk format constants.
//!
//! Apple's AppleFSCompression mechanism ("decmpfs") stores a file's data in
//! compressed form, transparently decompressed by the kernel on read. A
//! compressed file carries a `com.apple.decmpfs` extended attribute whose first
//! 16 bytes are a header (magic, compression type, uncompressed size). The
//! `compression_type` selects both the **algorithm** (Zlib / LZVN / LZFSE /
//! uncompressed / LZBitmap) and the **storage location** of the payload:
//!
//! - **odd** types store the payload **inline** in the `com.apple.decmpfs`
//!   xattr, immediately after the 16-byte header (used for small files);
//! - **even** types store the payload in the file's **resource fork**, split
//!   into independently-compressed [`CHUNK_SIZE`]-byte chunks indexed by a block
//!   table (used for larger files).
//!
//! This module is facts only — the magic, the type→(algorithm, storage) map,
//! the header field offsets, and the chunk size. The decoding algorithm (header
//! parse, block-table walk, codec dispatch) lives in the consuming reader
//! (`hfsplus-forensic`), per forensicnomicon's knowledge-only charter.
//!
//! # Authoritative sources
//!
//! Apple has never published a decmpfs specification; the layout below is the
//! settled reverse-engineered consensus of the forensic community:
//!
//! - Apple XNU kernel, `bsd/kern/decmpfs.c` + `bsd/sys/decmpfs.h` — the
//!   `decmpfs_disk_header` struct (`compression_magic` / `compression_type` /
//!   `uncompressed_size`) and the kernel-handled types (1/3/4/7/8/11/12):
//!   <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/decmpfs.c>
//! - The Sleuth Kit, `tsk/fs/hfs.c` — the canonical forensic implementation;
//!   its `decmpfs` switch documents types 3/4/7/8/9/10/11/12 and the 64 KiB
//!   chunking: <https://github.com/sleuthkit/sleuthkit>
//! - ydkhatri `mac_apt`, `plugins/helpers/structs.py` + `hfs_alt.py` — the
//!   `HFSPlusDecmpfs`, `HFSPlusCmpfRsrcHead` (Zlib resource fork) and
//!   `HFSPlusCmpfLZVNRsrcHead` (LZVN/LZFSE resource fork) block-table layouts:
//!   <https://github.com/ydkhatri/mac_apt>
//! - libyal `libfshfs`, *Apple Hierarchical File System plus (HFS+)* — the
//!   resource-fork compressed-data block table:
//!   <https://github.com/libyal/libfshfs>
//!
//! # Compression types
//!
//! | Type | Algorithm    | Storage        | Notes                                   |
//! |------|--------------|----------------|-----------------------------------------|
//! | 1    | uncompressed | inline xattr   | payload verbatim after the header       |
//! | 3    | Zlib         | inline xattr   | leading `0xFF` ⇒ remainder stored raw   |
//! | 4    | Zlib         | resource fork  | classic resource-manager block table    |
//! | 5    | (dedup)      | —              | de-dup generation store; no payload here |
//! | 7    | LZVN         | inline xattr   |                                         |
//! | 8    | LZVN         | resource fork  | macOS default for most files            |
//! | 9    | uncompressed | inline xattr   | variant of type 1                       |
//! | 10   | uncompressed | resource fork  | chunked, uncompressed                   |
//! | 11   | LZFSE        | inline xattr   |                                         |
//! | 12   | LZFSE        | resource fork  |                                         |
//! | 13   | LZBitmap     | inline xattr   | no public spec                          |
//! | 14   | LZBitmap     | resource fork  | no public spec                          |

/// `com.apple.decmpfs` header magic: ASCII `'cmpf'` read as a little-endian
/// `u32` (on-disk bytes `66 70 6d 63`).
pub const MAGIC: u32 = 0x636d_7066;

/// Length of the fixed `decmpfs` header that prefixes the xattr.
pub const HEADER_LEN: usize = 16;

/// Byte offset of `compression_type` (`u32` LE) within the header.
pub const COMPRESSION_TYPE_OFFSET: usize = 4;

/// Byte offset of `uncompressed_size` (`u64` LE) within the header.
pub const UNCOMPRESSED_SIZE_OFFSET: usize = 8;

/// Uncompressed size of each resource-fork chunk (the last chunk may be
/// shorter). Every even (resource-fork) compression type chunks at this size.
pub const CHUNK_SIZE: usize = 65536;

/// Where a compression type keeps its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// Inline in the `com.apple.decmpfs` xattr, after the 16-byte header.
    Inline,
    /// In the file's resource fork, chunked and indexed by a block table.
    ResourceFork,
}

/// The compression algorithm a decmpfs payload uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    /// Stored verbatim (no compression).
    Uncompressed,
    /// Zlib / DEFLATE (types 3, 4).
    Zlib,
    /// Apple LZVN / libFastCompression (types 7, 8).
    Lzvn,
    /// Apple LZFSE (types 11, 12).
    Lzfse,
    /// Apple LZBitmap (types 13, 14) — no public specification.
    LzBitmap,
}

/// A decoded `compression_type`: its algorithm and where the payload lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compression {
    /// The compression algorithm.
    pub algorithm: Algorithm,
    /// Where the payload is stored.
    pub storage: Storage,
}

/// Classify a raw `compression_type` value.
///
/// Returns `None` for type 5 (the de-dup generation store, which carries no
/// payload in this xattr) and for any type not in the documented set — the
/// caller must fail loud rather than guess.
#[must_use]
pub fn classify(compression_type: u32) -> Option<Compression> {
    use Algorithm::{LzBitmap, Lzfse, Lzvn, Uncompressed, Zlib};
    use Storage::{Inline, ResourceFork};
    let (algorithm, storage) = match compression_type {
        1 | 9 => (Uncompressed, Inline),
        10 => (Uncompressed, ResourceFork),
        3 => (Zlib, Inline),
        4 => (Zlib, ResourceFork),
        7 => (Lzvn, Inline),
        8 => (Lzvn, ResourceFork),
        11 => (Lzfse, Inline),
        12 => (Lzfse, ResourceFork),
        13 => (LzBitmap, Inline),
        14 => (LzBitmap, ResourceFork),
        // Type 5 is the de-dup generation store (no payload here); every other
        // value is undocumented — the caller must fail loud, not guess.
        _ => return None,
    };
    Some(Compression { algorithm, storage })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_is_cmpf_little_endian() {
        assert_eq!(MAGIC, 0x636d_7066);
        assert_eq!(MAGIC.to_le_bytes(), *b"fpmc");
    }

    #[test]
    fn header_layout_constants() {
        assert_eq!(HEADER_LEN, 16);
        assert_eq!(COMPRESSION_TYPE_OFFSET, 4);
        assert_eq!(UNCOMPRESSED_SIZE_OFFSET, 8);
        assert_eq!(CHUNK_SIZE, 65536);
    }

    #[test]
    fn zlib_types_3_inline_4_resource_fork() {
        assert_eq!(
            classify(3),
            Some(Compression { algorithm: Algorithm::Zlib, storage: Storage::Inline })
        );
        assert_eq!(
            classify(4),
            Some(Compression { algorithm: Algorithm::Zlib, storage: Storage::ResourceFork })
        );
    }

    #[test]
    fn lzvn_types_7_inline_8_resource_fork() {
        assert_eq!(
            classify(7),
            Some(Compression { algorithm: Algorithm::Lzvn, storage: Storage::Inline })
        );
        assert_eq!(
            classify(8),
            Some(Compression { algorithm: Algorithm::Lzvn, storage: Storage::ResourceFork })
        );
    }

    #[test]
    fn lzfse_types_11_inline_12_resource_fork() {
        assert_eq!(
            classify(11),
            Some(Compression { algorithm: Algorithm::Lzfse, storage: Storage::Inline })
        );
        assert_eq!(
            classify(12),
            Some(Compression { algorithm: Algorithm::Lzfse, storage: Storage::ResourceFork })
        );
    }

    #[test]
    fn uncompressed_types_1_9_inline_10_resource_fork() {
        for inline in [1, 9] {
            assert_eq!(
                classify(inline),
                Some(Compression {
                    algorithm: Algorithm::Uncompressed,
                    storage: Storage::Inline
                })
            );
        }
        assert_eq!(
            classify(10),
            Some(Compression {
                algorithm: Algorithm::Uncompressed,
                storage: Storage::ResourceFork
            })
        );
    }

    #[test]
    fn lzbitmap_types_13_inline_14_resource_fork() {
        assert_eq!(
            classify(13),
            Some(Compression { algorithm: Algorithm::LzBitmap, storage: Storage::Inline })
        );
        assert_eq!(
            classify(14),
            Some(Compression { algorithm: Algorithm::LzBitmap, storage: Storage::ResourceFork })
        );
    }

    #[test]
    fn dedup_type_5_and_unknown_types_are_none() {
        assert_eq!(classify(5), None); // de-dup generation store
        assert_eq!(classify(0), None);
        assert_eq!(classify(2), None);
        assert_eq!(classify(99), None);
    }

    #[test]
    fn parity_rule_odd_inline_even_resource_fork() {
        // Every documented compressing type follows odd⇒inline, even⇒resource-fork.
        for t in [3, 4, 7, 8, 11, 12, 13, 14] {
            let c = classify(t).expect("documented type");
            let expected = if t % 2 == 1 { Storage::Inline } else { Storage::ResourceFork };
            assert_eq!(c.storage, expected, "type {t}");
        }
    }
}
