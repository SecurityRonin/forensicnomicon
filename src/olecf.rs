//! OLE Compound File Binary (`[MS-CFB]`) format constants and offset layouts.
//!
//! The OLE Compound File (also "OLE2", "structured storage", "compound document")
//! is a FAT-like filesystem packed inside one file: a header, a sector-allocation
//! table (FAT), a mini-FAT for sub-512-byte streams, a DIFAT indexing the FAT, and
//! a red-black tree of 128-byte directory entries naming each *storage* (directory)
//! and *stream* (file). It backs legacy Office documents (`.doc`/`.xls`/`.ppt`),
//! Windows Jump Lists (`*.automaticDestinations-ms`), Outlook `.msg`, MSI installers,
//! thumbnail caches, and many other Windows artifacts.
//!
//! This module is **knowledge only** — the signature, header/directory-entry offset
//! tables, sector-shift and mini-sector invariants, the special FAT sector ids, and
//! the object-type / red-black colour enums. The parser (header decode, FAT/mini-FAT
//! chain walking, directory-tree traversal, stream carving) lives in the consuming
//! reader/analyzer (`cfb-forensic`), per forensicnomicon's knowledge-only charter.
//!
//! # Offset formulas
//!
//! A regular FAT sector with sector id `sid` begins at file byte offset
//! `(sid + 1) << sector_shift` — the `+ 1` skips the 512-byte header, which is itself
//! "sector −1" of the stream. A mini-stream sector with mini-sector id `msid` begins
//! at byte offset `msid << MINI_SECTOR_SHIFT_VALUE` (i.e. `msid * 64`) *within the
//! materialized mini-stream*, which is the root storage's own stream. Streams at or
//! above [`MINI_STREAM_CUTOFF_VALUE`] (4096) bytes live in the regular FAT; smaller
//! streams live in the mini-FAT.
//!
//! # Authoritative sources
//!
//! - `[MS-CFB]`, *Compound File Binary File Format*, Microsoft Open Specifications
//!   (§2.2 Compound File Header, §2.3 Compound File FAT Sectors, §2.4 Compound File
//!   Mini FAT Sectors, §2.5 Compound File DIFAT Sectors, §2.6 Compound File Directory
//!   Sectors):
//!   <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b>
//! - libyal `libolecf`, *OLE Compound File format* (J. Metz) — the reverse-engineered
//!   reference for the header, FAT/mini-FAT, and directory-entry layout:
//!   <https://github.com/libyal/libolecf/blob/main/documentation/OLE%20Compound%20File%20format.asciidoc>

/// OLE Compound File signature — the first 8 bytes of every CFB file
/// (`[MS-CFB]` §2.2, "Header Signature"). Historically `0xE11AB1A1E011CFD0`
/// read as a little-endian `u64`.
pub const OLECF_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Fixed size of the compound-file header in bytes (`[MS-CFB]` §2.2). The header
/// occupies the first sector; in a 512-byte-sector (v3) file it fills the sector,
/// in a 4096-byte-sector (v4) file the remaining 3584 bytes are reserved zero.
pub const HEADER_SIZE: usize = 512;

// ── Header field offsets (`[MS-CFB]` §2.2) ──────────────────────────────────────
// All multi-byte header fields are little-endian.

/// Minor version (`u16`) — SHOULD be `0x003E` for v3 and v4.
pub const MINOR_VERSION: usize = 24;
/// Major version (`u16`) — `0x0003` (512-byte sectors) or `0x0004` (4096-byte sectors).
pub const MAJOR_VERSION: usize = 26;
/// Byte-order mark (`u16`) — MUST be [`BYTE_ORDER_LE`] (`0xFFFE`, little-endian).
pub const BYTE_ORDER: usize = 28;
/// Sector shift (`u16`) — `log2(sector size)`: `9` for v3, `12` for v4.
pub const SECTOR_SHIFT: usize = 30;
/// Mini-sector shift (`u16`) — `log2(mini-sector size)`, MUST be `6` (64-byte mini-sectors).
pub const MINI_SECTOR_SHIFT: usize = 32;
/// Number of directory sectors (`u32`) — MUST be `0` for v3 (unused), a count for v4.
pub const NUM_DIR_SECTORS: usize = 40;
/// Number of FAT sectors (`u32`).
pub const NUM_FAT_SECTORS: usize = 44;
/// First directory sector id (`u32`) — start of the directory chain.
pub const FIRST_DIR_SECTOR: usize = 48;
/// Mini-stream cutoff (`u32`) — MUST be [`MINI_STREAM_CUTOFF_VALUE`] (4096). Streams
/// strictly smaller live in the mini-FAT, otherwise in the regular FAT.
pub const MINI_STREAM_CUTOFF: usize = 56;
/// First mini-FAT sector id (`u32`).
pub const FIRST_MINIFAT_SECTOR: usize = 60;
/// Number of mini-FAT sectors (`u32`).
pub const NUM_MINIFAT_SECTORS: usize = 64;
/// First DIFAT sector id (`u32`) — start of the DIFAT chain, or [`ENDOFCHAIN`] when
/// the 109 header DIFAT slots suffice.
pub const FIRST_DIFAT_SECTOR: usize = 68;
/// Number of DIFAT sectors (`u32`).
pub const NUM_DIFAT_SECTORS: usize = 72;
/// Byte offset where the in-header DIFAT array begins (the first 109 FAT-sector ids).
pub const DIFAT_HEADER_OFFSET: usize = 76;
/// Count of FAT-sector ids stored inline in the header DIFAT array.
pub const DIFAT_HEADER_COUNT: usize = 109;

// ── Structural invariants (`[MS-CFB]` §2.2, §2.6) ───────────────────────────────

/// Required byte-order mark value (little-endian) at [`BYTE_ORDER`].
pub const BYTE_ORDER_LE: u16 = 0xFFFE;
/// Required mini-stream cutoff value at [`MINI_STREAM_CUTOFF`].
pub const MINI_STREAM_CUTOFF_VALUE: u32 = 4096;
/// Mini-sector size in bytes (`1 << MINI_SECTOR_SHIFT_VALUE`).
pub const MINI_SECTOR_SIZE: usize = 64;
/// Required mini-sector shift value at [`MINI_SECTOR_SHIFT`] (`log2(64)`).
pub const MINI_SECTOR_SHIFT_VALUE: u16 = 6;
/// Sector shift for major version 3 (512-byte sectors).
pub const SECTOR_SHIFT_V3: u16 = 9;
/// Sector shift for major version 4 (4096-byte sectors).
pub const SECTOR_SHIFT_V4: u16 = 12;
/// Size in bytes of one directory entry (`[MS-CFB]` §2.6.1).
pub const DIR_ENTRY_SIZE: usize = 128;

// ── Special FAT sector ids (`[MS-CFB]` §2.2; SIDs/SECTs) ─────────────────────────

/// Free / unallocated sector — also the "no stream" sentinel for a directory entry's
/// child/sibling pointer ([`NOSTREAM`] shares this value).
pub const FREESECT: u32 = 0xFFFF_FFFF;
/// End-of-chain marker — terminates a FAT/mini-FAT/DIFAT sector chain.
pub const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
/// FAT sector marker — this sector holds part of the FAT itself.
pub const FATSECT: u32 = 0xFFFF_FFFD;
/// DIFAT sector marker — this sector holds part of the DIFAT.
pub const DIFSECT: u32 = 0xFFFF_FFFC;
/// Maximum regular (data-bearing) sector id; values above this are markers.
pub const MAXREGSECT: u32 = 0xFFFF_FFFA;
/// "No stream" sentinel for a directory entry's left/right/child pointer
/// (`[MS-CFB]` §2.6.1) — identical value to [`FREESECT`].
pub const NOSTREAM: u32 = 0xFFFF_FFFF;

// ── Directory-entry field offsets (`[MS-CFB]` §2.6.1) ───────────────────────────
// Offsets are relative to the start of the 128-byte entry.

/// Directory entry name (`64` bytes, UTF-16LE, NUL-padded).
pub const NAME: usize = 0;
/// Length in bytes of the name field including the terminating NUL (`u16`).
pub const NAME_LEN: usize = 64;
/// Object type (`u8`) — one of [`ObjectType`].
pub const OBJECT_TYPE: usize = 66;
/// Red-black tree node colour (`u8`) — one of [`Color`].
pub const COLOR: usize = 67;
/// Left-sibling directory-entry id (`u32`), or [`NOSTREAM`].
pub const LEFT_SIBLING: usize = 68;
/// Right-sibling directory-entry id (`u32`), or [`NOSTREAM`].
pub const RIGHT_SIBLING: usize = 72;
/// Child directory-entry id (`u32`) — root of the contained tree for a storage,
/// or [`NOSTREAM`] for a stream.
pub const CHILD: usize = 76;
/// Class id (`16` bytes, GUID). For a stream entry this MUST be all-zero
/// (`[MS-CFB]` §2.6.3); a non-zero CLSID on a stream is a tamper tell.
pub const CLSID: usize = 80;
/// User-defined state bits (`u32`). For a stream entry this MUST be zero
/// (`[MS-CFB]` §2.6.3).
pub const STATE_BITS: usize = 96;
/// Creation time (`8` bytes, Windows FILETIME). MUST be zero for a stream entry
/// and for the root entry (`[MS-CFB]` §2.6.3).
pub const CREATE_TIME: usize = 100;
/// Modification time (`8` bytes, Windows FILETIME). MUST be zero for a stream entry
/// (`[MS-CFB]` §2.6.3).
pub const MODIFY_TIME: usize = 108;
/// Starting sector id (`u32`) — first FAT sector (or mini-FAT sector for a small
/// stream); for the root entry, the first sector of the mini-stream.
pub const START_SECTOR: usize = 116;
/// Stream size (`u64` in v4; the low `u32` in v3, high `u32` reserved zero).
pub const STREAM_SIZE: usize = 120;

/// Directory-entry object type (`[MS-CFB]` §2.6.1, "Object Type" field).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum ObjectType {
    /// Unallocated / unknown directory entry (`0x00`).
    Unknown = 0x00,
    /// Storage object — a "directory" containing other entries (`0x01`).
    Storage = 0x01,
    /// Stream object — a "file" of bytes (`0x02`).
    Stream = 0x02,
    /// Root storage object — the unique tree root (`0x05`); also anchors the mini-stream.
    RootStorage = 0x05,
}

impl ObjectType {
    /// Map an object-type wire byte to the typed variant.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<ObjectType> {
        match value {
            0x00 => Some(ObjectType::Unknown),
            0x01 => Some(ObjectType::Storage),
            0x02 => Some(ObjectType::Stream),
            0x05 => Some(ObjectType::RootStorage),
            _ => None,
        }
    }
}

/// Red-black tree node colour (`[MS-CFB]` §2.6.1, "Color Flag" field).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Color {
    /// Red node (`0x00`).
    Red = 0x00,
    /// Black node (`0x01`).
    Black = 0x01,
}

impl Color {
    /// Map a colour-flag wire byte to the typed variant.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Color> {
        match value {
            0x00 => Some(Color::Red),
            0x01 => Some(Color::Black),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_olecf_magic() {
        assert_eq!(
            OLECF_SIGNATURE,
            [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
        );
        // Reads as 0xE11AB1A1E011CFD0 little-endian.
        assert_eq!(u64::from_le_bytes(OLECF_SIGNATURE), 0xE11A_B1A1_E011_CFD0);
        assert_eq!(HEADER_SIZE, 512);
    }

    #[test]
    fn header_field_offsets() {
        assert_eq!(MINOR_VERSION, 24);
        assert_eq!(MAJOR_VERSION, 26);
        assert_eq!(BYTE_ORDER, 28);
        assert_eq!(SECTOR_SHIFT, 30);
        assert_eq!(MINI_SECTOR_SHIFT, 32);
        assert_eq!(NUM_DIR_SECTORS, 40);
        assert_eq!(NUM_FAT_SECTORS, 44);
        assert_eq!(FIRST_DIR_SECTOR, 48);
        assert_eq!(MINI_STREAM_CUTOFF, 56);
        assert_eq!(FIRST_MINIFAT_SECTOR, 60);
        assert_eq!(NUM_MINIFAT_SECTORS, 64);
        assert_eq!(FIRST_DIFAT_SECTOR, 68);
        assert_eq!(NUM_DIFAT_SECTORS, 72);
        assert_eq!(DIFAT_HEADER_OFFSET, 76);
        assert_eq!(DIFAT_HEADER_COUNT, 109);
    }

    #[test]
    fn structural_invariants() {
        assert_eq!(BYTE_ORDER_LE, 0xFFFE);
        assert_eq!(MINI_STREAM_CUTOFF_VALUE, 4096);
        assert_eq!(MINI_SECTOR_SIZE, 64);
        assert_eq!(MINI_SECTOR_SHIFT_VALUE, 6);
        assert_eq!(1usize << MINI_SECTOR_SHIFT_VALUE, MINI_SECTOR_SIZE);
        assert_eq!(SECTOR_SHIFT_V3, 9);
        assert_eq!(SECTOR_SHIFT_V4, 12);
        assert_eq!(1u32 << SECTOR_SHIFT_V3, 512);
        assert_eq!(1u32 << SECTOR_SHIFT_V4, 4096);
        assert_eq!(DIR_ENTRY_SIZE, 128);
    }

    #[test]
    fn special_fat_sector_ids() {
        assert_eq!(FREESECT, 0xFFFF_FFFF);
        assert_eq!(ENDOFCHAIN, 0xFFFF_FFFE);
        assert_eq!(FATSECT, 0xFFFF_FFFD);
        assert_eq!(DIFSECT, 0xFFFF_FFFC);
        assert_eq!(MAXREGSECT, 0xFFFF_FFFA);
        assert_eq!(NOSTREAM, 0xFFFF_FFFF);
        // NOSTREAM and FREESECT share the all-ones sentinel.
        assert_eq!(NOSTREAM, FREESECT);
    }

    #[test]
    fn directory_entry_offsets() {
        assert_eq!(NAME, 0);
        assert_eq!(NAME_LEN, 64);
        assert_eq!(OBJECT_TYPE, 66);
        assert_eq!(COLOR, 67);
        assert_eq!(LEFT_SIBLING, 68);
        assert_eq!(RIGHT_SIBLING, 72);
        assert_eq!(CHILD, 76);
        assert_eq!(CLSID, 80);
        assert_eq!(STATE_BITS, 96);
        assert_eq!(CREATE_TIME, 100);
        assert_eq!(MODIFY_TIME, 108);
        assert_eq!(START_SECTOR, 116);
        assert_eq!(STREAM_SIZE, 120);
        // The entry is exactly 128 bytes: the last field (u64) ends at 128.
        assert_eq!(STREAM_SIZE + 8, DIR_ENTRY_SIZE);
    }

    #[test]
    fn object_type_round_trip() {
        assert_eq!(ObjectType::from_u8(0x00), Some(ObjectType::Unknown));
        assert_eq!(ObjectType::from_u8(0x01), Some(ObjectType::Storage));
        assert_eq!(ObjectType::from_u8(0x02), Some(ObjectType::Stream));
        assert_eq!(ObjectType::from_u8(0x05), Some(ObjectType::RootStorage));
        assert_eq!(ObjectType::from_u8(0x03), None);
        assert_eq!(ObjectType::Storage as u8, 0x01);
        assert_eq!(ObjectType::RootStorage as u8, 0x05);
    }

    #[test]
    fn color_round_trip() {
        assert_eq!(Color::from_u8(0x00), Some(Color::Red));
        assert_eq!(Color::from_u8(0x01), Some(Color::Black));
        assert_eq!(Color::from_u8(0x02), None);
        assert_eq!(Color::Red as u8, 0x00);
        assert_eq!(Color::Black as u8, 0x01);
    }

    #[test]
    fn sector_offset_formula() {
        // (sid + 1) << sector_shift, v3 (512-byte sectors): sector 0 starts at 512.
        let off = |sid: u32, shift: u16| (u64::from(sid) + 1) << shift;
        assert_eq!(off(0, SECTOR_SHIFT_V3), 512);
        assert_eq!(off(1, SECTOR_SHIFT_V3), 1024);
        // mini_offset = msid << 6.
        assert_eq!(0u64 << MINI_SECTOR_SHIFT_VALUE, 0);
        assert_eq!(1u64 << MINI_SECTOR_SHIFT_VALUE, 64);
        assert_eq!(3u64 << MINI_SECTOR_SHIFT_VALUE, 192);
    }
}
