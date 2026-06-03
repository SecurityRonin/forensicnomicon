//! Apple DMG / UDIF disk-image format constants and offset layouts.
//!
//! Single source of truth for the `koly` trailer, the `mish` (BLKX) block table,
//! and the UDIF block-chunk type values. A DMG has no header magic — the 512-byte
//! `koly` trailer lives at *end-of-file* (all big-endian).
//!
//! Source: Apple Universal Disk Image Format (UDIF), as documented by libdmg /
//! the `dmg2img` and Apple `hdiutil` reverse-engineering efforts.
//!   http://newosxbook.com/DMG.html

/// `koly` trailer magic, read as a big-endian `u32` (bytes `"koly"`).
pub const KOLY_MAGIC: u32 = 0x6B6F_6C79;
/// The koly trailer is exactly 512 bytes, located at end-of-file.
pub const KOLY_SIZE: u64 = 512;

/// `mish` BLKX block-table magic (bytes `"mish"`), big-endian.
pub const MISH_MAGIC: u32 = 0x6D69_7368;

/// Field offsets within the 512-byte koly trailer (all big-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct KolyTrailerOffsets {
    pub magic: u64,        // 0x000 u32  "koly"
    pub version: u64,      // 0x004 u32  (4)
    pub header_size: u64,  // 0x008 u32  (512)
    pub xml_offset: u64,   // 0x0D8 u64  offset of the property-list (plist) XML
    pub xml_length: u64,   // 0x0E0 u64  length of the plist XML
    pub sector_count: u64, // 0x1EC u64  total sectors of the decoded image
}

pub const KOLY_OFFSETS: KolyTrailerOffsets = KolyTrailerOffsets {
    magic: 0x000,
    version: 0x004,
    header_size: 0x008,
    xml_offset: 0x0D8,
    xml_length: 0x0E0,
    sector_count: 0x1EC,
};

/// UDIF BLKX block-chunk `entry_type` values (big-endian `u32`).
/// `BLK_ADC`/`BLK_BZIP2`/`BLK_LZFSE` are valid UDIF types not all decoders support.
pub const BLK_ZERO: u32 = 0x0000_0000;
pub const BLK_RAW: u32 = 0x0000_0001;
pub const BLK_IGNORE: u32 = 0x0000_0002;
pub const BLK_ADC: u32 = 0x8000_0004;
pub const BLK_ZLIB: u32 = 0x8000_0005;
pub const BLK_BZIP2: u32 = 0x8000_0006;
pub const BLK_LZFSE: u32 = 0x8000_0007;
pub const BLK_COMMENT: u32 = 0x7FFF_FFFE;
pub const BLK_TERMINATOR: u32 = 0xFFFF_FFFF;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn koly_trailer_magic_and_size() {
        // "koly" read as a big-endian u32; the trailer is 512 bytes at end-of-file.
        assert_eq!(KOLY_MAGIC, 0x6B6F_6C79);
        assert_eq!(&KOLY_MAGIC.to_be_bytes(), b"koly");
        assert_eq!(KOLY_SIZE, 512);
    }

    #[test]
    fn mish_block_table_magic() {
        assert_eq!(MISH_MAGIC, 0x6D69_7368);
        assert_eq!(&MISH_MAGIC.to_be_bytes(), b"mish");
    }

    #[test]
    fn koly_trailer_offsets() {
        assert_eq!(KOLY_OFFSETS.magic, 0x00);
        assert_eq!(KOLY_OFFSETS.version, 0x04);
        assert_eq!(KOLY_OFFSETS.header_size, 0x08);
        assert_eq!(KOLY_OFFSETS.xml_offset, 0xD8); // 216
        assert_eq!(KOLY_OFFSETS.xml_length, 0xE0); // 224
        assert_eq!(KOLY_OFFSETS.sector_count, 0x1EC); // 492
    }

    #[test]
    fn block_chunk_types() {
        assert_eq!(BLK_ZERO, 0x0000_0000);
        assert_eq!(BLK_RAW, 0x0000_0001);
        assert_eq!(BLK_IGNORE, 0x0000_0002);
        assert_eq!(BLK_ADC, 0x8000_0004);
        assert_eq!(BLK_ZLIB, 0x8000_0005);
        assert_eq!(BLK_BZIP2, 0x8000_0006);
        assert_eq!(BLK_LZFSE, 0x8000_0007);
        assert_eq!(BLK_COMMENT, 0x7FFF_FFFE);
        assert_eq!(BLK_TERMINATOR, 0xFFFF_FFFF);
    }
}
