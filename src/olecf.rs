//! OLE Compound File Binary (`[MS-CFB]`) format constants and offset layouts.
//!
//! Knowledge-only module: signature, header/directory-entry offsets, sector
//! invariants, special FAT sector ids, and the object-type / colour enums.
//! See `[MS-CFB]` §2 and libyal `libolecf`. Constants are added in the GREEN commit.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_olecf_magic() {
        assert_eq!(OLECF_SIGNATURE, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
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
        assert_eq!(SECTOR_SHIFT_V3, 9);
        assert_eq!(SECTOR_SHIFT_V4, 12);
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
    }

    #[test]
    fn object_type_round_trip() {
        assert_eq!(ObjectType::from_u8(0x01), Some(ObjectType::Storage));
        assert_eq!(ObjectType::from_u8(0x02), Some(ObjectType::Stream));
        assert_eq!(ObjectType::from_u8(0x05), Some(ObjectType::RootStorage));
        assert_eq!(ObjectType::from_u8(0x03), None);
    }

    #[test]
    fn color_round_trip() {
        assert_eq!(Color::from_u8(0x00), Some(Color::Red));
        assert_eq!(Color::from_u8(0x01), Some(Color::Black));
        assert_eq!(Color::from_u8(0x02), None);
    }
}
