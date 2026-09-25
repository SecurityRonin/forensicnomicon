//! GMDSOFT MD-NEXT mobile forensic image (`.mdf`) layout constants.
//!
//! Not the Alcohol 120% Media Descriptor File, the SQL Server master database
//! file, or ASAM MDF, which share the `.mdf` extension.

/// `GMDHDR`, at offset 0 of every image.
pub const HEADER_MAGIC: [u8; 6] = [0; 6];
/// `GMDFHL`, opening the trailing file catalogue.
pub const CATALOGUE_MAGIC: [u8; 6] = [0; 6];
/// `FHO`, the footer marker.
pub const FOOTER_MAGIC: [u8; 3] = [0; 3];
/// Every acquired file in the payload starts on this boundary.
pub const PAYLOAD_ALIGN: u64 = 0;
/// Length of a key value in the embedded backup manifest.
pub const MANIFEST_KEY_HEX_LEN: usize = 0;
/// The manifest package whose value is the WhatsApp backup key.
pub const WHATSAPP_PACKAGE: &str = "";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_markers() {
        assert_eq!(&HEADER_MAGIC, b"GMDHDR");
        assert_eq!(&CATALOGUE_MAGIC, b"GMDFHL");
        assert_eq!(&FOOTER_MAGIC, b"FHO");
    }

    #[test]
    fn payload_files_sit_on_a_512_byte_grid() {
        assert_eq!(PAYLOAD_ALIGN, 512);
    }

    #[test]
    fn the_whatsapp_manifest_value_is_a_32_byte_key_in_hex() {
        assert_eq!(MANIFEST_KEY_HEX_LEN, 64);
        assert_eq!(MANIFEST_KEY_HEX_LEN / 2, 32);
        assert_eq!(WHATSAPP_PACKAGE, "com.whatsapp");
    }
}
