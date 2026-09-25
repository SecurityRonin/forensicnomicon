//! GMDSOFT MD-NEXT mobile forensic image (`.mdf`) layout constants.
//!
//! Not the Alcohol 120% Media Descriptor File, the SQL Server master database
//! file, or ASAM MDF, which share the `.mdf` extension.
//!
//! GMDSOFT publishes no specification. Its own material says only that MD-NEXT
//! "saves physically extracted data as MDF image file" (MD–BOX product sheet,
//! "Image File save using MD–NEXT").
//! Source: <https://www.gmdsoft.com/?jet_download=6696afedc3b0acffb75aedc8398c010cfd33b97d>
//!
//! Everything else here was reverse-engineered by the SecurityRonin
//! `mdf-forensic` reader and checked on real MD-NEXT images of logical
//! (`adb backup`) acquisitions on 2026-09-24 `[OBSERVED]`. No public document
//! confirms it.
//!
//! | Region    | Where                                   | Contents |
//! |-----------|-----------------------------------------|----------|
//! | Header    | offset 0, [`HEADER_MAGIC`]              | plaintext Android `getprop` / `dumpsys` / `logcat` output |
//! | Payload   | after the header                        | each acquired file stored raw from a [`PAYLOAD_ALIGN`] boundary, the rest of its last block zero-filled |
//! | Catalogue | [`CATALOGUE_MAGIC`], within the final 128 MiB in the images examined | the file index, **not stored in the clear**: 8.0 bits/byte, no known compression header |
//! | Footer    | [`FOOTER_MAGIC`], within the final 4 KiB, not the final 16 bytes | — |
//!
//! Both images examined were a whole number of 512-byte blocks long.
//!
//! **Consequences for analysis.**
//!
//! - The catalogue cannot be read without the vendor's tooling, so files are
//!   found by carving the payload. A byte search can show a file is *present*;
//!   it can never show one is *absent*.
//! - Near the front of the payload MD-NEXT writes a plaintext JSON backup
//!   manifest, `{"<package>":{"<device path>":"<value>", …}, …}`. For
//!   [`WHATSAPP_PACKAGE`] the value is the same 64-hex string for every file:
//!   the 32-byte WhatsApp end-to-end backup key. Carved `.crypt15` backups
//!   decrypt and pass AES-GCM authentication under it, so an image that holds
//!   WhatsApp backups also holds their key. Other packages' values were not
//!   64-hex in the images examined.

/// `GMDHDR`, at offset 0 of every image.
pub const HEADER_MAGIC: [u8; 6] = *b"GMDHDR";
/// `GMDFHL`, opening the trailing file catalogue.
pub const CATALOGUE_MAGIC: [u8; 6] = *b"GMDFHL";
/// `FHO`, the footer marker.
pub const FOOTER_MAGIC: [u8; 3] = *b"FHO";
/// Every acquired file in the payload starts on this boundary; the rest of its
/// last block is zero-filled.
pub const PAYLOAD_ALIGN: u64 = 512;
/// Length of a key value in the embedded backup manifest (32 bytes as hex).
pub const MANIFEST_KEY_HEX_LEN: usize = 64;
/// The manifest package whose value is the WhatsApp backup key.
pub const WHATSAPP_PACKAGE: &str = "com.whatsapp";

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
