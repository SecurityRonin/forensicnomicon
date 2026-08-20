//! AFF4 (Advanced Forensic Format 4) container constants.
//!
//! Single source of truth for the structural facts of AFF4: a **ZIP container**
//! (local-file-header magic `PK\x03\x04`) carrying RDF/Turtle metadata
//! (`information.turtle`) and `aff4:ImageStream` data split into chunked "bevies".
//!
//! Source: AFF4 Standard v1.0 (Schatz Forensic)
//!   <https://github.com/aff4/Standard>

/// ZIP local-file-header signature `PK\x03\x04` — present at offset 0 of every AFF4
/// image (AFF4 is a ZIP container).
pub const ZIP_LOCAL_FILE_HEADER_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
/// ZIP end-of-central-directory signature `PK\x05\x06` (locates the central directory).
pub const ZIP_EOCD_MAGIC: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];

/// AFF4 RDF schema namespace.
pub const AFF4_NAMESPACE: &str = "http://aff4.org/Schema#";
/// URI scheme for AFF4 object identifiers (`aff4://<uuid>`).
pub const URI_SCHEME: &str = "aff4://";

/// ZIP segment holding the Turtle/RDF metadata that describes the image objects.
pub const METADATA_SEGMENT: &str = "information.turtle";
/// ZIP segment holding the container version string.
pub const VERSION_SEGMENT: &str = "version.txt";

/// Well-known RDF predicates used to model an AFF4 disk image. The image is either
/// a direct `aff4:ImageStream` or an `aff4:Map` that redirects virtual ranges to
/// ImageStream regions, zero-fill, or an all-`0xFF` symbolic stream.
pub const RDF_PREDICATES: &[&str] = &[
    "aff4:type",
    "aff4:size",
    "aff4:chunkSize",
    "aff4:chunksInSegment",
    "aff4:compressionMethod",
    "aff4:stored",
    "aff4:dataStream",
    "aff4:target",
];

/// Canonical `aff4:ImageStream` geometry from the AFF4 standard / aff4-imager:
/// 32 KiB chunks, 2048 chunks per bevy segment (a 64 MiB bevy).
pub const DEFAULT_CHUNK_SIZE: u64 = 32 * 1024;
pub const DEFAULT_CHUNKS_PER_SEGMENT: u64 = 2048;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_local_file_header_magic() {
        // AFF4 images are ZIP files; offset 0 is the ZIP local file header signature.
        assert_eq!(ZIP_LOCAL_FILE_HEADER_MAGIC, [0x50, 0x4B, 0x03, 0x04]);
        assert_eq!(&ZIP_LOCAL_FILE_HEADER_MAGIC[0..2], b"PK");
    }

    #[test]
    fn zip_end_of_central_directory_magic() {
        assert_eq!(ZIP_EOCD_MAGIC, [0x50, 0x4B, 0x05, 0x06]);
    }

    #[test]
    fn aff4_namespace_and_metadata_segment() {
        assert_eq!(AFF4_NAMESPACE, "http://aff4.org/Schema#");
        assert_eq!(METADATA_SEGMENT, "information.turtle");
        assert_eq!(VERSION_SEGMENT, "version.txt");
    }

    #[test]
    fn aff4_uri_scheme() {
        assert_eq!(URI_SCHEME, "aff4://");
    }

    #[test]
    fn well_known_rdf_predicates() {
        for p in [
            "aff4:type",
            "aff4:chunkSize",
            "aff4:chunksInSegment",
            "aff4:stored",
        ] {
            assert!(RDF_PREDICATES.contains(&p), "missing predicate {p}");
        }
    }

    #[test]
    fn default_image_stream_geometry() {
        // The canonical ImageStream uses 32 KiB chunks, 2048 chunks per bevy segment.
        assert_eq!(DEFAULT_CHUNK_SIZE, 32 * 1024);
        assert_eq!(DEFAULT_CHUNKS_PER_SEGMENT, 2048);
    }
}
