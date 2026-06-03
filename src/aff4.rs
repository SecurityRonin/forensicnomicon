//! AFF4 (Advanced Forensic Format 4) container constants.
//!
//! Single source of truth for the structural facts of AFF4: a **ZIP container**
//! (local-file-header magic `PK\x03\x04`) carrying RDF/Turtle metadata
//! (`information.turtle`) and `aff4:ImageStream` data split into chunked "bevies".
//!
//! Source: AFF4 Standard v1.0 (Schatz Forensic)
//!   https://github.com/aff4/Standard

// (implementation added in the GREEN commit)

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
        for p in ["aff4:type", "aff4:chunkSize", "aff4:chunksInSegment", "aff4:stored"] {
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
