//! Decoder plugin architecture.
//!
//! Provides a runtime-extensible wrapper around the static catalog,
//! allowing third-party crates to register custom decoders and artifact
//! descriptors without forking the core catalog.
//!
//! The core `CATALOG` static remains zero-alloc; `ExtendedCatalog` is
//! heap-allocated and intended for runtime use.

use crate::catalog::{ArtifactDescriptor, ArtifactValue, DecodeError, ForensicCatalog, CATALOG};

/// Trait for custom artifact decoders registered at runtime.
pub trait CustomDecoder: Send + Sync {
    /// Unique identifier for this decoder (e.g., "my_custom_format").
    fn id(&self) -> &str;

    /// Decode raw bytes with an optional name parameter.
    /// Returns a list of (field_name, value) pairs.
    fn decode(&self, raw: &[u8], name: &str) -> Result<Vec<(String, ArtifactValue)>, DecodeError>;
}

/// A runtime-extensible catalog wrapping the static [`CATALOG`].
///
/// Supports additional custom decoders and custom artifact descriptors.
/// The base catalog is unmodified.
pub struct ExtendedCatalog {
    base: &'static ForensicCatalog,
    custom_decoders: Vec<Box<dyn CustomDecoder>>,
    custom_descriptors: Vec<ArtifactDescriptor>,
}

impl Default for ExtendedCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtendedCatalog {
    /// Create a new ExtendedCatalog wrapping the global static CATALOG.
    pub fn new() -> Self {
        Self {
            base: &CATALOG,
            custom_decoders: Vec::new(),
            custom_descriptors: Vec::new(),
        }
    }

    /// Register a custom decoder.
    pub fn register_decoder<D: CustomDecoder + 'static>(&mut self, decoder: D) {
        self.custom_decoders.push(Box::new(decoder));
    }

    /// Register a custom artifact descriptor.
    pub fn register_descriptor(&mut self, descriptor: ArtifactDescriptor) {
        self.custom_descriptors.push(descriptor);
    }

    /// Look up an artifact descriptor by ID, checking custom descriptors first.
    pub fn by_id(&self, id: &str) -> Option<&ArtifactDescriptor> {
        self.custom_descriptors
            .iter()
            .find(|d| d.id == id)
            .or_else(|| self.base.by_id(id))
    }

    /// Returns the total number of descriptors (base + custom).
    pub fn len(&self) -> usize {
        self.base.for_triage().len() + self.custom_descriptors.len()
    }

    /// Returns true if there are no descriptors.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Find a custom decoder by ID.
    pub fn custom_decoder(&self, id: &str) -> Option<&dyn CustomDecoder> {
        self.custom_decoders
            .iter()
            .find(|d| d.id() == id)
            .map(|d| d.as_ref())
    }

    /// Returns the number of registered custom decoders.
    pub fn custom_decoder_count(&self) -> usize {
        self.custom_decoders.len()
    }

    /// Returns the number of registered custom descriptors.
    pub fn custom_descriptor_count(&self) -> usize {
        self.custom_descriptors.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{
        ArtifactDescriptor, ArtifactType, DataScope, Decoder, OsScope, TriagePriority,
    };

    struct TestDecoder {
        id: String,
    }

    impl CustomDecoder for TestDecoder {
        fn id(&self) -> &str {
            &self.id
        }

        fn decode(
            &self,
            raw: &[u8],
            _name: &str,
        ) -> Result<Vec<(String, ArtifactValue)>, DecodeError> {
            let text = std::str::from_utf8(raw).map_err(|_| DecodeError::InvalidUtf8)?;
            Ok(vec![(
                "value".to_string(),
                ArtifactValue::Text(text.to_string()),
            )])
        }
    }

    fn make_test_descriptor() -> ArtifactDescriptor {
        ArtifactDescriptor {
            id: "custom_test_artifact",
            name: "Custom Test Artifact",
            artifact_type: ArtifactType::File,
            hive: None,
            key_path: "",
            value_name: None,
            file_path: Some("/tmp/test"),
            scope: DataScope::System,
            os_scope: OsScope::Linux,
            decoder: Decoder::Identity,
            meaning: "Test artifact for plugin tests",
            mitre_techniques: &["T1059"],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &["https://example.com/test"],
            evidence_strength: None,
            evidence_caveats: &[],
            volatility: None,
            volatility_rationale: "",
        }
    }

    #[test]
    fn extended_catalog_wraps_base() {
        let ec = ExtendedCatalog::new();
        // Should find base catalog artifacts
        assert!(ec.by_id("userassist_exe").is_some());
        assert!(ec.by_id("prefetch_file").is_some());
    }

    #[test]
    fn register_custom_descriptor() {
        let mut ec = ExtendedCatalog::new();
        let desc = make_test_descriptor();
        let initial_count = ec.len();
        ec.register_descriptor(desc);
        assert_eq!(ec.len(), initial_count + 1);
        assert_eq!(ec.custom_descriptor_count(), 1);
    }

    #[test]
    fn custom_descriptor_found_by_id() {
        let mut ec = ExtendedCatalog::new();
        ec.register_descriptor(make_test_descriptor());
        let found = ec.by_id("custom_test_artifact");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Custom Test Artifact");
    }

    #[test]
    fn custom_descriptor_overrides_base() {
        // Registering with same ID as base should return custom first
        let mut ec = ExtendedCatalog::new();
        let mut desc = make_test_descriptor();
        desc.id = "userassist_exe"; // override base artifact
        desc.name = "Custom Override";
        ec.register_descriptor(desc);
        // Custom should come first
        let found = ec.by_id("userassist_exe").unwrap();
        assert_eq!(found.name, "Custom Override");
    }

    #[test]
    fn register_custom_decoder() {
        let mut ec = ExtendedCatalog::new();
        let decoder = TestDecoder {
            id: "test_decoder".to_string(),
        };
        ec.register_decoder(decoder);
        assert_eq!(ec.custom_decoder_count(), 1);
    }

    #[test]
    fn custom_decoder_found_by_id() {
        let mut ec = ExtendedCatalog::new();
        ec.register_decoder(TestDecoder {
            id: "my_decoder".to_string(),
        });
        assert!(ec.custom_decoder("my_decoder").is_some());
        assert!(ec.custom_decoder("nonexistent").is_none());
    }

    #[test]
    fn custom_decoder_decodes_utf8() {
        let mut ec = ExtendedCatalog::new();
        ec.register_decoder(TestDecoder {
            id: "utf8_decoder".to_string(),
        });
        let decoder = ec.custom_decoder("utf8_decoder").unwrap();
        let result = decoder.decode(b"hello world", "").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "value");
        assert_eq!(result[0].1, ArtifactValue::Text("hello world".to_string()));
    }

    #[test]
    fn custom_decoder_returns_error_for_invalid_utf8() {
        let mut ec = ExtendedCatalog::new();
        ec.register_decoder(TestDecoder {
            id: "utf8_decoder".to_string(),
        });
        let decoder = ec.custom_decoder("utf8_decoder").unwrap();
        let result = decoder.decode(&[0xFF, 0xFE, 0x00], "");
        assert!(result.is_err());
    }

    #[test]
    fn default_extended_catalog_is_not_empty() {
        let ec = ExtendedCatalog::default();
        assert!(!ec.is_empty());
    }
}
