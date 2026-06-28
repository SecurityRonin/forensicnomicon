//! Forensic artifact catalog — engine and types.
//!
//! This is the stable engine half of the catalog: the descriptor [`types`], the
//! [`ForensicCatalog`] lookup engine and its query methods, the container/record
//! parsing-profile tables, and the in-core [`Decoder`] logic. It carries **no**
//! artifact data — the assembled descriptor dataset lives in the umbrella
//! `forensicnomicon` crate, which wires it into a global `CATALOG` via
//! [`ForensicCatalog::new`].
//!
//! Parser knowledge is layered:
//!
//! - [`ContainerProfile`] models how to open and enumerate the outer container
//!   such as an offline Registry hive, SQLite database, EVTX log, or memory image.
//! - [`ContainerSignature`] models how to recognize or carve that container
//!   from raw bytes in unallocated space or memory.
//! - [`ArtifactDescriptor`] identifies where the artifact lives inside that
//!   container or on disk.
//! - [`ArtifactParsingProfile`] captures artifact-specific interpretation rules
//!   such as "UserAssist names are ROT13".
//! - [`RecordSignature`] models how to recognize or validate individual records
//!   or payloads inside a container when carving or validating fragments.
//! - [`Decoder`] is reserved for compact, stable transforms we can implement
//!   safely in-core.

mod containers_parsing;
mod decode;
pub mod types;

pub use types::{
    ArtifactDescriptor, ArtifactLocation, ArtifactParsingProfile, ArtifactQuery, ArtifactRecord,
    ArtifactValue, BinaryField, BinaryFieldType, ContainerProfile, ContainerSignature, DataScope,
    DecodeError, Decoder, FieldSchema, ForensicCatalog, HiveTarget, OsScope, Platform,
    PlatformMask, RecordSignature, TriagePriority, ValueType,
};

pub use containers_parsing::{
    all_container_profiles, all_container_signatures, all_parsing_profiles, all_record_signatures,
    container_profile, container_signature, parsing_profile, record_signatures_for_container,
};

// In-core decode helpers, exposed (doc-hidden) so cross-crate catalog tests in the
// umbrella crate can exercise ROT13 / FILETIME directly. Not part of the stable API.
#[doc(hidden)]
pub use decode::{filetime_to_iso8601, rot13};

// ── ForensicCatalog extension methods ─────────────────────────────────────────
// These delegate to sibling parsing/decode modules. They look an artifact up in
// `self` (the catalog instance) rather than any global, so the engine carries no
// dependency on a particular dataset.

impl ForensicCatalog {
    /// Look up parsing guidance for an artifact id.
    pub fn parsing_profile(&self, id: &str) -> Option<&'static ArtifactParsingProfile> {
        containers_parsing::parsing_profile(id)
    }

    /// Look up the container parsing layer for an artifact id.
    pub fn container_profile(&self, id: &str) -> Option<&'static ContainerProfile> {
        if let Some(binding) = containers_parsing::artifact_container_bindings()
            .iter()
            .find(|b| b.artifact_id.eq_ignore_ascii_case(id))
        {
            return containers_parsing::container_profile(binding.container_id);
        }
        let desc = self.by_id(id)?;
        containers_parsing::infer_container_profile_pub(desc)
    }

    /// Look up carving/recognition guidance for an artifact's outer container.
    pub fn container_signature(&self, id: &str) -> Option<&'static ContainerSignature> {
        let profile = self.container_profile(id)?;
        containers_parsing::container_signature(profile.id)
    }

    /// Look up carving/recognition guidance for records associated with an artifact.
    pub fn record_signatures(&self, id: &str) -> Vec<&'static RecordSignature> {
        let direct: Vec<&'static RecordSignature> = containers_parsing::all_record_signatures()
            .iter()
            .filter(|sig| {
                sig.artifact_id
                    .is_some_and(|artifact_id| artifact_id.eq_ignore_ascii_case(id))
            })
            .collect();
        if !direct.is_empty() {
            return direct;
        }
        if let Some(profile) = self.container_profile(id) {
            return containers_parsing::record_signatures_for_container(profile.id);
        }
        Vec::new()
    }

    /// Decode raw data using the descriptor's embedded decoder.
    ///
    /// # Parameters
    /// - `descriptor` -- the catalog entry describing the artifact
    /// - `name` -- the registry value name (or filename), used by ROT13 and
    ///   PipeDelimited decoders
    /// - `raw` -- the raw byte payload of the registry value or file content
    pub fn decode(
        &self,
        descriptor: &ArtifactDescriptor,
        name: &str,
        raw: &[u8],
    ) -> Result<ArtifactRecord, DecodeError> {
        decode::decode_artifact(descriptor, name, raw)
    }
}
