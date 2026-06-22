//! Universal forensic artifact catalog.
//!
//! Provides a self-describing, queryable registry of forensic artifact locations
//! (registry keys, files, event logs) with embedded decode logic. Consumers
//! query the catalog by id, hive, scope, or MITRE technique and receive fully
//! decoded [`ArtifactRecord`] values -- never raw bytes.
//!
//! # Design principles
//!
//! - **Zero mandatory external deps** -- FILETIME conversion and ROT13 are pure
//!   math/ASCII. Timestamps are ISO 8601 `String`s.
//! - **`const`/`static`-friendly** -- [`ArtifactDescriptor`] and its constituent
//!   enums are all constructible in `const` context. [`Decoder`] is flat (no
//!   recursive `&'static Decoder`).
//! - **Additive** -- existing modules (`ports`, `persistence`, ...) are untouched.
//!   This module is purely additive.
//! - **Single source of truth** -- artifact paths, decode logic, field schemas,
//!   and MITRE mappings live here. Consumers never hardcode them.
//!
//! # Curated source corpus
//!
//! Artifact additions in this module are researched from a maintained DFIR source
//! corpus. The authoritative inventory now lives in machine-readable form under
//! `archive/sources/`:
//!
//! - `catalog-directories.json` for directory-style discovery pages
//! - `manual-sources.json` for curated manual additions and knowledge bases
//! - `dfir-feeds.opml` for subscribed RSS/Atom feeds
//! - `source-inventory.json` for the normalized canonical inventory
//!
//! The catalog should prefer primary/vendor documentation and well-cited
//! practitioner research over generic security blogging. Individual
//! [`ArtifactDescriptor::sources`] entries should still point to the specific
//! authoritative references that justify each artifact; the maintained source
//! corpus is discovery input, not a blanket citation.
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
//!   such as "UserAssist names are ROT13" or "BITS jobs must be reconstructed
//!   from qmgr*.dat records".
//! - [`RecordSignature`] models how to recognize or validate individual records
//!   or payloads inside a container when carving or validating fragments.
//! - [`Decoder`] is reserved for compact, stable transforms we can implement
//!   safely in-core.

mod containers_parsing;
mod decode;
mod descriptors;
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

// ── CATALOG-dependent free functions ─────────────────────────────────────────
// These functions need access to CATALOG (defined below), so they live here
// rather than in containers_parsing.rs.

/// Returns the outer-container parsing profile for a catalog artifact id.
pub fn container_profile_for_artifact(id: &str) -> Option<&'static ContainerProfile> {
    use containers_parsing::artifact_container_bindings;
    if let Some(binding) = artifact_container_bindings()
        .iter()
        .find(|b| b.artifact_id.eq_ignore_ascii_case(id))
    {
        return container_profile(binding.container_id);
    }
    let desc = CATALOG.by_id(id)?;
    containers_parsing::infer_container_profile_pub(desc)
}

/// Returns the outer-container carving/signature guidance for a catalog artifact id.
pub fn container_signature_for_artifact(id: &str) -> Option<&'static ContainerSignature> {
    let profile = container_profile_for_artifact(id)?;
    container_signature(profile.id)
}

/// Returns record signatures associated with a catalog artifact id.
pub fn record_signatures_for_artifact(id: &str) -> Vec<&'static RecordSignature> {
    let direct: Vec<&'static RecordSignature> = all_record_signatures()
        .iter()
        .filter(|sig| {
            sig.artifact_id
                .is_some_and(|artifact_id| artifact_id.eq_ignore_ascii_case(id))
        })
        .collect();
    if !direct.is_empty() {
        return direct;
    }
    if let Some(container_sig) = container_profile_for_artifact(id) {
        return record_signatures_for_container(container_sig.id);
    }
    Vec::new()
}

// ── ForensicCatalog extension methods ─────────────────────────────────────────
// These methods delegate to free functions in sibling modules and therefore
// cannot live in types.rs (which has no visibility into those siblings).

impl ForensicCatalog {
    /// Look up parsing guidance for an artifact id.
    pub fn parsing_profile(&self, id: &str) -> Option<&'static ArtifactParsingProfile> {
        parsing_profile(id)
    }

    /// Look up the container parsing layer for an artifact id.
    pub fn container_profile(&self, id: &str) -> Option<&'static ContainerProfile> {
        container_profile_for_artifact(id)
    }

    /// Look up carving/recognition guidance for an artifact's outer container.
    pub fn container_signature(&self, id: &str) -> Option<&'static ContainerSignature> {
        container_signature_for_artifact(id)
    }

    /// Look up carving/recognition guidance for records associated with an artifact.
    pub fn record_signatures(&self, id: &str) -> Vec<&'static RecordSignature> {
        record_signatures_for_artifact(id)
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

// Re-export private decode helpers so crate-internal tests can call them directly.
#[cfg(test)]
#[doc(hidden)]
pub(crate) use decode::{filetime_to_iso8601, rot13};

// Re-export descriptor statics so crate-internal tests can reference them by name
// (e.g. `USERASSIST_EXE`, `RUN_KEY_HKLM_RUN`). These are not part of the public
// API — consumers should use `CATALOG.by_id(...)` instead.
#[cfg(test)]
#[doc(hidden)]
pub(crate) use descriptors::*;

/// The global forensic artifact catalog containing all known artifact descriptors.
///
/// Maintainer note:
/// New descriptors should be researched against the curated DFIR source corpus
/// documented in this module header, then anchored with artifact-specific URLs in
/// the descriptor's `sources` field. Archived source corpora are discovery input;
/// they do not replace per-artifact attribution.
pub static CATALOG: ForensicCatalog = ForensicCatalog::new(descriptors::CATALOG_ENTRIES);

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests;

#[cfg(test)]
mod refactor_contract {
    use super::*;

    /// Verifies that the public API surface of the catalog module remains
    /// accessible after any internal reorganisation (e.g. splitting artifact.rs
    /// into src/catalog/). If this test compiles and passes, the refactor has
    /// not broken any consumer-facing path.
    #[test]
    fn catalog_api_surface_intact() {
        // CATALOG static and its query methods must be reachable.
        let _ = CATALOG.by_id("userassist_exe");
        let _ = CATALOG.for_triage();
        let _ = CATALOG.by_mitre("T1547.001");
        let _ = CATALOG.filter_by_keyword("prefetch");

        // Key public types must be nameable without qualification issues.
        let _: ArtifactLocation = ArtifactLocation::File;
        let _: TriagePriority = TriagePriority::Critical;
        let _: DataScope = DataScope::User;
        let _: OsScope = OsScope::Win10Plus;
        let _: HiveTarget = HiveTarget::NtUser;

        // Free functions must be reachable.
        let _ = all_container_profiles();
        let _ = all_container_signatures();
        let _ = all_parsing_profiles();
        let _ = all_record_signatures();
    }
}
