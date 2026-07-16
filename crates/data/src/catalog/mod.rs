//! Forensic artifact catalog — assembled dataset + global [`CATALOG`].
//!
//! The catalog **engine** (descriptor [`types`], the [`ForensicCatalog`] lookup
//! engine and its query methods, container/record parsing profiles, and in-core
//! decoders) lives in the `forensicnomicon-core` crate. This module owns the
//! fast-moving **data** — the ~6.5k assembled artifact descriptors — and wires
//! them into the compile-time global [`CATALOG`].
//!
//! The whole engine surface is re-exported here, so existing
//! `forensicnomicon::catalog::*` (and crate-internal `crate::catalog::*`) paths —
//! including the `types` submodule the generated descriptors reference — resolve
//! exactly as they did before the engine/data split.
//!
//! # Curated source corpus
//!
//! Artifact additions are researched from a maintained DFIR source corpus under
//! `archive/sources/` (`catalog-directories.json`, `manual-sources.json`,
//! `dfir-feeds.opml`, `source-inventory.json`). Prefer primary/vendor
//! documentation and well-cited practitioner research; each
//! [`ArtifactDescriptor::sources`] entry should still point to the specific
//! authoritative references that justify the artifact.

// Re-export the entire engine surface (types, the `types` module, ForensicCatalog,
// parsing-profile free functions, decode helpers) from core. This makes every
// `crate::catalog::*` and `crate::catalog::types::*` path used by the descriptor
// dataset resolve unchanged.
pub use forensicnomicon_core::catalog::*;

mod descriptors;

/// The global forensic artifact catalog containing all known artifact descriptors.
///
/// Maintainer note:
/// New descriptors should be researched against the curated DFIR source corpus
/// documented in this module header, then anchored with artifact-specific URLs in
/// the descriptor's `sources` field. Archived source corpora are discovery input;
/// they do not replace per-artifact attribution.
pub static CATALOG: ForensicCatalog = ForensicCatalog::new(descriptors::CATALOG_ENTRIES);

// ── Backward-compatible free functions ───────────────────────────────────────
// Pre-split these lived here and queried the global CATALOG directly. They now
// delegate to the equivalent engine methods on the global catalog instance, so
// the public `forensicnomicon::catalog::*_for_artifact` paths keep working.

/// Returns the outer-container parsing profile for a catalog artifact id.
pub fn container_profile_for_artifact(id: &str) -> Option<&'static ContainerProfile> {
    CATALOG.container_profile(id)
}

/// Returns the outer-container carving/signature guidance for a catalog artifact id.
pub fn container_signature_for_artifact(id: &str) -> Option<&'static ContainerSignature> {
    CATALOG.container_signature(id)
}

/// Returns record signatures associated with a catalog artifact id.
pub fn record_signatures_for_artifact(id: &str) -> Vec<&'static RecordSignature> {
    CATALOG.record_signatures(id)
}

// Re-export descriptor statics so crate-internal tests can reference them by name
// (e.g. `USERASSIST_EXE`, `RUN_KEY_HKLM_RUN`). These are not part of the public
// API -- consumers should use `CATALOG.by_id(...)` instead.
#[cfg(test)]
#[doc(hidden)]
pub(crate) use descriptors::*;

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests;

#[cfg(test)]
mod refactor_contract {

    #[test]
    fn artifact_facade_fns_delegate_to_catalog() {
        for id in [
            "userassist_exe",
            "prefetch_file",
            "run_key_hklm",
            "not-a-real-id",
        ] {
            assert_eq!(
                container_profile_for_artifact(id).is_some(),
                CATALOG.container_profile(id).is_some(),
            );
            assert_eq!(
                container_signature_for_artifact(id).is_some(),
                CATALOG.container_signature(id).is_some(),
            );
            assert_eq!(
                record_signatures_for_artifact(id).len(),
                CATALOG.record_signatures(id).len(),
            );
        }
    }
    use super::*;

    /// Verifies that the public API surface of the catalog module remains
    /// accessible after the engine/data split. If this test compiles and passes,
    /// the split has not broken any consumer-facing path.
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
