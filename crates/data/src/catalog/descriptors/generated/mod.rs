//! Auto-generated artifact descriptor modules from the mass-import ingest pipeline.
//!
//! Each module was produced by `cargo run -p ingest -- --source <name>` and contains
//! `ArtifactDescriptor` statics ready for inclusion in `CATALOG_ENTRIES`.
//!
//! Descriptor statics per module. Every one of them is wired into
//! `CATALOG_ENTRIES` — `catalog_integrity::every_generated_descriptor_is_reachable_from_the_catalog`
//! enforces it, so these counts are also the number of catalog entries each
//! module contributes.
//!
//! | Source      | Count |
//! |-------------|-------|
//! | browsers    |    37 |
//! | dfir_scripts|   404 |
//! | evtx        |   995 |
//! | fa          |  2597 |
//! | kape        |  2422 |
//! | nirsoft     |    22 |
//! | regedit     |    43 |
//! | velociraptor|   122 |
//! | **Total**   |**6642**|

pub(super) mod browsers_generated;
pub(super) mod dfir_scripts_generated;
pub(super) mod evtx_generated;
pub(super) mod fa_generated;
pub(super) mod kape_generated;
pub(super) mod nirsoft_generated;
pub(super) mod regedit_generated;
pub(super) mod velociraptor_generated;
