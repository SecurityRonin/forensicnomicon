//! Auto-generated artifact descriptor modules from the mass-import ingest pipeline.
//!
//! Each module was produced by `cargo run -p ingest -- --source <name>` and contains
//! `ArtifactDescriptor` statics ready for inclusion in `CATALOG_ENTRIES`.
//!
//! Total generated statics (deduplicated):
//!
//! | Source      | Count |
//! |-------------|-------|
//! | browsers    |    37 |
//! | evtx        |   995 |
//! | fa          |  2545 |
//! | kape        |  2422 |
//! | nirsoft     |    22 |
//! | regedit     |    44 |
//! | velociraptor|   122 |
//! | **Total**   |**6187**|

pub(super) mod browsers_generated;
pub(super) mod evtx_generated;
pub(super) mod fa_generated;
pub(super) mod kape_generated;
pub(super) mod nirsoft_generated;
pub(super) mod regedit_generated;
pub(super) mod velociraptor_generated;
