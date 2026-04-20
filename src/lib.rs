//! forensic-catalog — DFIR knowledge as code.
//!
//! This crate publishes two kinds of knowledge:
//!
//! - small static indicator modules such as [`ports`], [`lolbins`], [`paths`],
//!   and [`persistence`]
//! - the larger [`catalog`] module, which models concrete forensic artifacts
//!   with source citations, ATT&CK mappings, triage priority, decode guidance,
//!   parsing profiles, and carving/signature knowledge
//!
//! The published docs are intended to be useful to both developers and DFIR
//! analysts. If you are new to the crate, start here:
//!
//! - [`catalog::CATALOG`] for the artifact registry
//! - [`handbook`] for the analyst-facing handbook
//! - [`references`] for module-level provenance
//! - [`catalog::all_container_profiles`] for outer parsing layers
//! - [`catalog::all_container_signatures`] for carving/recognition guidance
//! - [`catalog::all_parsing_profiles`] for artifact-specific parsing semantics
//! - [`catalog::all_record_signatures`] for record-level carving/validation
//!
//! Practical reading order:
//!
//! 1. Find an artifact in [`catalog::CATALOG`]
//! 2. Check its [`catalog::ArtifactDescriptor::sources`]
//! 3. Resolve its outer parser with [`catalog::ForensicCatalog::container_profile`]
//! 4. Resolve carving rules with [`catalog::ForensicCatalog::container_signature`]
//! 5. Resolve artifact semantics with [`catalog::ForensicCatalog::parsing_profile`]
//! 6. Resolve record-level carving hints with [`catalog::ForensicCatalog::record_signatures`]
//!
//! The repository also keeps deeper maintainer docs:
//!
//! - `README.md` for the project overview and architecture diagrams
//! - `docs/module-sources.md` for the source corpus and knowledge architecture
//! - `archive/sources/source-inventory.md` for the normalized source inventory
//!
//! Scope boundary:
//!
//! This crate is a forensic catalog first, not a full DFIR parsing engine.
//! Compact stable transforms such as `UserAssist` ROT13 or `FILETIME`
//! normalization belong here. Large evolving formats such as full hibernation,
//! WMI repository, or BITS database parsers should stay in separate parser
//! modules or companion crates.

pub mod antiforensics;
pub mod antiforensics_aware;
pub mod catalog;
pub mod chainsaw;
pub mod dependencies;
pub mod eventids;
pub mod evidence;
pub mod forensicartifacts;
pub mod navigator;
pub mod playbooks;
pub mod plugin;
pub mod sigma;
pub mod stix;
pub mod temporal;
pub mod toolchain;
pub mod version_history;
pub mod volatility;
pub mod yara;
pub use catalog as artifact;
pub mod commands;
pub mod encryption;
pub mod handbook;
pub mod lolbins;
pub mod paths;
pub mod pca;
pub mod persistence;
pub mod ports;
pub mod processes;
pub mod no_std_compat;
pub mod references;
pub mod remote_access;
pub mod third_party;
