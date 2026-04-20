//! forensicnomicon — the comprehensive DFIR artifact catalog.
//!
//! 187 forensic artifacts — registry keys, files, event logs, memory regions —
//! each with a decoder, MITRE ATT&CK mapping, triage priority, and source
//! citations. Cross-referenced against Sigma rules, KAPE targets, Velociraptor
//! artifacts, STIX 2.1 observables, YARA templates, and investigation playbooks.
//! Zero dependencies. Everything in `const`/`static` memory.
//!
//! # Quick start
//!
//! ```rust
//! use forensicnomicon::catalog::{CATALOG, TriagePriority};
//! use forensicnomicon::ports::is_suspicious_port;
//!
//! // Boolean checks — no allocation
//! assert!(is_suspicious_port(4444));
//!
//! // Critical artifacts, triage order
//! let critical: Vec<_> = CATALOG.for_triage()
//!     .into_iter()
//!     .filter(|d| d.triage_priority == TriagePriority::Critical)
//!     .collect();
//! ```
//!
//! # Module map
//!
//! ## Artifact catalog
//!
//! - [`catalog`] / [`artifact`] — 187-entry descriptor registry with decode,
//!   ATT&CK mapping, triage priority, parsing profiles, and carving signatures.
//!   Start with [`catalog::CATALOG`].
//!
//! ## Investigation support
//!
//! - [`playbooks`] — six directed investigation paths (lateral movement, credential
//!   harvesting, persistence, exfiltration, execution, defense evasion)
//! - [`evidence`] — evidence strength ratings (`Unreliable` → `Definitive`) per artifact
//! - [`volatility`] — RFC 3227 Order of Volatility; use [`volatility::acquisition_order`]
//! - [`temporal`] — temporal correlation hints for timeline analysis and timestomp detection
//! - [`antiforensics_aware`] — per-artifact anti-forensic risk model
//! - [`version_history`] — artifact changes across OS versions
//! - [`dependencies`] — artifact dependency graph; use [`dependencies::full_collection_set`]
//!
//! ## Detection engineering
//!
//! - [`sigma`] — Sigma rule cross-references; [`sigma::sigma_refs_for`]
//! - [`chainsaw`] — Chainsaw / Hayabusa hunt rule references
//! - [`navigator`] — ATT&CK Navigator JSON layer generator
//! - [`yara`] — YARA rule skeleton generator
//! - [`stix`] — STIX 2.1 observable mappings and indicator patterns
//!
//! ## Collection toolchain
//!
//! - [`toolchain`] — KAPE targets/modules and Velociraptor artifact names;
//!   use [`toolchain::kape_target_set`] for deduplicated collection plans
//! - [`forensicartifacts`] — ForensicArtifacts.com definition names and YAML export
//! - [`eventids`] — Windows Event ID enrichment (forensic meaning, MITRE, artifact)
//!
//! ## Static indicator tables
//!
//! These modules export only `&'static` slices and boolean lookups — safe in
//! `no_std` environments:
//!
//! - [`ports`] — suspicious TCP/UDP ports (`is_suspicious_port`)
//! - [`lolbins`] — Windows LOLBAS + Linux GTFOBins
//! - [`persistence`] — run keys, cron, LaunchAgents, IFEO, AppInit
//! - [`processes`] — masquerade targets and offensive process names
//! - [`commands`] — log-wipe commands, rootkit names
//! - [`paths`] — suspicious staging and hijack paths
//! - [`antiforensics`] — anti-forensic tool indicators
//! - [`encryption`] — encryption tool paths
//! - [`remote_access`] — LOLRMM / RMM tool indicators
//! - [`third_party`] — PuTTY, WinSCP, cloud sync, browser registry artifacts
//! - [`pca`] — Windows 11 Program Compatibility Assistant artifacts
//! - [`references`] — queryable source map per module
//! - [`no_std_compat`] — documents and validates the `no_std`-safe API surface
//!
//! ## Extension
//!
//! - [`plugin`] — runtime decoder plugin architecture ([`plugin::ExtendedCatalog`],
//!   [`plugin::CustomDecoder`] trait)
//!
//! # Parsing stack
//!
//! ```text
//! Raw bytes → ContainerSignature → ContainerProfile → ArtifactDescriptor
//!          → ArtifactParsingProfile → RecordSignature → Decoder → ArtifactRecord
//! ```
//!
//! All layers queryable via `CATALOG`:
//!
//! ```rust
//! use forensicnomicon::catalog::CATALOG;
//! let cp = CATALOG.container_profile("windows_registry_hive");
//! let pp = CATALOG.parsing_profile("userassist_exe");
//! ```
//!
//! # Scope boundary
//!
//! This crate is a forensic catalog first, not a full DFIR parsing engine.
//! Compact stable transforms such as `UserAssist` ROT13 or `FILETIME`
//! normalization belong here. Large evolving formats such as full hibernation,
//! WMI repository, or BITS database parsers should stay in separate companion crates.

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
