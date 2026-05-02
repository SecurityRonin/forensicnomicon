//! forensicnomicon — the comprehensive DFIR artifact catalog.
//!
//! **6,548 forensic artifacts**, each enriched beyond just a path.
//! Other registries tell you where an artifact lives. forensicnomicon tells
//! you what it means, how to decode it, how reliable it is as evidence,
//! when to acquire it, what else to collect alongside it, and which detection
//! rules apply — all compiled into your binary at zero runtime cost.
//!
//! 361 entries are fully curated with all enrichments. The remaining 6,187
//! are generated from seven authoritative corpora — KAPE targets (2,422),
//! ForensicArtifacts YAML (2,545), EVTX/ETW channels (995), Velociraptor
//! (122), RECmd batch files (44), browser paths (37), NirSoft (22) — and
//! carry location, OS scope, decoder, and source citation.
//!
//! Zero dependencies. Everything in `const`/`static` memory.
//!
//! # Quick start
//!
//! ```rust
//! use forensicnomicon::catalog::{CATALOG, TriagePriority};
//! use forensicnomicon::evidence::evidence_for;
//! use forensicnomicon::volatility::acquisition_order;
//!
//! // Acquisition order for live response (RFC 3227 — most volatile first)
//! let order = acquisition_order();
//!
//! // What to triage first
//! let critical: Vec<_> = CATALOG.for_triage()
//!     .into_iter()
//!     .filter(|d| d.triage_priority == TriagePriority::Critical)
//!     .collect();
//!
//! // How reliable is this artifact as evidence?
//! let e = evidence_for("userassist_exe").unwrap();
//! // e.strength → EvidenceStrength::Strong
//! // e.caveats  → &["Key can be cleared; absence does not prove non-execution"]
//! ```
//!
//! # Module map
//!
//! ## Artifact catalog
//!
//! - [`catalog`] / [`artifact`] — 6,548-entry descriptor registry with decode,
//!   ATT&CK mapping, triage priority, parsing profiles, and carving signatures.
//!   Start with [`catalog::CATALOG`].
//!
//! ## Enrichments — investigation
//!
//! - [`playbooks`] — six directed investigation paths (lateral movement, credential
//!   harvesting, persistence, exfiltration, execution, defense evasion)
//! - [`evidence`] — evidence strength ratings (`Unreliable` → `Definitive`) with analyst caveats
//! - [`volatility`] — RFC 3227 Order of Volatility; use [`volatility::acquisition_order`]
//! - [`temporal`] — temporal correlation hints for timeline and timestomp detection
//! - [`antiforensics_aware`] — per-artifact anti-forensic tampering risk
//! - [`version_history`] — artifact format and location changes across OS versions
//! - [`dependencies`] — artifact dependency graph; use [`dependencies::full_collection_set`]
//!
//! ## Enrichments — detection
//!
//! - [`mitre`] — MITRE ATT&CK integration: shared [`mitre::AttackTechnique`] type + YARA rule name prefix lookup
//! - [`attack_flow`] — campaign graph layer: 5 pre-built adversary scenarios with artifact evidence mapping
//! - [`sigma`] — Sigma rule references per artifact; [`sigma::sigma_refs_for`]
//! - [`chainsaw`] — Chainsaw / Hayabusa hunt rule references
//! - [`navigator`] — ATT&CK Navigator JSON layer generator
//! - [`yara`] — YARA rule skeleton generator
//! - [`stix`] — STIX 2.1 observable mappings and indicator patterns
//!
//! ## Enrichments — collection toolchain
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
pub mod attack_flow;
pub mod catalog;
pub mod chainsaw;
pub mod dependencies;
pub mod eventids;
pub mod evidence;
pub mod forensicartifacts;
pub mod mitre;
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
pub mod abusable_sites;
pub mod encryption;
pub mod handbook;
pub mod lolbins;
pub mod no_std_compat;
pub mod paths;
pub mod pca;
pub mod persistence;
pub mod ports;
pub mod processes;
pub mod references;
pub mod remote_access;
pub mod third_party;
