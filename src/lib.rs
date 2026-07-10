#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)
)]
//! forensicnomicon — the comprehensive DFIR artifact catalog.
//!
//! **See also:**
//! [Architecture & knowledge schema](../architecture.html) |
//! [Search widget](../search.html) |
//! [Source on GitHub](https://github.com/SecurityRonin/forensicnomicon)
//!
//! **6,548 forensic artifacts**, each enriched beyond just a path.
//! Other registries tell you where an artifact lives. forensicnomicon tells
//! you what it means, how to decode it, how reliable it is as evidence,
//! when to acquire it, what else to collect alongside it, and which detection
//! rules apply — all compiled into your binary at zero runtime cost.
//!
//! 415 entries are fully curated with evidence strength, volatility, and caveats.
//! The remaining 6,133 are generated from seven authoritative corpora — KAPE targets (2,422),
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
//! - [`cadet`] — **CADET** (Categories of Activity in Digital Evidence Taxonomy):
//!   the forensic-semantic axis ([`cadet::ActivityCategory`]) — *what evidence
//!   means* across sources, with stable `code()` + ATT&CK-tactic alignment
//! - [`playbooks`] — `INVESTIGATION_PATHS` (6 ATT&CK-tactic artifact chains) +
//!   `PLAYBOOKS` (5 scenario checklists: ransomware, data_breach, bec, insider, supply_chain)
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
//! - [`services`] — known-good Windows service-baseline catalogs: standalone
//!   OwnProcess service exes (`is_known_service_binary`) and svchost-hosted
//!   `ServiceDll`s (`is_known_service_dll`) for service-masquerade leads (T1543.003)
//! - [`drivers`] — LOLDrivers BYOVD *denylist* (`is_known_vulnerable_driver`):
//!   known-vulnerable/malicious driver `.sys` basenames — the inverse of the
//!   service allowlists, presence is the lead (T1543.003 / T1068)
//! - [`commands`] — log-wipe commands, rootkit names
//! - [`paths`] — suspicious staging and hijack paths
//! - [`antiforensics`] — anti-forensic tool indicators
//! - [`encryption`] — encryption tool paths
//! - [`remote_access`] — LOLRMM / RMM tool indicators
//! - [`third_party`] — PuTTY, WinSCP, cloud sync, browser registry artifacts
//! - [`pca`] — Windows 11 Program Compatibility Assistant artifacts
//! - [`peripheral`] — external-device bus taxonomy (DMA / mass-storage class, MITRE)
//! - [`shlink`] — Shell Link (`.LNK`) `[MS-SHLLINK]` format constants
//! - [`jumplist`] — Jump List (`*.automaticDestinations-ms` / `*.customDestinations-ms`)
//!   DestList / CustomDestinations offset tables + AppID map
//! - [`shellbags`] — `BagMRU` PIDL / shell-item class-type knowledge
//! - [`shell_history`] — bash/zsh/fish/PSReadLine format facts + tampering indicators
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

pub mod aff4;
pub mod antiforensics;
pub mod antiforensics_aware;
pub mod apm;
pub mod appcompatcache;
pub mod attack_events;
pub mod attack_flow;
pub mod beaconing;
pub mod boot_signatures;
pub mod bootkit;
pub mod cadet;
pub mod cloud_ranges;
pub mod temporal_formats;
pub mod timestamp_artifacts;
pub use forensicnomicon_data::catalog;
pub mod chainsaw;
pub use forensicnomicon_core::decmpfs;
pub mod dependencies;
pub mod dmg;
pub mod dpapi;
pub mod drivers;
pub mod eventids;
pub use forensicnomicon_data::evidence;
pub mod eol_os;
pub mod evtx;
pub mod ewf;
pub use forensicnomicon_core::filesystems;
pub mod forensicartifacts;
pub mod gpt;
pub mod history;
pub mod mitre;
pub mod navigator;
pub mod ntfs;
pub mod obf;
pub mod olecf;
pub use forensicnomicon_core::partition_schemes;
pub use forensicnomicon_core::partition_types;
pub mod playbooks;
pub mod plugin;
pub mod process_lifetime;
pub mod qcow2;
pub use forensicnomicon_core::report;
pub mod sigma;
pub mod sqlite;
pub mod srum;
pub mod stix;
pub mod temporal;
pub mod timelining;
pub mod toolchain;
pub mod version_history;
pub mod vhd;
pub mod vhdx;
pub mod vmdk;
pub use forensicnomicon_data::volatility;
pub mod yara;
pub use forensicnomicon_data::catalog as artifact;
pub mod abusable_sites;
pub mod commands;
pub mod encryption;
pub mod handbook;
pub mod lolbins;
pub use lolbins::{
    lolbas_entry, lolbas_names, LolbasEntry, UC_ARCHIVE, UC_BYPASS, UC_CREDENTIALS, UC_DECODE,
    UC_DEFENSE_EVASION, UC_DOWNLOAD, UC_EXECUTE, UC_NETWORK, UC_PERSIST, UC_PROXY, UC_RECON,
    UC_UPLOAD,
};
pub mod heuristics;
pub mod journald;
pub mod jumplist;
pub mod no_std_compat;
pub mod paths;
pub mod pca;
pub mod peripheral;
pub mod persistence;
pub mod ports;
pub mod processes;
pub mod references;
pub mod remote_access;
pub mod rootkit;
pub mod services;
pub mod shell_history;
pub mod shellbags;
pub mod shlink;
pub mod third_party;
pub mod threat_intel;
