#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)
)]
//! # forensicnomicon-core
//!
//! Stable engine layer of the ForensicNomicon. Houses the slow-moving pieces that
//! downstream analyzers and readers depend on, kept apart from the fast-moving
//! detection knowledge (the ~6.5k artifact descriptors) in the umbrella
//! `forensicnomicon` crate:
//!
//! - [`report`] — the normalized cross-scheme DFIR finding vocabulary
//!   (`Finding`/`Severity`/`Observation`) that every `*-forensic` analyzer emits.
//! - [`catalog`] — the descriptor `types`, the [`catalog::ForensicCatalog`] lookup
//!   engine and its query methods, container/record parsing profiles, and the
//!   in-core decoders. It carries **no** artifact data; the umbrella crate wires
//!   the assembled dataset into a global `CATALOG` via `ForensicCatalog::new`.
//! - [`evidence::EvidenceStrength`] and [`volatility::VolatilityClass`] — the
//!   rating types stored on each descriptor (the catalog-querying helpers live in
//!   the umbrella crate, where the global catalog is wired).
//! - Structural format constants readers depend on: [`decmpfs`], [`filesystems`],
//!   [`partition_schemes`], [`partition_types`].
//!
//! These carry no dependency on the assembled detection catalog, so a knowledge
//! change never forces a republish of crates that only need this engine. The
//! umbrella `forensicnomicon` crate re-exports everything here, so existing imports
//! such as `forensicnomicon::report::Finding` or `forensicnomicon::catalog::CATALOG`
//! continue to resolve unchanged.

pub mod catalog;
pub mod decmpfs;
pub mod evidence;
pub mod file_id;
pub mod filesystems;
pub mod partition_schemes;
pub mod partition_types;
pub mod report;
pub mod usb_vendors;
pub mod volatility;
pub mod volume_encryption;
pub mod volume_serial;

/// Filesystem-object identity, re-exported at the crate root so consumers write
/// `forensicnomicon_core::FileId` (ADR 0009). `forensic-vfs` re-exports this in
/// turn, keeping every existing `forensic_vfs::FileId` import working unchanged.
pub use file_id::FileId;
