#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)
)]
//! # forensicnomicon-core
//!
//! Stable engine layer of the ForensicNomicon. Houses the slow-moving pieces that
//! downstream analyzers and readers depend on, kept apart from the fast-moving
//! detection knowledge in the `forensicnomicon` data crate:
//!
//! - [`report`] — the normalized cross-scheme DFIR finding vocabulary
//!   (`Finding`/`Severity`/`Observation`) that every `*-forensic` analyzer emits.
//! - Structural format constants readers depend on: [`decmpfs`], [`filesystems`],
//!   [`partition_schemes`], [`partition_types`].
//!
//! These carry no dependency on the detection catalog, so a knowledge change never
//! forces a republish of crates that only need this engine. The umbrella
//! `forensicnomicon` crate re-exports everything here, so existing imports such as
//! `forensicnomicon::report::Finding` continue to resolve unchanged.

pub mod decmpfs;
pub mod filesystems;
pub mod partition_schemes;
pub mod partition_types;
pub mod report;
