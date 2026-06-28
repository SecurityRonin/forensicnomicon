#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)
)]
//! # forensicnomicon-data
//!
//! The fast-moving **detection knowledge** layer of the ForensicNomicon, split out
//! from the stable engine in `forensicnomicon-core` so it can release frequently
//! and independently. It carries the assembled artifact catalog and the lookups
//! built over it:
//!
//! - [`catalog`] — the ~6.5k assembled artifact descriptors and the global
//!   [`catalog::CATALOG`]. The descriptor *types* and the lookup *engine* live in
//!   `forensicnomicon-core`; this crate supplies the data and wires it into a
//!   compile-time `CATALOG` via `ForensicCatalog::new`. The engine surface is
//!   re-exported, so `forensicnomicon_data::catalog::*` mirrors the core API.
//! - [`evidence`] / [`volatility`] — the `EvidenceStrength` / `VolatilityClass`
//!   rating enums (re-exported from core) plus the catalog-querying helpers
//!   (`evidence_for`, `volatility_for`, `acquisition_order`, …).
//!
//! The umbrella `forensicnomicon` crate re-exports this crate, so existing
//! `forensicnomicon::catalog::CATALOG` / `forensicnomicon::evidence::evidence_for`
//! paths resolve unchanged.

pub mod catalog;
pub mod evidence;
pub mod volatility;
