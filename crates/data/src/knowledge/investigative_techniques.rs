//! Static [`InvestigativeTechnique`] instances and the
//! [`INVESTIGATIVE_TECHNIQUES`] slice.
//!
//! Each entry records an analytic framework as its ORIGINAL publication
//! states it — including the original's own scope and limits, which the
//! popular retellings routinely drop. A framework taught without its boundary
//! conditions becomes folklore: the ordering, the bands, or the axioms get
//! repeated with more confidence than the author ever claimed. The
//! `failure_modes` field is where each framework's own stated limits live,
//! because that is where the schema puts "conditions under which this yields
//! a confident wrong answer".
//!
//! Every entry cites the original published work (author, year in the doc
//! comment; durable link in `sources`) — never a training course or a
//! third-party retelling. `evidence_tier` grades how the entry's description
//! is established, and it is set honestly: a widely-repeated model that was
//! never empirically evaluated is recorded as such, not inflated because the
//! paper is famous.

#[allow(unused_imports)]
use super::{InvestigativeTechnique, TechniqueStep};
#[allow(unused_imports)]
use forensicnomicon_core::evidence::EvidenceTier;

/// Every registered investigative technique. Lookup and iteration read this
/// slice; a static not referenced here is invisible to every consumer.
pub static INVESTIGATIVE_TECHNIQUES: &[InvestigativeTechnique] = &[];
