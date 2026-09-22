//! Evidence strength / confidence model for forensic artifacts.
//!
//! Two orthogonal axes, deliberately separate:
//!
//! - [`EvidenceStrength`] — how strongly the artifact proves a fact *about the
//!   case*, stored on [`crate::catalog::ArtifactDescriptor::evidence_strength`].
//! - [`EvidenceTier`] — how strongly *we* know the catalog's own claim about
//!   that artifact is true, stored on
//!   [`crate::catalog::ArtifactDescriptor::evidence_tier`].
//!
//! A `Definitive` artifact can rest on a `SourceOrMultiImpl` claim: the
//! artifact proves execution, while our knowledge of its layout comes from
//! reading two parsers rather than from a vendor specification. Collapsing the
//! two axes would hide exactly that.
//!
//! The catalog-querying helpers (`evidence_for`, `artifacts_with_strength`)
//! live in the umbrella `forensicnomicon` crate, where the assembled global
//! catalog is wired.

/// How strongly an artifact proves a fact in isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EvidenceStrength {
    /// Known false-positive generator; use only with strong corroboration.
    Unreliable = 0,
    /// Suggestive but easily explained by benign activity.
    Circumstantial = 1,
    /// Useful with other evidence; not standalone proof.
    Corroborative = 2,
    /// Strong evidence; edge-case alternative explanations exist.
    Strong = 3,
    /// Definitive proof of the claimed activity (e.g., Prefetch = execution occurred).
    Definitive = 4,
}

/// How a catalog claim itself is established — the provenance of the knowledge,
/// not the probative weight of the artifact.
///
/// A public knowledge base must let a reader tell a vendor-documented fact from
/// one recovered by reading source code. Both can be true; they are not equally
/// checkable, and presenting the second as the first is the failure this type
/// exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EvidenceTier {
    /// Looked for, and NOT found. A claim worth recording whose primary source
    /// could not be located — the search happened and came back empty.
    ///
    /// This is deliberately not an absence. Dropping such a claim makes it
    /// indistinguishable from one nobody ever investigated, so the next reader
    /// repeats the same failed search and drops it again; "no primary source
    /// documents this" is itself a finding, and an expensive one to establish.
    ///
    /// An entry at this tier MUST record where it was looked for, so the next
    /// person can search somewhere new rather than somewhere already exhausted.
    /// It is a research lead, never something to act on in casework.
    SearchedNotFound = 0,
    /// A single secondary source (one blog, one forum post). Record as a lead;
    /// do not assert it as established.
    SingleSecondary = 1,
    /// Read out of source code, or corroborated by two or more INDEPENDENT
    /// implementations or captures that agree. Three articles copying one
    /// original are one source, not three.
    SourceOrMultiImpl = 2,
    /// The vendor or a normative specification documents it.
    VendorDocumented = 3,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering_is_consistent() {
        assert!(EvidenceTier::VendorDocumented > EvidenceTier::SourceOrMultiImpl);
        assert!(EvidenceTier::SourceOrMultiImpl > EvidenceTier::SingleSecondary);
        assert!(EvidenceTier::SingleSecondary > EvidenceTier::SearchedNotFound);
    }

    /// A claim we looked for and could NOT source must still be recordable.
    ///
    /// Without this tier the only choices are to assert an unverifiable claim
    /// or to drop it, and dropping destroys real work: a dropped lead is
    /// indistinguishable from a lead nobody ever had, so the next reader runs
    /// the same search, hits the same dead end, and drops it again. "No primary
    /// source documents this" is itself a finding, and an expensive one.
    ///
    /// It is the WEAKEST tier rather than an absence, because the search
    /// happened - that is exactly what distinguishes it from silence.
    #[test]
    fn a_searched_but_unsourced_claim_is_the_weakest_tier_not_an_absence() {
        assert!(EvidenceTier::SearchedNotFound < EvidenceTier::SingleSecondary);
        assert!(EvidenceTier::SearchedNotFound < EvidenceTier::VendorDocumented);
    }

    #[test]
    fn strength_ordering_is_consistent() {
        assert!(EvidenceStrength::Definitive > EvidenceStrength::Strong);
        assert!(EvidenceStrength::Strong > EvidenceStrength::Corroborative);
        assert!(EvidenceStrength::Corroborative > EvidenceStrength::Circumstantial);
        assert!(EvidenceStrength::Circumstantial > EvidenceStrength::Unreliable);
    }
}
