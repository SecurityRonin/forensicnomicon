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
    /// A single secondary source (one blog, one forum post). Record as a lead;
    /// do not assert it as established.
    SingleSecondary = 0,
    /// Read out of source code, or corroborated by two or more INDEPENDENT
    /// implementations or captures that agree. Three articles copying one
    /// original are one source, not three.
    SourceOrMultiImpl = 1,
    /// The vendor or a normative specification documents it.
    VendorDocumented = 2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering_is_consistent() {
        assert!(EvidenceTier::VendorDocumented > EvidenceTier::SourceOrMultiImpl);
        assert!(EvidenceTier::SourceOrMultiImpl > EvidenceTier::SingleSecondary);
    }

    #[test]
    fn strength_ordering_is_consistent() {
        assert!(EvidenceStrength::Definitive > EvidenceStrength::Strong);
        assert!(EvidenceStrength::Strong > EvidenceStrength::Corroborative);
        assert!(EvidenceStrength::Corroborative > EvidenceStrength::Circumstantial);
        assert!(EvidenceStrength::Circumstantial > EvidenceStrength::Unreliable);
    }
}
