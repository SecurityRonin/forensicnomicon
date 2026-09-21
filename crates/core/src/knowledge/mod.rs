//! DFIR knowledge that is not artifact-shaped.
//!
//! [`crate::catalog::ArtifactDescriptor`] answers *"what is this artifact and
//! what does it prove?"*. It cannot answer four other questions an examiner
//! asks constantly, and for a long time that schema limit acted as a scope
//! decision — knowledge that did not fit was recorded as out of scope rather
//! than as unrepresentable.
//!
//! | Type | Question |
//! |---|---|
//! | [`InvestigativeTechnique`] | How do I establish X, and when does that mislead? |
//! | [`ToolBehaviour`] | Does my tool show me the artifact as it really is? |
//! | [`CorrelationHint`] | These two sources disagree — what does that mean? |
//! | [`AntiForensicMethod`] | What was done to remove this, and what survived? |
//!
//! **In each type the load-bearing field is the negative one.** Not what the
//! artifact shows, but what the tool hides ([`ToolBehaviour::consequence`]),
//! what the mismatch reveals ([`CorrelationHint::divergence_means`]), what
//! survives the wipe ([`AntiForensicMethod::residue`]), and where the procedure
//! yields a confident wrong answer ([`InvestigativeTechnique::failure_modes`]).
//! Those are the facts that had nowhere to live.
//!
//! All four mirror `ArtifactDescriptor`: `const`-constructible so they live in
//! `static`s, cross-referenced to artifacts by id, and each carrying an
//! [`crate::evidence::EvidenceTier`] so a reader can tell a vendor-documented
//! claim from one recovered by reading source.
//!
//! Kept in one module while the data volume is small; split per-type when it
//! grows, as `catalog/` did.

use crate::evidence::EvidenceTier;

// ── Investigative technique ──────────────────────────────────────────────────

/// One step in an [`InvestigativeTechnique`].
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TechniqueStep {
    /// 1-based position in the sequence.
    pub order: u8,
    /// What the examiner does.
    pub action: &'static str,
    /// Catalog artifact this step reads, if any.
    pub artifact_id: Option<&'static str>,
    /// What this step yields that the next one consumes.
    pub yields: &'static str,
}

/// An ordered procedure for establishing a fact, and the conditions under which
/// it misleads.
///
/// Roadmap §1.3 (Investigation Playbook Engine).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvestigativeTechnique {
    /// Short machine-readable identifier.
    pub id: &'static str,
    /// Human-readable display name.
    pub name: &'static str,
    /// The question this answers, phrased as an examiner would ask it.
    pub question: &'static str,
    /// The ordered procedure.
    pub steps: &'static [TechniqueStep],
    /// Catalog artifact ids this technique consumes.
    pub artifacts_used: &'static [&'static str],
    /// What must already hold. An unmet precondition invalidates the result
    /// silently rather than failing loudly, which is why these are listed
    /// separately from the steps.
    pub preconditions: &'static [&'static str],
    /// Conditions under which this technique yields a CONFIDENT WRONG answer.
    /// A technique that merely fails is safe; one that succeeds incorrectly is
    /// not, and those cases belong here.
    pub failure_modes: &'static [&'static str],
    /// How this technique's own description is established.
    pub evidence_tier: EvidenceTier,
    /// MITRE ATT&CK technique IDs this helps investigate.
    pub mitre_techniques: &'static [&'static str],
    /// Authoritative references.
    pub sources: &'static [&'static str],
}

// ── Tool behaviour ───────────────────────────────────────────────────────────

/// The way a tool's output departs from the artifact it parses.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolBehaviourKind {
    /// Parses the artifact but omits a field from its output.
    SilentlyDropsField,
    /// Reads a structure at the wrong offset, or with the wrong semantics.
    MisreadsStructure,
    /// Emits an identifier that looks stable across runs and is not.
    UnstableIdentifier,
    /// Correct only when a non-default flag is supplied.
    RequiresFlag,
    /// Summarises or truncates in a way that hides detail the examiner needs.
    OutputHidesDetail,
    /// Returns fewer records than the evidence contains, with no error — an
    /// incomplete listing indistinguishable from a complete one. The most
    /// dangerous kind: a missed artifact reads as an absent artifact.
    SilentlyIncomplete,
    /// Routinely flags benign data as suspicious. The inverse of
    /// [`Self::SilentlyIncomplete`]: a hit is a lead to corroborate, never a
    /// finding on its own.
    FalsePositiveProne,
}

/// A documented divergence between an artifact and how a tool presents it.
///
/// The catalog describes artifacts as they exist on disk; examiners see them
/// through tools. Where the two differ, the difference is itself forensic
/// knowledge — and it has no home on an artifact descriptor.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolBehaviour {
    /// Short machine-readable identifier.
    pub id: &'static str,
    /// Tool name as its authors write it.
    pub tool: &'static str,
    /// Versions affected, or `None` if unbounded or not established.
    pub version_range: Option<&'static str>,
    /// Catalog artifact whose reading this affects.
    pub artifact_id: Option<&'static str>,
    /// How the output departs from the artifact.
    pub kind: ToolBehaviourKind,
    /// What the tool does, precisely enough to verify.
    pub detail: &'static str,
    /// What an examiner concludes WRONGLY if unaware. This field is why the
    /// type exists: a tool quirk with no wrong conclusion attached is trivia.
    pub consequence: &'static str,
    /// What to do instead.
    pub mitigation: &'static str,
    /// How this behaviour is established.
    pub evidence_tier: EvidenceTier,
    /// Authoritative references, ideally the tool's own source.
    pub sources: &'static [&'static str],
}

// ── Correlation ──────────────────────────────────────────────────────────────

/// How two or more artifacts relate in a [`CorrelationHint`].
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationRelation {
    /// One must precede the other; the ordering is itself evidence.
    TemporalOrdering,
    /// Two independent records of a single event.
    SameEventTwoSources,
    /// One source bounds a gap in the other.
    BoundsGap,
    /// Presence of one raises confidence in the other.
    Corroborates,
    /// Presence of one lowers confidence in the other.
    Contradicts,
}

/// What it means when two sources describing the same activity agree — and,
/// more usefully, when they do not.
///
/// `ArtifactDescriptor::related_artifacts` is a bare id list: it can say two
/// artifacts are related but not what their disagreement implies, which is
/// where the forensic value usually sits.
///
/// Roadmap §2.3 (Temporal Correlation Hints).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorrelationHint {
    /// Short machine-readable identifier.
    pub id: &'static str,
    /// Human-readable display name.
    pub name: &'static str,
    /// Two or more catalog artifact ids.
    pub artifacts: &'static [&'static str],
    /// The nature of the relationship.
    pub relation: CorrelationRelation,
    /// What agreement between the sources supports.
    pub agreement_means: &'static str,
    /// What DISAGREEMENT supports — usually the reason the pair is worth
    /// pairing at all.
    pub divergence_means: &'static str,
    /// How this correlation is established.
    pub evidence_tier: EvidenceTier,
    /// MITRE ATT&CK technique IDs this helps detect.
    pub mitre_techniques: &'static [&'static str],
    /// Authoritative references.
    pub sources: &'static [&'static str],
}

// ── Anti-forensics ───────────────────────────────────────────────────────────

/// A method for suppressing or destroying an artifact, and what it fails to
/// remove.
///
/// Roadmap §2.4 (Anti-Forensics Awareness Layer).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiForensicMethod {
    /// Short machine-readable identifier.
    pub id: &'static str,
    /// Human-readable display name.
    pub name: &'static str,
    /// Catalog artifact ids this suppresses or destroys.
    pub suppresses: &'static [&'static str],
    /// How it works, precisely enough to reason about what it touches.
    pub method: &'static str,
    /// What the method FAILS to erase. This is the entry's forensic value: the
    /// evidence that survives the attempt to remove the evidence. An entry with
    /// an empty `residue` is telling the examiner the artifact is genuinely
    /// gone, which is itself worth stating explicitly.
    pub residue: &'static [&'static str],
    /// How to detect that the method was used.
    pub detection: &'static str,
    /// How this method's description is established.
    pub evidence_tier: EvidenceTier,
    /// MITRE ATT&CK technique IDs.
    pub mitre_techniques: &'static [&'static str],
    /// Authoritative references.
    pub sources: &'static [&'static str],
}
