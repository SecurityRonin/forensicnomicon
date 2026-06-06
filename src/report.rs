//! Normalized cross-scheme forensic report vocabulary.
//!
//! The shared model the SecurityRonin disk/filesystem analyzers
//! (`mbr-forensic`, `gpt-forensic`, `apm-forensic`, `iso9660-forensic`, …)
//! normalize into, and that the `disk-forensic`/`disk4n6` CLI and the `issen`
//! triage product render. Hosting it here keeps the vocabulary a single source
//! of truth — today each analyzer copy-pastes its own `Severity`/`Anomaly` — and
//! avoids a dependency cycle: `forensicnomicon` is a leaf, so every analyzer,
//! `disk-forensic`, and `issen` can depend *down* onto it.
//!
//! A [`Finding`] is an **observation with evidence**, never an assertion of
//! intent; the analyst/tribunal draws conclusions. Scheme-specific detail is
//! preserved losslessly as typed [`Evidence`] key/value/location triples, so the
//! model is the union (superset) of the analyzers' data, not a flattening.

use core::fmt;

/// Severity of a forensic finding (`Info` < `Low` < `Medium` < `High` < `Critical`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Severity {
    /// Informational — provenance/context, not suspicious on its own.
    Info,
    /// Low — minor irregularity with a common benign explanation.
    Low,
    /// Medium — notable irregularity worth examiner attention.
    Medium,
    /// High — strong indicator of tampering or concealment.
    High,
    /// Critical — structural contradiction; the medium cannot be trusted as-is.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        })
    }
}

/// The forensic lens a finding belongs to — the analytical category, not a
/// severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Category {
    /// Integrity / authenticity (CRC, checksum, image completeness).
    Integrity,
    /// Structural contradiction (overlap, out-of-bounds, internal mismatch).
    Structure,
    /// Residue / recoverability (deleted entries, slack, hidden data).
    Residue,
    /// Provenance / attribution (tool, OS, era, vendor fingerprints).
    Provenance,
    /// History (resize, move, clone, format — the medium's biography).
    History,
    /// Concealment / anti-forensics (hidden flags, wiping, misdirection).
    Concealment,
    /// Threat (bootkits / boot-sector malware).
    Threat,
}

/// Where a finding's evidence sits on the medium — spanning partition-table
/// (byte/LBA/sector) and filesystem (path/field) analyzers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Location {
    /// Absolute byte offset in the image.
    ByteOffset(u64),
    /// Logical block address.
    Lba(u64),
    /// Physical/optical sector index.
    Sector(u64),
    /// Path within a filesystem/volume.
    Path(String),
    /// A named structure field (e.g. `volume_space_size`).
    Field(String),
}

/// One piece of evidence backing a finding: a named field, its observed value,
/// and where it was found. Capturing per-analyzer detail this way keeps the
/// normalized model lossless without depending on the analyzer crates.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Evidence {
    /// Field / observation name.
    pub field: String,
    /// Observed value, rendered as text.
    pub value: String,
    /// Where it was observed, if locatable.
    pub location: Option<Location>,
}

/// The analyzer (and the scope within the medium) that produced a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Source {
    /// Analyzer name, e.g. `gpt-forensic`.
    pub analyzer: String,
    /// Scope within the medium, e.g. `partition 1` or `volume: Macintosh HD`.
    pub scope: String,
}

/// A normalized forensic finding — an observation, never an assertion of intent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Finding {
    /// Severity of the observation.
    pub severity: Severity,
    /// Analytical lens.
    pub category: Category,
    /// Stable machine-readable code, e.g. `GPT-PARTITION-OVERLAP`.
    pub code: String,
    /// Human-readable observation (consistent-with language, never "proves").
    pub note: String,
    /// Producing analyzer + scope.
    pub source: Source,
    /// Backing evidence (lossless per-analyzer detail).
    pub evidence: Vec<Evidence>,
}

/// One event in the merged super-timeline reconstructed across analyzers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimelineEvent {
    /// When it happened (`YYYY[-MM[-DD …]]`), if datable.
    pub when: Option<String>,
    /// Analyzer that inferred the event.
    pub source: String,
    /// What was observed/inferred.
    pub event: String,
}

/// A provenance breadcrumb — a tool/OS/era/vendor fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Provenance {
    /// What the breadcrumb identifies (e.g. `alignment`, `bootloader`).
    pub label: String,
    /// The observed value / inference.
    pub value: String,
    /// Analyzer that observed it.
    pub source: String,
}

/// The aggregate normalized report: every analyzer's findings, the merged
/// timeline, and provenance breadcrumbs, in one renderable model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Report {
    /// All findings, normalized across analyzers.
    pub findings: Vec<Finding>,
    /// Provenance breadcrumbs (attribution).
    pub provenance: Vec<Provenance>,
    /// Merged super-timeline.
    pub timeline: Vec<TimelineEvent>,
}

impl Report {
    /// The highest severity among all findings, or `None` when clean.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}
