//! Normalized cross-scheme forensic report vocabulary — the superset model.
//!
//! The shared model the SecurityRonin analyzers (`mbr-forensic`, `gpt-forensic`,
//! `apm-forensic`, `iso9660-forensic`, `vmdk-forensic`, `vhdx-forensic`,
//! `ewf-forensic`, `srum-forensic`, `winevt-forensic`, `usnjrnl-forensic`,
//! `memory-forensic`, `exec-pe-forensic`, …) normalize into, and that the
//! `disk-forensic`/`disk4n6` CLI and the `issen` triage product render. Hosting
//! it here keeps the vocabulary a single source of truth and avoids a dependency
//! cycle: `forensicnomicon` is a leaf, so every analyzer can depend *down* onto
//! it.
//!
//! A [`Finding`] is an **observation with evidence**, never an assertion of
//! intent; the analyst/tribunal draws conclusions. It is the **union (superset)
//! of the analyzers' data, not a flattening**: scheme-specific detail is
//! preserved losslessly as [`Evidence`], non-disk targets as [`SubjectRef`], and
//! behavioral context (MITRE technique refs, confidence, occurrence count,
//! timestamps) as [`FindingContext`].
//!
//! ## Design contract
//!
//! - Analyzers keep their own typed `AnomalyKind` enums (domain knowledge) and
//!   implement [`Observation`] on them; [`Observation::to_finding`] assembles the
//!   canonical [`Finding`]. The shared crate never enumerates every anomaly kind.
//! - [`Finding`] is built through [`Finding::observation`] / [`Finding::unrated`]
//!   and the returned [`FindingBuilder`] — never a struct literal — so adding
//!   fields later is a non-breaking change for the published fleet.
//! - A finding's [`Finding::severity`] is `Option<Severity>`: `None` ("not
//!   scored") is forensically distinct from `Some(Severity::Info)` ("scored,
//!   benign"). Analyzers that cannot grade a finding (e.g. a PE writable+
//!   executable section) emit it unrated rather than inventing a grade.
//! - Stable `code` strings are a published contract: prefix with the scheme
//!   (`VMDK-…`, `GPT-…`) and never change a shipped code.
//! - MITRE / threat refs are **"consistent with"**, never a verdict.

use core::fmt;
use core::num::NonZeroU64;
use std::borrow::Cow;

/// Severity of a forensic finding (`Info` < `Low` < `Medium` < `High` < `Critical`).
#[non_exhaustive]
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
/// severity. Fine-grained threat taxonomy (C2, ransomware, injection) lives in
/// the finding's `code` and MITRE refs, not in new categories.
#[non_exhaustive]
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
    /// Threat — malicious code or behavior (bootkits, rootkits, injection,
    /// C2/beaconing, ransomware indicators).
    Threat,
}

impl Category {
    /// Classify a stable finding `code` into a coarse [`Category`] by keyword.
    ///
    /// A pragmatic, scheme-agnostic default so analyzers need not hand-map every
    /// anomaly variant; an analyzer overrides [`Observation::category`] for the
    /// codes where this heuristic is wrong (e.g. overloaded `BOOT` prefixes).
    #[must_use]
    pub fn from_code(code: &str) -> Category {
        let c = code.to_ascii_uppercase();
        if c.contains("CRC") || c.contains("INTEGRITY") || c.contains("CHECKSUM") || c.contains("HASH") {
            Category::Integrity
        } else if c.contains("OVERLAP")
            || c.contains("OOB")
            || c.contains("BOUND")
            || c.contains("CHS")
            || c.contains("MAP-COUNT")
        {
            Category::Structure
        } else if c.contains("HIDDEN")
            || c.contains("CONCEAL")
            || c.contains("WIPED")
            || c.contains("ERASED")
            || c.contains("SPOOF")
            || c.contains("PROTECTIVE")
        {
            // Checked before Residue so a wiped/erased *gap* reads as anti-forensics,
            // not mere slack.
            Category::Concealment
        } else if c.contains("RESIDUAL")
            || c.contains("SLACK")
            || c.contains("GAP")
            || c.contains("CARVE")
            || c.contains("UNMAPPED")
            || c.contains("ZEROLEN")
        {
            Category::Residue
        } else if c.contains("BOOT") {
            Category::Threat
        } else {
            Category::Structure
        }
    }
}

/// Where a finding's evidence sits on the medium — spanning partition-table
/// (byte/LBA/sector), filesystem (path/field), executable/memory (RVA),
/// record-oriented (event-log/journal/database) and registry positions.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Location {
    /// Absolute byte offset in the image.
    ByteOffset(u64),
    /// Logical block address.
    Lba(u64),
    /// Physical/optical sector index.
    Sector(u64),
    /// Relative virtual address (executable image / memory).
    Rva(u64),
    /// Record identity (event-log record, USN/journal record, database row).
    RecordId(u64),
    /// Path within a filesystem/volume.
    Path(String),
    /// A named structure field (e.g. `volume_space_size`).
    Field(String),
    /// A registry key path.
    Key(String),
    /// Escape hatch: a numeric address in a named space (e.g. `memory:va`).
    /// Prefer a dedicated variant when one fits; this keeps rare cases lossless.
    Other {
        /// Namespaced address space, e.g. `memory:va`.
        space: String,
        /// The numeric value in that space.
        value: u64,
    },
}

/// One piece of evidence backing a finding: a named field, its observed value
/// (rendered as text), and where it was found.
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

/// A non-disk subject a finding is *about* — a process, module, connection,
/// registry key, PE section, etc. Disk findings leave this empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubjectRef {
    /// Namespaced subject scheme, e.g. `memory`, `winevt`, `pe`, `filesystem`.
    pub scheme: String,
    /// Generic type within the scheme, e.g. `process`, `module`, `registry_key`.
    pub kind: String,
    /// Stable identifier in that scheme, e.g. `pid:4242`, `0x401000`.
    pub id: String,
    /// Optional human label, e.g. an image name.
    pub label: Option<String>,
}

/// An external reference a finding is **consistent with** — never a verdict.
/// Most commonly a MITRE ATT&CK technique; also CVEs, vendor docs, case tags.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalRef {
    /// Reference scheme, e.g. `mitre-attack`, `cve`.
    pub scheme: String,
    /// Identifier within the scheme, e.g. `T1003`, `T1055.001`.
    pub id: String,
    /// Optional canonical URL.
    pub url: Option<String>,
}

impl ExternalRef {
    /// A MITRE ATT&CK technique reference (e.g. `"T1003"`).
    #[must_use]
    pub fn mitre_attack(id: impl Into<String>) -> Self {
        Self {
            scheme: "mitre-attack".to_string(),
            id: id.into(),
            url: None,
        }
    }
}

/// A confidence score in `0.0..=1.0`, validated at construction so a producer
/// can never emit `NaN`, a negative, or an out-of-range value.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "f32", into = "f32"))]
pub struct Confidence(f32);

impl Confidence {
    /// Construct a confidence in `0.0..=1.0`; returns `None` for `NaN` or
    /// out-of-range input.
    #[must_use]
    pub fn new(value: f32) -> Option<Self> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Some(Self(value))
        } else {
            None
        }
    }

    /// The score as `f32`.
    #[must_use]
    pub fn get(self) -> f32 {
        self.0
    }
}

impl TryFrom<f32> for Confidence {
    type Error = &'static str;
    fn try_from(value: f32) -> Result<Self, Self::Error> {
        Self::new(value).ok_or("confidence must be finite and within 0.0..=1.0")
    }
}

impl From<Confidence> for f32 {
    fn from(c: Confidence) -> Self {
        c.0
    }
}

/// A timestamp attached to a finding (distinct from the merged super-timeline).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Timestamp {
    /// RFC 3339 when known; analyzer-native string otherwise.
    pub value: String,
    /// What the time means, e.g. `observed`, `created`, `event`, `inferred`.
    pub kind: String,
    /// Where the timestamp was read, if locatable.
    pub location: Option<Location>,
}

/// The analyzer (and the scope within the medium) that produced a finding.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Source {
    /// Analyzer name, e.g. `gpt-forensic`.
    pub analyzer: String,
    /// Scope within the medium, e.g. `partition 1` or `volume: Macintosh HD`.
    pub scope: String,
    /// Analyzer version, for court-grade reproducibility.
    pub version: Option<String>,
}

/// Optional behavioral / aggregation context for a finding. Disk findings leave
/// this at its default; behavioral analyzers (memory, winevt, srum) populate it.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FindingContext {
    /// Heuristic confidence, when the finding is inferential rather than structural.
    pub confidence: Option<Confidence>,
    /// Number of underlying occurrences this finding aggregates (default 1).
    pub occurrences: Option<NonZeroU64>,
    /// Timestamps anchoring the finding in time.
    pub timestamps: Vec<Timestamp>,
    /// External references the finding is consistent with (MITRE ATT&CK, CVE …).
    pub external_refs: Vec<ExternalRef>,
    /// Analyzer-specific labels (filter flags, sub-classifications) without
    /// schema churn.
    pub tags: Vec<Cow<'static, str>>,
}

/// A normalized forensic finding — an observation, never an assertion of intent.
///
/// Construct via [`Finding::observation`] / [`Finding::unrated`]; the type is
/// `#[non_exhaustive]` so adding fields later does not break consumers.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Finding {
    /// Severity, or `None` when the analyzer deliberately did not score it.
    pub severity: Option<Severity>,
    /// Analytical lens.
    pub category: Category,
    /// Stable machine-readable, scheme-prefixed code, e.g. `GPT-PARTITION-OVERLAP`.
    pub code: Cow<'static, str>,
    /// Human-readable observation (consistent-with language, never "proves").
    pub note: String,
    /// Producing analyzer + scope.
    pub source: Source,
    /// Non-disk subjects the finding is about (empty for disk findings).
    pub subjects: Vec<SubjectRef>,
    /// Backing evidence (lossless per-analyzer detail).
    pub evidence: Vec<Evidence>,
    /// Behavioral / aggregation context (default-empty for disk findings).
    pub context: FindingContext,
}

impl Finding {
    /// Begin a rated finding.
    #[must_use]
    pub fn observation(
        severity: Severity,
        category: Category,
        code: impl Into<Cow<'static, str>>,
    ) -> FindingBuilder {
        FindingBuilder::new(Some(severity), category, code.into())
    }

    /// Begin a finding the analyzer deliberately leaves unrated (`severity: None`).
    #[must_use]
    pub fn unrated(category: Category, code: impl Into<Cow<'static, str>>) -> FindingBuilder {
        FindingBuilder::new(None, category, code.into())
    }
}

/// Builder for [`Finding`] — the only supported construction path.
#[derive(Debug, Clone)]
pub struct FindingBuilder {
    finding: Finding,
}

impl FindingBuilder {
    fn new(severity: Option<Severity>, category: Category, code: Cow<'static, str>) -> Self {
        Self {
            finding: Finding {
                severity,
                category,
                code,
                note: String::new(),
                source: Source::default(),
                subjects: Vec::new(),
                evidence: Vec::new(),
                context: FindingContext::default(),
            },
        }
    }

    /// Human-readable observation.
    #[must_use]
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.finding.note = note.into();
        self
    }

    /// The producing analyzer + scope.
    #[must_use]
    pub fn source(mut self, source: Source) -> Self {
        self.finding.source = source;
        self
    }

    /// Add an evidence row without a location.
    #[must_use]
    pub fn evidence(self, field: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence_item(Evidence {
            field: field.into(),
            value: value.into(),
            location: None,
        })
    }

    /// Add an evidence row anchored at a location.
    #[must_use]
    pub fn evidence_at(
        self,
        field: impl Into<String>,
        value: impl Into<String>,
        location: Location,
    ) -> Self {
        self.evidence_item(Evidence {
            field: field.into(),
            value: value.into(),
            location: Some(location),
        })
    }

    /// Add a fully-formed evidence row.
    #[must_use]
    pub fn evidence_item(mut self, evidence: Evidence) -> Self {
        self.finding.evidence.push(evidence);
        self
    }

    /// Add a non-disk subject the finding is about.
    #[must_use]
    pub fn subject(mut self, subject: SubjectRef) -> Self {
        self.finding.subjects.push(subject);
        self
    }

    /// Add a MITRE ATT&CK technique the finding is consistent with.
    #[must_use]
    pub fn mitre(self, technique: impl Into<String>) -> Self {
        self.external_ref(ExternalRef::mitre_attack(technique))
    }

    /// Add an external reference (MITRE, CVE, vendor doc, case tag).
    #[must_use]
    pub fn external_ref(mut self, reference: ExternalRef) -> Self {
        self.finding.context.external_refs.push(reference);
        self
    }

    /// Attach a heuristic confidence.
    #[must_use]
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.finding.context.confidence = Some(confidence);
        self
    }

    /// Set the number of occurrences this finding aggregates (`0` clears it).
    #[must_use]
    pub fn occurrences(mut self, count: u64) -> Self {
        self.finding.context.occurrences = NonZeroU64::new(count);
        self
    }

    /// Anchor the finding in time.
    #[must_use]
    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.finding.context.timestamps.push(timestamp);
        self
    }

    /// Add an analyzer-specific tag.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<Cow<'static, str>>) -> Self {
        self.finding.context.tags.push(tag.into());
        self
    }

    /// Finish building.
    #[must_use]
    pub fn build(self) -> Finding {
        self.finding
    }
}

/// The producer trait analyzers implement on their own typed anomaly kind.
///
/// Only `severity`, `category`, `code`, and `note` are required; the rest carry
/// behavioral detail and default to empty. [`Observation::to_finding`] assembles
/// the canonical [`Finding`] so the construction logic lives in one place.
pub trait Observation {
    /// Severity, or `None` if the analyzer deliberately does not grade this kind.
    fn severity(&self) -> Option<Severity>;
    /// Stable, scheme-prefixed machine code.
    fn code(&self) -> &'static str;
    /// Human-readable, consistent-with note.
    fn note(&self) -> String;

    /// Analytical lens; defaults to [`Category::from_code`] of [`Observation::code`].
    /// Override when a code's keyword classification is wrong.
    fn category(&self) -> Category {
        Category::from_code(self.code())
    }

    /// Non-disk subjects this kind is about (default: none).
    fn subjects(&self) -> Vec<SubjectRef> {
        Vec::new()
    }
    /// Backing evidence rows (default: none).
    fn evidence(&self) -> Vec<Evidence> {
        Vec::new()
    }
    /// MITRE ATT&CK technique ids this kind is consistent with (default: none).
    fn mitre(&self) -> &'static [&'static str] {
        &[]
    }
    /// Heuristic confidence, if inferential (default: none).
    fn confidence(&self) -> Option<Confidence> {
        None
    }

    /// Assemble the canonical [`Finding`] from this kind and its producing source.
    fn to_finding(&self, source: Source) -> Finding {
        let mut builder = match self.severity() {
            Some(sev) => Finding::observation(sev, self.category(), self.code()),
            None => Finding::unrated(self.category(), self.code()),
        }
        .note(self.note())
        .source(source);

        for subject in self.subjects() {
            builder = builder.subject(subject);
        }
        for evidence in self.evidence() {
            builder = builder.evidence_item(evidence);
        }
        for technique in self.mitre() {
            builder = builder.mitre(*technique);
        }
        if let Some(confidence) = self.confidence() {
            builder = builder.confidence(confidence);
        }
        builder.build()
    }
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
/// timeline, provenance breadcrumbs, and report-level metadata.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Report {
    /// All findings, normalized across analyzers.
    pub findings: Vec<Finding>,
    /// Provenance breadcrumbs (attribution).
    pub provenance: Vec<Provenance>,
    /// Merged super-timeline.
    pub timeline: Vec<TimelineEvent>,
    /// Report-level metadata (tool versions, case identifiers, …).
    pub metadata: Vec<Evidence>,
}

impl Report {
    /// The highest *rated* severity among all findings, or `None` when clean or
    /// entirely unrated.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().filter_map(|f| f.severity).max()
    }

    /// Findings rated at least `min` (unrated findings are excluded).
    pub fn findings_at_least(&self, min: Severity) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(move |f| f.severity.is_some_and(|s| s >= min))
    }

    /// Findings the analyzer deliberately left unrated (`severity: None`).
    pub fn unrated_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.severity.is_none())
    }
}
