# Knowledge beyond artifacts — schema proposal

**Status:** proposal, not implemented. Seeking review before landing.

## The problem

`ArtifactDescriptor` is the only knowledge shape this crate can express. That is
a schema limit, and it has been quietly acting as a scope decision.

Two courseware corpora were distilled recently. Of ~18,500 facts from one, only
**2,670 were artifact-shaped** — the remaining ~15,800 are investigative
technique, tool behaviour, correlation logic and anti-forensics. A coverage audit
against the catalog could only ask artifact-shaped questions, so that knowledge
had nowhere to land and was recorded as "out of scope."

It is not out of scope. The README says **DFIR Knowledge-as-Code**, and the
roadmap already plans the homes: §1.3 Investigation Playbook Engine, §2.3
Temporal Correlation Hints, §2.4 Anti-Forensics Awareness Layer. None is built —
there is no `Playbook`, `Technique` or correlation type anywhere in `crates/`.

Meanwhile the knowledge is already arriving and being wedged into the wrong
field. Research landed in `951a7b0` established that **two XP AppCompatCache
parsers read the live-entry count from the wrong offset, and a third silently
drops `LastUpdateTime`** — a fact about a *tool*, not an artifact, currently
living inside an `evidence_caveats` string because there was nowhere better.

## Design principles

1. **Mirror `ArtifactDescriptor`.** Same `const`-constructible shape, same
   `&'static str` discipline, same cross-reference-by-id, same registration
   pattern. Four sibling types, not one overloaded struct.
2. **Every type carries how it is known.** A new `EvidenceTier` makes the T1/T2/T3
   distinction structural instead of prose. A reader must be able to tell a
   vendor-documented fact from one established by reading two parsers.
3. **The load-bearing field is the negative one.** For each type there is one
   field that carries the real forensic value, and in every case it is about
   failure: what the analyst gets *wrong*, what disagreement *means*, what the
   attacker *failed* to erase.

## Shared: evidence tier

Tonight's research resolved six claims a stricter pass had rejected for not being
vendor-documented. That bar was too narrow — but landing them without recording
*how* they are known would trade one error for a worse one.

```rust
/// How a knowledge claim is established. Ordered weakest-last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceTier {
    /// The vendor or a normative specification documents it.
    VendorDocumented = 2,
    /// Read out of source code, or >= 2 INDEPENDENT implementations agree.
    SourceOrMultiImpl = 1,
    /// A single secondary source. Record as a lead; do not assert.
    SingleSecondary = 0,
}
```

`ArtifactDescriptor` should gain this field too, as a later migration.

## 1. `InvestigativeTechnique` — roadmap §1.3

Answers *"how do I establish X?"* — the ordered pivot, and the conditions under
which it misleads.

```rust
pub struct InvestigativeTechnique {
    pub id: &'static str,
    pub name: &'static str,
    /// The analyst question this answers, in the analyst's words.
    pub question: &'static str,
    pub steps: &'static [TechniqueStep],
    /// Catalog artifact ids this technique consumes.
    pub artifacts_used: &'static [&'static str],
    /// What must already be true or collected. An unmet precondition
    /// silently invalidates the result rather than failing loudly.
    pub preconditions: &'static [&'static str],
    /// Conditions under which this technique yields a CONFIDENT WRONG answer.
    pub failure_modes: &'static [&'static str],
    pub evidence_tier: EvidenceTier,
    pub mitre_techniques: &'static [&'static str],
    pub sources: &'static [&'static str],
}

pub struct TechniqueStep {
    pub order: u8,
    pub action: &'static str,
    pub artifact_id: Option<&'static str>,
    /// What this step yields that the next one consumes.
    pub yields: &'static str,
}
```

**Worked example** — from the 5156 research:

```rust
InvestigativeTechnique {
    id: "establish_audit_subcategory_before_reading_absence",
    name: "Establish an audit subcategory was enabled before reading absence",
    question: "This log has no 5156 events. Does that mean no network connection occurred?",
    steps: &[
        TechniqueStep { order: 1, action: "Read the effective audit policy from the SECURITY hive LSA policy, or auditpol output if live", artifact_id: None, yields: "whether Filtering Platform Connection was enabled at all" },
        TechniqueStep { order: 2, action: "Look for 4719 audit-policy-change events bounding the window", artifact_id: None, yields: "when the subcategory changed state" },
        TechniqueStep { order: 3, action: "Confirm the log did not roll over across the window of interest", artifact_id: None, yields: "whether absence is retention rather than non-generation" },
    ],
    artifacts_used: &["evtx_security"],
    preconditions: &["The SECURITY hive or a live host is available"],
    failure_modes: &[
        "Reading absence as 'no connection occurred'. The subcategory is OFF BY DEFAULT on every Windows role and version, so absence is evidence about audit CONFIGURATION, not about network activity",
        "Reading absence as anti-forensics. The default state produces the same emptiness as deliberate disabling",
    ],
    evidence_tier: EvidenceTier::VendorDocumented,
    mitre_techniques: &["T1562.002"],
    sources: &["https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging"],
}
```

## 2. `ToolBehaviour` — no roadmap entry; already biting

The catalog describes artifacts as they exist on disk. Analysts see them through
tools, and the tool can differ from the artifact. This is the gap that forced a
tool fact into `evidence_caveats`.

```rust
pub struct ToolBehaviour {
    pub id: &'static str,
    pub tool: &'static str,
    /// Versions this applies to, or `None` if unbounded/unknown.
    pub version_range: Option<&'static str>,
    /// The artifact whose reading this affects.
    pub artifact_id: Option<&'static str>,
    pub kind: ToolBehaviourKind,
    pub detail: &'static str,
    /// What the analyst concludes WRONGLY if unaware. This is the field
    /// that earns the type.
    pub consequence: &'static str,
    pub mitigation: &'static str,
    pub evidence_tier: EvidenceTier,
    pub sources: &'static [&'static str],
}

pub enum ToolBehaviourKind {
    /// Parses the artifact but omits a field from output.
    SilentlyDropsField,
    /// Reads a structure at the wrong offset or with wrong semantics.
    MisreadsStructure,
    /// Emits an identifier that looks stable and is not.
    UnstableIdentifier,
    /// Correct only when a non-default flag is passed.
    RequiresFlag,
    /// Summarises output in a way that hides detail.
    OutputHidesDetail,
}
```

**Worked examples** — both established in `951a7b0`:

```rust
ToolBehaviour {
    id: "appcompatcacheparser_drops_xp_lastupdatetime",
    tool: "AppCompatCacheParser",
    version_range: None,
    artifact_id: Some("appcompatcache"),
    kind: ToolBehaviourKind::SilentlyDropsField,
    detail: "On the Windows XP 32-bit format the parser does not emit the second FILETIME at entry offset 544 (LastUpdateTime), which the XP format carries and Server 2003 onward dropped",
    consequence: "An analyst concludes the XP shim cache has no execution-time information, when the one timestamp that tracks use is present in the data and absent only from the output",
    mitigation: "Cross-read with ShimCacheParser or Volatility 2 shimcache, or parse the value directly",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &["https://github.com/mandiant/ShimCacheParser", "https://github.com/EricZimmerman/AppCompatCacheParser"],
}

ToolBehaviour {
    id: "memprocfs_findevil_ordinal_unstable",
    tool: "MemProcFS FindEvil",
    version_range: None,
    artifact_id: Some("mem_findevil"),
    kind: ToolBehaviourKind::UnstableIdentifier,
    detail: "The leading '#' column of findevil.txt is a presentation ordinal printed in base 16 and assigned during the final sorted emit; it renumbers whenever any finding is added or removed",
    consequence: "Citing a finding as '#0042' in a report produces a reference that silently points at a different finding on the next run",
    mitigation: "Cite by PID plus virtual address, not by the ordinal",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &["https://github.com/ufrisk/MemProcFS"],
}
```

## 3. `CorrelationHint` — roadmap §2.3

Two artifacts describing the same event. The catalog has `related_artifacts`
(a bare id list) but cannot say **what their disagreement means** — which is
where the forensic value lives.

```rust
pub struct CorrelationHint {
    pub id: &'static str,
    pub name: &'static str,
    /// Two or more catalog artifact ids.
    pub artifacts: &'static [&'static str],
    pub relation: CorrelationRelation,
    /// What agreement between the sources supports.
    pub agreement_means: &'static str,
    /// What DISAGREEMENT supports. Usually the reason the pair is worth pairing.
    pub divergence_means: &'static str,
    pub evidence_tier: EvidenceTier,
    pub mitre_techniques: &'static [&'static str],
    pub sources: &'static [&'static str],
}

pub enum CorrelationRelation {
    /// One must precede the other; order is itself evidence.
    TemporalOrdering,
    /// Two independent records of one event.
    SameEventTwoSources,
    /// One bounds a gap in the other.
    BoundsGap,
    Corroborates,
    Contradicts,
}
```

**Worked example** — `$SI` vs `$FN`:

```rust
CorrelationHint {
    id: "si_fn_timestamp_divergence",
    name: "$STANDARD_INFORMATION vs $FILE_NAME timestamp divergence",
    artifacts: &["ntfs_timestomping_si_fn"],
    relation: CorrelationRelation::SameEventTwoSources,
    agreement_means: "Both attributes were written by the same ordinary filesystem operation; no evidence of timestamp manipulation from this pair",
    divergence_means: "$SI is writable through documented API (SetFileTime) while $FN is updated by the kernel on rename/move. $SI older than $FN is consistent with timestomping. It is NOT proof: installers, archive extraction and file-copy utilities legitimately set $SI",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    mitre_techniques: &["T1070.006"],
    sources: &["https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime"],
}
```

## 4. `AntiForensicMethod` — roadmap §2.4

The catalog says what an artifact proves when present. It cannot say what an
attacker does to remove it — or, critically, **what that removal fails to erase**.

```rust
pub struct AntiForensicMethod {
    pub id: &'static str,
    pub name: &'static str,
    /// Catalog artifact ids this suppresses or destroys.
    pub suppresses: &'static [&'static str],
    pub method: &'static str,
    /// What the method FAILS to erase. This is the forensic value of the
    /// entry: the artifact that survives the attempt to remove the artifact.
    pub residue: &'static [&'static str],
    pub detection: &'static str,
    pub evidence_tier: EvidenceTier,
    pub mitre_techniques: &'static [&'static str],
    pub sources: &'static [&'static str],
}
```

**Worked example** — Tarrask:

```rust
AntiForensicMethod {
    id: "tarrask_task_hiding_sd_deletion",
    name: "Scheduled task hidden by deleting the TaskCache Tree SD value",
    suppresses: &["taskcache_tasks_path"],
    method: "Deleting the SD (security descriptor) value under the task's TaskCache\\Tree subkey removes the task from schtasks /query and the Task Scheduler MMC while the task continues to run",
    residue: &[
        "The TaskCache\\Tasks GUID subkey and the task's XML under System32\\Tasks are untouched by the SD deletion",
        "Task Scheduler Operational log entries for the task's registration and each execution",
        "An enumeration-based negative is unsound: a task absent from schtasks output is not evidence the task does not exist",
    ],
    detection: "Compare TaskCache\\Tree entries against TaskCache\\Tasks and the System32\\Tasks XML; a Tree entry lacking SD, or a Tasks GUID with no corresponding visible task, is the signal",
    evidence_tier: EvidenceTier::VendorDocumented,
    mitre_techniques: &["T1053.005", "T1562.001"],
    sources: &["https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/"],
}
```

## What this unlocks

The audit that classified ~15,800 facts as out-of-scope can be re-run with four
more questions it is now able to ask. Expected homes, from the two corpora:

| Type | Example content available now |
|---|---|
| `InvestigativeTechnique` | pivot orders, triage sequencing, "establish before concluding" procedures |
| `ToolBehaviour` | parser offset disagreements, silently-dropped fields, unstable identifiers |
| `CorrelationHint` | `$SI`/`$FN`, Prefetch/Amcache/Shimcache triangulation, `$UsnJrnl` bounding an MFT gap |
| `AntiForensicMethod` | Tarrask, SDelete rename ladder, 1102 clearing, USN journal re-stamping |

## Open questions for review

1. **Four types or one with a `kind` discriminator?** Four mirrors the existing
   style and queries better; one is less code. Proposal picks four.
2. **Where do they live?** Suggest `crates/core/src/knowledge/` with per-type
   modules, and data in `crates/data/src/knowledge/`, parallel to `catalog/`.
3. **Should `ArtifactDescriptor` gain `evidence_tier` now or later?** It needs it
   — 6,805 descriptors would default to a tier, which is a large migration.
4. **Does `ToolBehaviour` need a roadmap entry?** It has no §-number but is the
   one already causing harm.
