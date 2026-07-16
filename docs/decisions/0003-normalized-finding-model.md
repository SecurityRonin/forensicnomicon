# 0003 — A normalized Finding/Observation model as the fleet vocabulary

**Status:** Accepted

## Context

The fleet has many `*-forensic` analyzers (registry, NTFS, shimcache, amcache, prefetch,
userassist, …), each surfacing findings from a different artifact. If each invents its own
result shape, a downstream consumer cannot compare, merge, rank, or timeline findings across
analyzers, and every integration is bespoke.

## Decision

Define one normalized finding vocabulary in `forensicnomicon-core::report` that every analyzer
emits:

- `Severity` and `Category` (with `Category::from_code`), a validated `Confidence(f32)`
  newtype, `SubjectRef`, `Evidence`/`Location`, `ExternalRef` (e.g. `ExternalRef::mitre_attack`),
  `Timestamp`/`TimelineEvent`, and `Provenance`.
- A `Finding` assembled through a fluent, misuse-resistant `FindingBuilder`
  (`.note/.source/.evidence/.subject/.mitre/.confidence/.timestamp/.tag/.build`), with
  `Finding::observation(...)` for rated and `Finding::unrated(...)` for unrated findings.
- An **`Observation` trait** analyzers implement to project their domain type into a `Finding`,
  with sensible default hooks (category, subjects, evidence, mitre, confidence).
- A `Report` aggregate with `max_severity()`, `findings_at_least(min)`, `unrated_findings()`.

Evidence: `crates/core/src/report.rs` (`report.rs:8` — "keeps the vocabulary a single source of
truth"; builder, `Observation` trait, `Report`). Lives in the *stable* core (ADR-0002) so the
vocabulary does not churn under analyzers.

## Consequences

- **+** Heterogeneous analyzers produce one comparable output shape — findings merge, rank, and
  timeline across the fleet.
- **+** The `Observation` trait + builder make the common path easy and the wrong shape hard to
  construct; MITRE/evidence/confidence are first-class, not free-text.
- **+** Placing it in core means the model is a deliberate, majors-only contract.
- **−** Adding a field to the model touches the stable core (a considered change), not a data
  bump. Intended: the vocabulary is a contract.
