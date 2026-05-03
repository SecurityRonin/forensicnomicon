# PLAN.md — forensicnomicon Implementation Roadmap

Concrete decisions, prerequisites, and implementation steps for planned work.
For principles and standards, see [CLAUDE.md](CLAUDE.md).

---

## Deferred Refactor: Merge `ArtifactProfile` into `ArtifactDescriptor`

**Decision:** Combine them — but only after the 6,193 generated entries have meaningful defaults.

**Why they should be combined:**
- `ArtifactProfile.id` is a `&'static str` FK into `CATALOG` enforced only by tests, not the type system — a design smell
- Every artifact has exactly one evidence strength and one volatility class; no many-to-one relationship justifies a separate table
- The split API is worse: `evidence_for("mft")` vs `descriptor.evidence_strength`

**Why they are separate right now:**
- Only 361/6,554 entries have profiles; the 6,193 generated entries have no evidence-strength judgment yet — they would all be `None`, making the incompleteness visible but awkward
- `ArtifactProfile` was added after the catalog was built; touching 6,554 entries was deferred

**Prerequisite before merging:** Assign at least a meaningful default to every generated entry — `EvidenceStrength::Circumstantial` and `VolatilityClass::SystemConfig` are reasonable placeholders for unanalyzed artifacts. Until then the separate array is the honest representation of "cataloged but not assessed."

**Refactor steps when ready (strict TDD):**
1. Add `evidence_strength: Option<EvidenceStrength>` and `volatility: Option<VolatilityClass>` to `ArtifactDescriptor`
2. Fill in the 361 hand-curated values inline in their descriptors
3. Delete `ArtifactProfile` struct, `ARTIFACT_PROFILES` static, and `src/profile.rs`
4. Make `evidence_for()` and `volatility_for()` thin wrappers over `CATALOG.get(id)`
5. Update all callers in `navigator.rs`, `4n6query/main.rs`, tests

---
