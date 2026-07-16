# 0002 — Three-layer crate split: stable core / fast data / facade

**Status:** Accepted

## Context

Two forces pull in opposite directions. DFIR *knowledge* must move fast — new artifacts,
drivers, and techniques land constantly, and a slow release cadence makes the tool stale. But
the *API* that downstream `*-forensic` analyzers and `forensic-vfs` depend on must be stable —
they pin a version and expect it not to churn. A single crate cannot be both fast-moving and
stable.

## Decision

Split into three published crates by rate-of-change:

- **`forensicnomicon-core`** — the stable engine: the `report` finding model and the catalog
  *query* engine over `&'static` data, plus structural format constants. Carries **no artifact
  data**. Downstream analyzers pin `forensicnomicon-core = "1"` and treat major bumps as
  deliberate events. `no_std`-capable, zero runtime deps (optional `serde`).
- **`forensicnomicon-data`** — the fast-moving knowledge: the assembled artifact catalog that
  supplies the `&'static [ArtifactDescriptor]` slice and wires the global catalog. Evolves
  additively (minor bumps).
- **`forensicnomicon`** (facade) — re-exports core + data so the paths
  `forensicnomicon::report::Finding` / `forensicnomicon::catalog::CATALOG` never change, and
  adds the detection/heuristic knowledge modules. One import for consumers who want everything.

Evidence: `crates/core/src/lib.rs` and `crates/data/src/lib.rs` module docs; workspace member
comments in `Cargo.toml`; the split rationale in
`docs/plans/2026-06-28-knowledge-propagation-and-crate-split.md`; a `public-api.yml` CI gate on
the core surface.

## Consequences

- **+** Knowledge ships fast (data minor bumps) without moving the stable API.
- **+** Analyzers depend on a small, zero-dep, `no_std`-capable engine — cheap to embed,
  slow to break. `forensic-vfs`, a foundational leaf, can depend on core without pulling the
  full tree.
- **+** Re-export via the facade keeps import paths stable regardless of which layer a type
  lives in.
- **−** Three crates to version and release in dependency order — handled by release-plz
  (ADR-0009).
- **−** A contributor must know which layer a change belongs in (engine vs. knowledge vs.
  facade re-export). Documented in the crate docs.
