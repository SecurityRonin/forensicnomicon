# Handoff: forensicnomicon knowledge propagation — Plans A & B

> **ARCHIVED 2026-06-29 — Plan A COMPLETE.** Kept as a record + for Plan B.

**Status (2026-06-29, Plan A done):**
- **3-crate split + 1.0 cut — SHIPPED.** `forensicnomicon`, `forensicnomicon-core`,
  `forensicnomicon-data` all at **1.0.0** on crates.io (facade re-exports both;
  release-plz / cargo-public-api / Renovate automation in place). `forensicnomicon-cli`
  at 0.1.2.
- **Fleet — FULLY MIGRATED.** ~38 dependent repos (~70 crate versions) republished onto
  `forensicnomicon = "1"` in dependency order; every mainline tree resolves a single
  fn 1.0 major (stale-caret + local-ahead strands cleaned up).
- **Resolved decisions:** keep the `forensicnomicon` facade long-term (no hard-cut);
  crate names `-core` / `-data`.
- **Plan B (engine/knowledge `-core` decoupling) was NOT done and remains a future
  option** — the fleet pins the facade `"1"`, not `-core` directly. The broader
  direction is now the fleet-monorepo consolidation (see issen
  `docs/plans/2026-06-29-fleet-monorepo-consolidation.md`), which would subsume Plan B.
- **Option C** (signed runtime knowledge pack) remains deferred.

**Original proposal date:** 2026-06-28.
**Audience:** whoever picks up forensicnomicon release engineering next.

## Executive Summary

forensicnomicon is the fleet's forensic *knowledge* library (artifact catalog,
IOC/threat tables, MITRE mappings) **and** the home of the shared *report model*
(`Finding`/`Severity`/`Observation`) that ~37 `*-forensic` analyzer crates and the
apps (`issen`, `4n6query`) depend on. Today it is `0.11.0` (pre-1.0).

**The question that prompted this:** does every knowledge change require
republishing all dependents? **No.** Adding catalog entries is additive and
non-breaking; the binding constraint is the *app's* `Cargo.lock` (apps rebuild to
ship compiled-in knowledge; analyzer *libraries* need no republish if their
version requirement already admits the new version).

**The real problem** is the inverse: dependents are pinned across **six
incompatible forensicnomicon ranges** (`0.3.1`, `0.5`, `0.7`, `0.10`, `0.11`,
path), so ~13 analyzer libs **cannot receive any forensicnomicon update** without
an individual widen + republish, and the shared `Finding` type only composes if
every analyzer agrees on one major — a latent duplicate-version / type-identity
hazard (not live in `issen` today; its lock holds a single `0.11.0`).

Two plans, do them in order:

- **Plan A — release hygiene (days).** Normalize the fleet to one major, cut
  `1.0`, automate propagation (Renovate + release-plz + tag-driven app releases).
  Fixes the live stale-pin hazard cheaply. Low risk.
- **Plan B — engine/knowledge split (weeks).** Split the slow-moving engine
  (report model + schema + lookup API + stable structural constants) from the
  fast-moving detection knowledge (catalog/IOCs/MITRE). The 37 analyzer libs then
  couple only to the stable engine and need **zero** republish when knowledge
  changes. This is the proven Volatility/Sigma/YARA/ClamAV pattern.

Mechanics validated against the Cargo reference and an adversarial review (Codex).

---

## Background — verified facts (2026-06-28)

- `forensicnomicon = 0.11.0`, pre-1.0, MSRV `1.75`, published to crates.io.
  Workspace members: `.` (root crate — everything), `crates/ingest`,
  `crates/4n6query`.
- The root crate bundles two concerns with very different change cadences:
  - **Stable engine / API:** `src/report.rs` (`Finding`/`Severity`/`Observation`,
    the model every analyzer emits), `src/evidence.rs`, the catalog **types**
    (`ArtifactDescriptor`, `FieldSchema`, enums) and lookup engine
    (`ForensicCatalog`), and **structural constants readers need** (filesystem
    magics, `decmpfs`, type codes — e.g. `apfs-core` consumes these).
  - **Fast-moving knowledge:** `src/catalog/descriptors/**` (~6668 artifact
    descriptors), `src/heuristics/`, `src/threat_intel/`, and the large data
    files (`drivers_data.rs` ~278K, `lolbins.rs` ~253K, `attack_flow.rs` ~237K,
    `mitre.rs` ~95K, `abusable_sites.rs` ~43K, …).
- The catalog total count is **not** public API (internal tests only), so
  additions are non-breaking at the API level.
- Dependent pins (working trees) are scattered and stale:

  | Range | Crates |
  |---|---|
  | `0.3.1` | dar, ewf, exec-pe, journald, qcow2, usnjrnl, vhdx |
  | `0.5` | apfs-forensic, snapshot, vsc |
  | `0.7` | ext4fs, udf |
  | `0.10` | dpapi |
  | `0.11` | ~20 (majority) + issen |
  | path | hfsplus-forensic |

### Cargo mechanics (fact vs. policy)

- `^0.x.y` uses the left-most non-zero component: `^0.11.0` = `>=0.11.0,<0.12.0`;
  `^0.5` = `>=0.5.0,<0.6.0` (cannot reach `0.11`). Pre-1.0, a minor bump
  (`0.11→0.12`) is a **breaking** boundary in Cargo's eyes.
- "Additive ⇒ patch" is a **release-policy choice**, not a Cargo fact. New
  descriptors change detection output / FP rates / binary size, so a minor may be
  the honest label. Cargo only defines resolver ranges, not your version label.
- The freeze point that decides what *ships* is the **app's committed
  `Cargo.lock`** — a compatible `0.11.1` only reaches users after
  `cargo update` / Renovate + an app rebuild.
- A published library's dependency requirement is **frozen in its published
  manifest** — a crate pinned to `"0.5"` never resolves `0.11` transitively;
  widening requires a new release of *that* crate.
- Two semver-incompatible forensicnomicon versions in one tree ⇒ Cargo builds
  **both**, duplicating the compiled catalog and making the `Finding` types
  distinct (won't unify across crate boundaries). Inspect with `cargo tree -d`.
- `cargo install` does a **fresh resolve** at install time, so an installed build
  can carry a different catalog than the released binary — a reproducibility
  concern for forensic tooling; pin/lock and document the baseline.

---

## Plan A — Release hygiene (do first)

**Goal:** every dependent tracks one forensicnomicon major, and compatible
knowledge updates propagate automatically into app lockfiles + releases with no
manual N-crate republish.

### A1. Decide the stability line — cut `forensicnomicon 1.0`
- Pre-1.0, additive knowledge can only stay auto-compatible as `0.11.x` *patches*
  (since `0.12` would break `^0.11`). That conflates "new knowledge" with
  "patch". Going `1.0` makes additive knowledge a normal **minor** (`1.x`) on a
  single stable major — the natural compatible channel.
- Precondition: confirm the public API (`report`, catalog types, `ForensicCatalog`,
  re-exported enums) is one you're willing to hold stable under SemVer. Audit
  `pub` surface (`cargo public-api` if available) before tagging `1.0.0`.
- Keep MSRV `1.75` (published-library floor, CI-verified) — see fleet MSRV policy.

### A2. Normalize all dependents to the one major
- Set every `*-forensic` / app pin to `forensicnomicon = "1"` (or `"0.11"` if
  `1.0` is deferred). Fix the 13 stale `0.3.1/0.5/0.7/0.10` pins specifically.
- Each repo with its own workspace: hoist the dep to
  `[workspace.dependencies] forensicnomicon = "1"` so it is one edit per repo.
- Each widened library needs a new **patch release** (its frozen manifest must be
  republished to carry the wider requirement). Sequence: forensicnomicon `1.0`
  first, then libraries (leaf-first), then apps.
- Verify no duplicates remain: `cargo tree -d -p forensicnomicon` in `issen` and
  `4n6query` must show a single version.

### A3. Automate propagation (per the fleet Dependency-Freshness policy)
- **Renovate** (every fleet repo): `rangeStrategy: "bump"` +
  `"lockFileMaintenance": { "enabled": true }`, scoped/grouped to the
  forensicnomicon namespace, automerge patch/minor for **app** repos only (never
  auto-raise a published library's MSRV).
- **release-plz** on forensicnomicon so a merged knowledge PR auto-publishes a
  minor/patch.
- **Tag-driven release** on apps so the auto-bumped lockfile actually ships
  binaries (`release.yml`).
- Commit `Cargo.lock` in app repos; CI freshness gate
  (`cargo update --locked --dry-run`).

### A4. Acceptance criteria
- `cargo tree -d -p forensicnomicon` clean (single version) in every app.
- A trivial forensicnomicon knowledge merge results, with no human edits, in: a
  published forensicnomicon release → Renovate lockfile-bump PRs in apps →
  app release containing the new knowledge.
- All fleet repos pin a single major; no `0.3.1/0.5/0.7/0.10` pins remain.

### A5. Risks / rollback
- Widening pins may surface real breaking changes accumulated across `0.5→1.0`
  in the 13 stale crates — budget for per-crate fixes, not just a version bump.
- Automerge on apps can ship a regression; mitigate with CI gates + rolling
  releases. Rollback = pin the lockfile back (`cargo update -p forensicnomicon
  --precise <old>`), re-release.

---

## Plan B — Engine / knowledge split (target architecture)

**Goal:** decouple knowledge cadence from the 37-crate library surface. A
knowledge change then touches only the data crate + app rebuilds; analyzer
libraries that depend on the stable engine need **zero** republish.

### B1. Target crate boundaries
- **`forensicnomicon-core`** (stable, `1.x`, slow): the report model
  (`report.rs`: `Finding`/`Severity`/`Observation`/`Source`), `evidence.rs`,
  catalog/threat **types + schema** (`ArtifactDescriptor`, `FieldSchema`, enums),
  the lookup **engine** (`ForensicCatalog` and its query methods over an
  injected dataset), and **stable structural constants** readers depend on
  (filesystem magics, `decmpfs`, type codes). No bulk data.
- **`forensicnomicon-data`** (fast, frequent compatible releases): the detection
  knowledge — `catalog/descriptors/**`, `heuristics/`, `threat_intel/`,
  `drivers_data`, `lolbins`, `mitre`, `attack_flow`, `abusable_sites`, … Depends
  on `-core` for the types; exposes the assembled `CATALOG_ENTRIES` (and friends)
  that `ForensicCatalog::new(...)` consumes.
- **`forensicnomicon`** (facade, optional): re-exports `-core` + a default
  baseline from `-data`, preserving today's single-import ergonomics and the
  offline single-static-binary default.

### B2. Who depends on what (the payoff)
- `*-forensic` analyzer halves that emit findings → depend on **`-core`** only →
  unaffected by knowledge releases.
- Reader `*-core` halves needing magics/`decmpfs`/type codes → **`-core`** (those
  constants live there because they are structural, not detection cadence).
- Analyzer logic that *queries the detection catalog* + the apps (`issen`,
  `4n6query`) → depend on **`-data`** → rebuild for new knowledge.

> **Key design decision for the implementer:** classify each currently-bundled
> table as *structural* (→ `-core`, stable) vs *detection* (→ `-data`, fast).
> Magics/type-codes/`decmpfs` are structural; artifact catalog / IOCs / MITRE /
> lolbins / drivers are detection. Getting this line right is what determines how
> many libs are insulated from knowledge churn. When unsure, default to `-data`
> (a reader can take a `-core` constant later without breaking anyone).

### B3. Migration steps (incremental, keep green throughout)
1. Introduce `forensicnomicon-core` as a new workspace member; move `report.rs`,
   `evidence.rs`, catalog **types** + `ForensicCatalog` engine, and the
   structural-constant modules into it. Re-export them from the root crate so
   nothing downstream breaks yet (root `pub use forensicnomicon_core::*`).
2. Introduce `forensicnomicon-data`; move the descriptor data + big tables; have
   it depend on `-core`. Root crate re-exports the baseline dataset.
3. Make `ForensicCatalog` dataset-injected so `-data` (or a runtime pack, see C)
   supplies entries to the `-core` engine.
4. Publish `-core 1.0` and `-data 0.1`/`1.0`. Migrate dependents: analyzer libs
   `forensicnomicon-core = "1"`; apps add `forensicnomicon-data`.
5. Keep the `forensicnomicon` facade crate for one or two releases as a
   compatibility shim; deprecate once dependents have moved.

### B4. Hazards specific to B
- **Type identity:** while migrating, an app may transitively pull old
  `forensicnomicon` *and* new `forensicnomicon-core`; their `Finding` types are
  distinct. Migrate leaf-first and verify `cargo tree -d`. The facade shim must
  re-export, not redefine, `-core` types.
- **Feature unification:** if crates grow features (`serde`, catalog subsets,
  runtime loading), workspace builds union them — keep feature surface minimal and
  documented.
- **Churn during the split** is a one-time cost across ~40 repos; sequence and
  automate (Plan A's Renovate/release-plz must be in place first — hence A→B).

### B5. Acceptance criteria
- A new artifact added to `-data`, released, reaches `issen` via an automated
  lockfile bump **without any release of any `*-forensic` analyzer library**.
- `cargo tree -d` clean across the fleet; analyzer libs depend on
  `forensicnomicon-core` only.

---

## Option C (conditional, not now) — signed runtime knowledge pack

If knowledge cadence ever outpaces the automated release pipeline, add an
**opt-in** signed knowledge pack loaded at runtime as an overlay on the compiled
baseline (the AV/YARA model): the baseline stays compiled-in (preserving the
single-static-binary / offline / `forbid(unsafe)` default), while a verified pack
delivers new artifacts/IOCs without a rebuild. Requires: signature verification
(secure-by-default), schema/version metadata, downgrade + poisoning defenses, a
robust untrusted-bundle parser (fail-loud), and dual-codepath maintenance. Only
worth it when the cadence justifies the added attack surface.

---

## Recommended sequencing

1. **Plan A now** — cheap, fixes the live stale-pin hazard, and is a prerequisite
   for B (you need the automation before adding a second published crate).
2. **Plan B next** — the durable fix; classify structural-vs-detection carefully.
3. **Option C only if** field updates between releases become a hard requirement.

## Open decisions for the human
- Cut `1.0` now, or stay `0.x` and only normalize pins? (1.0 recommended; still open.)

Resolved 2026-06-29:
- **Facade lifetime — keep the `forensicnomicon` facade long-term** as a re-export
  shim over `-core`/`-data`; no deprecate, no hard-cut. The standing cost: on every
  `-core`/`-data` major, cut a matching facade major and re-pin; the facade must
  re-export (never redefine) `-core` types; keep `cargo tree -d -p forensicnomicon-core`
  clean fleet-wide to hold off the duplicate-version / `Finding` type-identity hazard.
- **Crate names — `forensicnomicon-core` + `forensicnomicon-data`** (shipped).
- **Structural-vs-detection classification** — implemented in the shipped split
  (`-core` = report model + schema + lookup engine + structural constants;
  `-data` = catalog / IOCs / MITRE); refine per-table as needed.

## Verification cheat-sheet
- `cargo tree -d -p forensicnomicon` — detect duplicate incompatible versions.
- `cargo update -p forensicnomicon --precise <ver> --dry-run` — is a version
  published & reachable? ("candidate versions … didn't match" = requirement too
  narrow → widen.)
- `cargo public-api diff` — confirm a release is non-breaking before labeling it.
