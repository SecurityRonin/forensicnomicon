# Product Requirements Document — Forensicnomicon

*Reverse-engineered from the codebase at the 1.6 / core-1.1 / data-1.2 line. Describes the
product as it exists today; forward-looking items are marked "Proposed".*

## Executive Summary

**Forensicnomicon is DFIR knowledge compiled into code.** MITRE ATT&CK, LOLBAS, LOLDrivers,
and the working set of Windows/Linux/macOS forensic artifacts ship as a zero-runtime-dependency
Rust library and an offline binary (`4n6query`), answerable in milliseconds with no browser and
no network. The reference knowledge a responder normally *browses* across a dozen sites is
instead a `&'static` dataset linked into the binary.

- **Primary user:** an incident responder or DFIR engineer mid-investigation who needs an
  authoritative answer — *is this binary abusable? what does this artifact decode to? what
  should I collect first?* — offline and immediately.
- **Secondary user:** a Rust developer building a detection pipeline or a `*-forensic`
  analyzer, who wants the same knowledge as a stable, embeddable library and a normalized
  finding vocabulary to emit.
- **Core promise:** correct, current DFIR knowledge, queryable offline in milliseconds, with a
  stable API surface that downstream tools can pin against for years.

Two things carry the product: the **data** (a large, enriched, provenance-tracked artifact
catalog assembled from authoritative corpora) and the **engine** (a stable, panic-free,
`no_std`-capable core that models findings and answers catalog queries over `&'static` data).
They are deliberately separated so knowledge can move fast while the API a downstream analyzer
depends on stays still.

## Problem

DFIR reference knowledge is fragmented and online. During an active investigation a responder
consults MITRE ATT&CK, LOLBAS, LOLDrivers, KAPE targets, EZ-tools notes, and a stack of blog
posts — each a separate site, each requiring a browser and network access the responder may not
have on an isolated analysis host. The knowledge is also not machine-consumable: a tool that
wants to know "is `certutil.exe` a LOLBin, and which ATT&CK techniques does it enable" has to
scrape or re-encode it. And the knowledge drifts — the same fact (a driver's hash, an
artifact's decode schema) is re-transcribed per tool, so the fleet disagrees with itself.

## Goals

1. **Offline, instant answers.** Every shipped query resolves from compiled-in `&'static` data
   with zero I/O and zero network at runtime.
2. **One authoritative encoding.** Each fact — a signature, a decode schema, a driver entry —
   has a single source of truth in the codebase, so tools that share it cannot drift.
3. **Embeddable + stable.** The engine is a library any Rust DFIR tool can pin, with a finding
   vocabulary analyzers emit and a query API that does not churn.
4. **Broad reach, safe by construction.** Low MSRV, `no_std`-capable, `forbid(unsafe)`, and
   panic-free in every published accessor.
5. **Fresh without breaking.** Knowledge evolves additively behind a fast-moving data crate;
   the stable engine bumps majors only deliberately.

## Non-Goals

- **Not a parser/mounting/acquisition tool.** Forensicnomicon encodes *knowledge and
  detection heuristics*, not disk mounting or evidence acquisition. Format constants and
  signatures live here; the parsing lives in the consuming `*-forensic` / VFS crates.
- **Not a complete allowlist of "safe".** Denylists (e.g. BYOVD drivers) are explicitly
  non-exhaustive, point-in-time, names-only leads — absence is not proof of safety.
- **Not an online service.** The only network access is the offline, human-run `ingest`
  codegen tool; shipped crates never reach the network.

## Users & Key Use Cases

| Persona | Situation | What they run / call |
|---|---|---|
| Incident responder | Isolated host, active IR, no browser | `4n6query certutil.exe` — LOLBin verdict + ATT&CK + use cases |
| Triage lead | Deciding collection order under time pressure | `4n6query --triage` — critical artifacts first, RFC 3227 order |
| Detection engineer | Mapping coverage to a technique | `4n6query T1547.001` — every artifact/indicator for the technique |
| `*-forensic` author | Building an analyzer in Rust | `forensicnomicon-core = "1"` — emit `report::Finding`, no churn |
| Knowledge consumer | Wants the full catalog embedded | `forensicnomicon = "1"` — facade: engine + catalog, one import |

## Requirements

### Functional

- **FR1 — Artifact catalog.** A large enriched catalog (~6,500 artifacts; see *Open Questions*
  on the exact count) of forensic artifacts, each with OS scope, decode schema, MITRE mapping,
  triage priority, and evidence/volatility ratings. Queryable by id, keyword, MITRE technique,
  and triage priority.
- **FR2 — LOLBin / LOFL lookup.** LOLBAS plus Living-Off-Foreign-Land across Windows, Linux,
  and macOS, with per-binary ATT&CK techniques and use cases.
- **FR3 — BYOVD driver denylist.** Known-vulnerable/malicious drivers sourced from LOLDrivers,
  pinned to a specific upstream commit and validated against real IR data.
- **FR4 — Signature registries.** Single-source-of-truth `(offset, magic) → identity` tables
  for filesystems, partition schemes, boot code, and container/record formats.
- **FR5 — Finding model.** A normalized `Finding` / `Observation` vocabulary (Severity,
  Category, Confidence, MITRE refs, evidence, provenance, timeline) that every analyzer emits,
  so a heterogeneous fleet produces one comparable output shape.
- **FR6 — Offline CLI.** `4n6query` answers artifact / LOLBin / technique / triage queries with
  text and machine-readable (JSON/YAML) output.

### Non-Functional

- **NFR1 — Offline & instant.** Zero runtime I/O, zero network; queries resolve from `&'static`
  data in milliseconds.
- **NFR2 — Zero runtime dependencies** in the core (optional `serde` only); minimal in the
  facade.
- **NFR3 — Panic-free & memory-safe.** `unsafe_code = "forbid"` workspace-wide;
  `unwrap_used`/`expect_used` denied in production; untrusted-byte parsers are fuzzed.
- **NFR4 — `no_std`-capable core** (with an external `alloc` when `serde` is enabled).
- **NFR5 — Low MSRV (1.75)** across all published crates, held as a compatibility guarantee.
- **NFR6 — API stability.** The core engine surface is gated by a public-API check; downstream
  tools pin `forensicnomicon-core = "1"` and bump majors only deliberately.
- **NFR7 — Validated knowledge.** Value-producing and denylist claims are checked against an
  independent oracle on real-world data (Doer-Checker), documented in `docs/validation.md`.

## Architecture at a Glance

Three published library crates plus a CLI and an offline build tool:

- **`forensicnomicon-core`** — the stable engine: the `report` finding model, the catalog
  *query* engine over `&'static [ArtifactDescriptor]`, and structural format constants. Zero
  runtime deps, `no_std`-capable. Downstream analyzers and `forensic-vfs` pin this.
- **`forensicnomicon-data`** — the fast-moving knowledge layer: the assembled artifact catalog
  (hand-curated + machine-generated descriptors) that wires the global catalog. Evolves
  additively.
- **`forensicnomicon`** (facade) — re-exports core + data and adds the detection/heuristic
  knowledge modules (mitre, lolbins, drivers, threat_intel profiles, heuristics, format
  modules). One import for consumers who want everything; stable re-export paths.
- **`4n6query`** (`forensicnomicon-cli`) — the offline binary.
- **`ingest`** (`publish = false`) — the offline, human/CI-run codegen tool that fetches
  authoritative corpora and emits committed `ArtifactDescriptor` Rust into `forensicnomicon-data`.

The load-bearing decisions behind this shape are recorded as ADRs in
[`docs/decisions/`](decisions/).

## Release & Distribution

Two decoupled pipelines: **release-plz** publishes the library crates to crates.io on merge to
`main` (dependency-ordered, per-crate changelogs, release-triggering commit types allowlisted);
a **tag-driven `release.yml`** builds and distributes the `4n6query` binaries (macOS/Linux/
Windows, Homebrew tap) only on a manual `v*` tag. See ADR-0009.

## Success Metrics

- A responder gets a correct LOLBin/artifact/technique answer offline in one command, sub-second.
- Downstream `*-forensic` analyzers depend on `forensicnomicon-core` without breakage across a
  data-crate release cycle (the public-API gate stays green).
- Every value-producing or denylist knowledge claim has a named oracle in `docs/validation.md`.

## Open Questions

- **Artifact count is stated inconsistently** — README says 6,554, the CLI package description
  says 6,548, and the library docs say "~6.5k". These should be reconciled to one derived count
  (ideally computed from the catalog at build time, not hand-maintained) before it is quoted as
  a spec number.
- **Detection-from-signature for `FsKind`** (mapping `FILESYSTEM_SIGNATURES` to `FsKind`) is
  deferred; the canonical-name vs. signature-name mismatch needs a clean mapping first.
