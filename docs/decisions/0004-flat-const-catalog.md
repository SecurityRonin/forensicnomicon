# 0004 — Flat, `const`-constructible catalog descriptors

**Status:** Accepted

## Context

The catalog is compiled-in `&'static` data (ADR-0001) assembled from thousands of hand-curated
and machine-generated entries (ADR-0008). For entries to be `&'static` and built at compile time
— no runtime allocation, no lazy init — every type in a descriptor must be `const`-constructible.
A recursive or heap-backed decoder representation would force runtime construction and break the
zero-I/O guarantee.

## Decision

Model each catalog entry as an `ArtifactDescriptor` carrying an `OsScope`, a **flat,
non-recursive `Decoder` enum**, a MITRE mapping, a `TriagePriority`, and evidence/volatility
ratings. The `Decoder` is deliberately flat — no recursive `&'static Decoder` — so descriptors
are `const`-constructible and the generated data files are plain `static` arrays.
`OsScope → Platform` via `OsScope::platform()`; platform sets are a `PlatformMask(u8)` bitmask
builder. `ForensicCatalog` wraps the `&'static` slice with a `const fn new()` and exposes the
query engine (`by_id`, `filter`, `by_mitre`, `for_triage`, `unassessed`, `filter_by_keyword`).

Evidence: `crates/core/src/catalog/types.rs` — `Decoder` (`types.rs:264` "no recursive
`&'static Decoder`"), `ArtifactDescriptor`, `PlatformMask`, `ForensicCatalog::new` (`const fn`).

## Consequences

- **+** The entire catalog is a compile-time constant — zero runtime construction, consistent
  with the offline/instant guarantee.
- **+** Generated descriptor files are simple `static` arrays that the `ingest` codegen can emit
  mechanically.
- **−** A genuinely nested decode (a field that is itself a structured blob) must be expressed
  as a flat decoder variant plus schema, not by nesting `Decoder`. Accepted trade for
  `const`-constructibility.
- **−** Growing the decode vocabulary means adding a flat `Decoder` variant (a core change), not
  composing existing ones.
