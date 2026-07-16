# 0008 — Offline `ingest` codegen → committed generated Rust

**Status:** Accepted

## Context

The catalog draws from many authoritative upstream corpora (LOLBAS, KAPE, EZ-tools, Velociraptor,
NirSoft, browser artifact sets, and more). That content must become compiled-in `&'static`
`ArtifactDescriptor` data (ADR-0001/0004) — but the shipped crates must stay offline and
zero-network (ADR-0001), so fetching cannot happen at build time (`build.rs`) or runtime.

## Decision

Do the fetch-and-generate offline, in a dedicated `ingest` tool run by a human/CI, and **commit
its output as generated Rust** into `forensicnomicon-data`:

1. `ingest` fetches upstream corpora (`reqwest`, blocking), parses each with a per-source module,
   normalizes to an `IngestRecord`, and dedups against the existing catalog ids.
2. `codegen.rs` emits valid `ArtifactDescriptor` `static` arrays into
   `crates/data/src/catalog/descriptors/generated/*_generated.rs`, marked `@generated`.
3. The generated files are **checked in** and compiled directly into `forensicnomicon-data`
   alongside the hand-curated `*_ext.rs` descriptors.

`ingest` is `publish = false` / `release = false` (mirrored in Cargo.toml, which release-plz
cross-checks); its raw feeds and tooling are excluded from the published data crate. A
`feed-watch.yml` CI job tracks upstream freshness.

Evidence: `crates/ingest/` (`github.rs`, `sources/`, `normalize.rs`, `dedup.rs`, `codegen.rs`,
`main.rs` output path into `../data/src/catalog/descriptors/generated`); `crates/data`
`exclude = ["archive/", "scripts/", ...]`.

## Consequences

- **+** Shipped crates stay fully offline; the network dependency lives only in a tool nobody
  ships.
- **+** Generated code is reviewable in diffs and compiles like any other source — provenance is
  visible, not hidden behind a build script.
- **+** Regeneration is reproducible and dedups against curated entries, so hand-curation and
  bulk import coexist.
- **−** Regenerating and committing large generated files is a deliberate, reviewed step, not
  automatic — the price of keeping the runtime offline and the provenance auditable.
- **−** Committed generated code enlarges the repo; mitigated by excluding raw feeds from the
  published package.
