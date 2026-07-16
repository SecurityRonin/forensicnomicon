# 0001 — DFIR knowledge compiled into `&'static` code

**Status:** Accepted

## Context

DFIR reference knowledge — MITRE ATT&CK, LOLBAS, LOLDrivers, artifact decode schemas, KAPE
targets — lives across many websites. During an active investigation on an isolated analysis
host there is often no browser and no network, and the responder needs an authoritative answer
now. The same knowledge is also not machine-consumable: every tool re-scrapes or re-transcribes
it, and the copies drift.

## Decision

Compile the knowledge directly into the binary as `&'static` Rust data and answer queries from
it with zero runtime I/O and zero network. The catalog is a `&'static [ArtifactDescriptor]`;
lookups are iteration/filtering over static slices, not deserialization of an external store.
Network access exists **only** in the offline, human/CI-run `ingest` tool (see ADR-0008);
shipped crates never reach the network.

Evidence: README "DFIR knowledge compiled into code … queryable in milliseconds with no browser
and no network"; `ForensicCatalog` wraps `entries: &'static [ArtifactDescriptor]` with a
`const fn new()` (`crates/core/src/catalog/types.rs`); the CLI resolves queries from the linked
catalog with no I/O.

## Consequences

- **+** Answers are offline and sub-second; nothing to install a server for, nothing to reach.
- **+** Knowledge becomes a typed, testable API rather than scraped text — tools consume it
  directly and share one encoding.
- **+** No runtime deserialization or store, so no parser/allocation attack surface at query
  time.
- **−** New knowledge requires a rebuild/release, not a live data push — mitigated by the
  fast-moving data crate (ADR-0002) and the `ingest` pipeline (ADR-0008).
- **−** The full catalog is linked into every consumer; binary size grows with the corpus.
  Accepted: offline availability is the product.
