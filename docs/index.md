# forensicnomicon

**6,554 forensic artifacts. Every one enriched.** The zero-dependency KNOWLEDGE leaf of the SecurityRonin forensic fleet — a compile-time artifact catalog plus the normalized `report` and `history` vocabularies every analyzer builds on.

You're in an active IR. You need to know if a binary is abusable, right now, offline, without opening a browser.

```bash
brew install SecurityRonin/tap/4n6query
# or: cargo install forensicnomicon-cli

4n6query certutil.exe          # LOLBin lookup, ATT&CK techniques, use cases
4n6query userassist            # 5 artifact variants, decoded field schemas, triage priority
4n6query T1547.001             # all artifacts mapped to this technique
4n6query --triage              # Critical artifacts to collect first, RFC 3227 order
```

Building DFIR tools in Rust? The same data is a zero-dependency library.

## What it does

Most artifact registries tell you *where* an artifact lives. forensicnomicon tells you what it **means** — and gives your tool the structured knowledge to act on that meaning automatically. Every artifact entry carries decode rules, forensic meaning, evidence reliability, triage priority, RFC 3227 volatility class, and dependencies. The [DFIR Handbook](dfir-handbook.md) is the analyst-facing tour of the catalog.

The crate is the fleet's three KNOWLEDGE vocabularies in one zero-dependency leaf:

### The artifact catalog

Magic bytes, record markers, format header offsets, field schemas, and invariants for thousands of forensic artifacts — plus LOLBAS/LOFL enrichment, ATT&CK mappings, and abusable-site data. No parsing algorithms, no file I/O.

### Normalized reporting (`report`)

The **shared finding vocabulary every SecurityRonin analyzer normalizes onto**, so VMDK, VHDX, EWF, MBR/GPT/APM, ISO 9660, EVTX, SRUM, memory, and PE findings aggregate into one uniform `Report` instead of N bespoke result types. It is the **union of the analyzers' data, not a flattening** — and a `Finding` is an *observation with evidence*, never a verdict.

```rust
use forensicnomicon::report::{Finding, Severity, Category, Source};

let finding = Finding::observation(Severity::High, Category::Integrity, "VMDK-RGD-MISMATCH")
    .note("redundant grain directory diverges from the primary")
    .source(Source { analyzer: "vmdk-forensic".into(), scope: "VMDK".into(), version: None })
    .mitre("T1565.001")                 // "consistent with", never an assertion
    .evidence("primary_gte", "0x1234")
    .build();

assert_eq!(finding.severity, Some(Severity::High));
```

- **5-level `Severity`** (`Info < Low < Medium < High < Critical`), carried as `Option` so *unrated* is distinct from *scored, benign*.
- **`Observation` producer trait** — implement `severity`/`category`/`code`/`note` on your typed anomaly and get `to_finding()` for free. `Finding` is builder-only and `#[non_exhaustive]`.
- **Stable, scheme-prefixed codes** (`VMDK-RGD-MISMATCH`, `MEM-PROCESS-HOLLOWING`, `WINEVT-PROVIDER-GUID-SPOOFING`) are the cross-scheme join key.

### State-history (`history`)

The `[H]` state-history layer — a cross-cutting functor that lifts every navigation primitive to a time-indexed variant (disk → VSS/APFS snapshots, memory → hiberfil chain, log → rotated/sealed journals, query → point-in-time exports; `[C]` git is the fixed point). Pure declarative vocabulary — no parsing, no I/O. `TemporalCohort<H>`, `ClockProvenance` (four orthogonal trust axes), and `SourceTemporalProfile` give the fleet one canonical temporal classification per source family so consumers never re-derive and drift.

## Design

`forensicnomicon` stays the zero-dependency **leaf**: every analyzer depends *down* onto it; it depends on no one.

## Used by

- [`issen`](https://github.com/SecurityRonin/issen) — live incident response triage; renders the normalized `Report`
- [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) — `disk4n6` partition-scheme orchestrator; aggregates analyzer findings
- The SecurityRonin **forensic analyzer fleet** — `vmdk-forensic`, `vhdx-forensic`, `ewf-forensic`, `mbr-/gpt-/apm-/iso9660-forensic`, `winevt-forensic`, `srum-forensic`, `memory-forensic`, `exec-pe-forensic`, `usnjrnl-forensic` — all emit `forensicnomicon::report::Finding`
- [`blazehash`](https://github.com/SecurityRonin/blazehash) — high-speed forensic hash verification
