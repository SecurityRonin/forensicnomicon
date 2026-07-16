# Architecture Decision Records

These ADRs are **reverse-engineered** from the codebase: they record the load-bearing
architectural decisions already embodied in Forensicnomicon, so the *why* is captured
alongside the *what*. Each is written in the state it holds today (status **Accepted** unless
noted). New decisions get the next number; superseding an ADR links forward.

Format: Context → Decision → Consequences, with `file:line` evidence where it grounds the claim.

| # | Title | Status |
|---|---|---|
| [0001](0001-knowledge-as-code.md) | DFIR knowledge compiled into `&'static` code | Accepted |
| [0002](0002-three-layer-crate-split.md) | Three-layer crate split: stable core / fast data / facade | Accepted |
| [0003](0003-normalized-finding-model.md) | A normalized Finding/Observation model as the fleet vocabulary | Accepted |
| [0004](0004-flat-const-catalog.md) | Flat, `const`-constructible catalog descriptors | Accepted |
| [0005](0005-open-string-backed-newtypes.md) | Open string-backed newtypes over closed enums for identity sets | Accepted |
| [0006](0006-single-source-of-truth-registries.md) | Single-source-of-truth static signature registries | Accepted |
| [0007](0007-panic-free-safe-portable-posture.md) | Panic-free, `forbid(unsafe)`, low-MSRV, `no_std`-capable, serde-optional | Accepted |
| [0008](0008-offline-ingest-codegen.md) | Offline `ingest` codegen → committed generated Rust | Accepted |
| [0009](0009-decoupled-release-pipelines.md) | Two decoupled release pipelines (libraries vs. binaries) | Accepted |
| [0010](0010-oracle-validated-knowledge.md) | Oracle-validated knowledge on real IR data; denylists non-exhaustive | Accepted |
