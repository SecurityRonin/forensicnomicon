# 0007 — Panic-free, `forbid(unsafe)`, low-MSRV, `no_std`-capable, serde-optional

**Status:** Accepted

## Context

Forensicnomicon is a foundational library embedded by DFIR tools that run against
attacker-influenced evidence. A panic or a memory-safety bug in the library becomes a crash or
worse in every consumer, mid-investigation. Consumers also range widely (embedded/`no_std`
contexts, older toolchains, tools that do and don't want serde), so the library must be broadly
embeddable without forcing dependencies.

## Decision

Adopt a uniform "paranoid gatekeeper" posture across the workspace:

- **`unsafe_code = "forbid"`** workspace-wide; clippy `correctness`/`suspicious` denied;
  **`unwrap_used`/`expect_used` denied in production** ("a published accessor must never
  panic"). Tests opt out via `#![cfg_attr(test, allow(...))]`.
- **Untrusted-byte parsers are fuzzed** — a `cargo-fuzz` target per raw-`&[u8]` surface (PE
  headers, PCA UTF-16, boot-code scanners, XOR deobfuscation, entropy/scoring, fixed-size
  history constructors), invariant "never panic", run on Linux CI (`fuzz.yml`).
- **`no_std`-capable core** — `std` is an empty additive feature; `no_std_compat` documents and
  validates the `#![no_std]`-safe surface (with external `alloc` when `serde` is enabled).
- **Low MSRV 1.75**, held uniformly across all published crates as a compatibility guarantee.
- **`serde` optional everywhere** — derives and impls gated behind the feature; the zero-config
  path pulls no serialization dependency.

Evidence: `[workspace.lints]` in `Cargo.toml`; `src/no_std_compat.rs`; `fuzz/` targets +
`.github/workflows/fuzz.yml`; per-crate `rust-version = "1.75"`; `[features] serde` across
core/data/facade.

## Consequences

- **+** A published accessor cannot panic on bad input by construction; the fuzz targets are the
  runtime backstop for the parsers.
- **+** The library embeds in `no_std` contexts and on older toolchains, with no forced serde.
- **+** Memory-safety is guaranteed by `forbid(unsafe)`, not audited case by case.
- **−** No `unwrap`/`expect` in production means bounded readers and explicit `Option`/`Result`
  threading — more verbose than the panicking idiom. Accepted for a foundational library.
- **−** Holding MSRV 1.75 forgoes newer language features until the floor is deliberately raised
  (a near-breaking change for consumers).
