# 0006 — Single-source-of-truth static signature registries

**Status:** Accepted

## Context

Facts like "NTFS has magic `NTFS␣␣␣␣` at offset 3" or "this MBR boot code is GRUB" are needed by
many tools and modules. If each re-encodes the bytes, the copies drift and a fix in one place
does not reach the others — the exact drift the Knowledge-as-Code thesis (ADR-0001) exists to
prevent. Within this codebase the same risk applies module-to-module.

## Decision

Encode each such fact once, as a documented `static`/`const` slice that is the explicit single
source of truth, and have every consumer reference it rather than re-transcribe the bytes. Each
entry cites its authoritative on-disk-format reference.

Registries: `FILESYSTEM_SIGNATURES` (`(offset, magic) → name`,
`crates/core/src/filesystems.rs:53`), `partition_schemes` magics, `BOOT_CODE_SIGNATURES`
(`src/boot_signatures.rs:36`), `CONTAINER_SIGNATURES` / `RECORD_SIGNATURES`
(`crates/core/src/catalog/containers_parsing.rs`). The `report` vocabulary (ADR-0003) and the
temporal `SourceTemporalProfile` are the same pattern for non-byte knowledge. When a magic
already exists in a sibling module, new code references it — it does not duplicate the bytes
(Doer-Checker: names/magics must match what the format modules already encode).

## Consequences

- **+** A fact is fixed in one place and every consumer gets the fix — no fleet drift.
- **+** Each registry is independently testable and citable against its format spec.
- **+** New detection code composes existing registries instead of re-encoding signatures.
- **−** Contributors must find and extend the canonical registry rather than inline a local
  copy — a search-first discipline, enforced by review.
