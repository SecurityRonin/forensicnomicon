# 0005 — Open string-backed newtypes over closed enums for identity sets

**Status:** Accepted

## Context

Some identity sets grow indefinitely and are shared across crates — the set of *filesystems*
(`FsKind`) is the motivating case. A closed enum (`enum FsKind { Ntfs, Ext, Xfs, …, Other }`)
has two failure modes: every new filesystem needs a release of the contract crate plus
cross-session coordination just to add a variant; and the long tail degrades into a stringly
`Other`, so equivalent things get two representations (btrfs shipped as `Other` while xfs was a
named variant). Filesystem identity is *knowledge* — it belongs with the other per-format
knowledge, not baked into a downstream contract enum.

## Decision

Represent such open identity sets as a **string-backed newtype** with named constants, not a
closed enum:

```rust
pub struct FsKind(&'static str);
impl FsKind {
    pub const NTFS: FsKind = FsKind("ntfs");
    // … one const per filesystem; adding one is a new const, never a breaking change
    pub const fn as_str(&self) -> &'static str { self.0 }
    pub fn from_name(name: &'static str) -> FsKind { FsKind(name) }
    pub fn known() -> &'static [FsKind] { KNOWN }
}
```

`as_str` round-trips (stable lowercase, log/JSON/URI-safe); `known()` is the enumerable
allowlist; serde is the transparent bare string behind the `serde` feature; a documented
`UNKNOWN_FALLBACK` handles deserialization of an unrecognized name without leaking a
`&'static str`. The type lives in `forensicnomicon-core::filesystems`, next to the existing
`FILESYSTEM_SIGNATURES` source of truth (ADR-0006), so `forensic-vfs 0.3` can derive its
`FsKind` from it instead of maintaining a parallel enum.

Evidence: `crates/core/src/filesystems.rs:145-272` (newtype rationale, consts, `known()`,
`UNKNOWN_FALLBACK`, serde). The same const-slice-of-newtype shape recurs (`Confidence(f32)`,
`PlatformMask(u8)`).

## Consequences

- **+** Adding a filesystem is one `const` in the knowledge leaf — no contract-crate release, no
  variant/`Other` split, ever. One uniform representation; nothing is "special".
- **+** `known()` still lets consumers enumerate/validate without a closed enum; the set is open
  for extension but inspectable.
- **−** The compiler cannot exhaustively match on an open set — callers that switch on kind must
  handle the open case (validate against `known()` where they need a closed world).
- **−** `from_name` is `&'static`-only by construction; runtime-string entry (serde) must resolve
  to a known const or the documented fallback, which callers must validate if they require a
  registered kind.
