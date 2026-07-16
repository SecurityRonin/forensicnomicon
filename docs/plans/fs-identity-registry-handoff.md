# Handoff: canonical filesystem-identity registry (`FsKind`) in forensicnomicon

**For:** the next agent working on `forensicnomicon`.
**Status:** proposed, not started. This is the KNOWLEDGE-leaf half of a two-repo fix;
the `forensic-vfs` half is a separate, coordinated change (see "Downstream").
**Why now:** the fleet VFS migration exposed an architectural smell in
`forensic-vfs::FsKind` that must be fixed at the root — here.

## Executive summary

`forensic-vfs` currently identifies filesystems with a **closed enum**
`FsKind { Ntfs, Ext, Xfs, Apfs, HfsPlus, Iso9660, Udf, Fat, ExFat, Other }`. This is
wrong two ways at once:

1. **Closed-enum bottleneck** — every new filesystem (zfs, ufs, refs, btrfs, …) needs
   a `forensic-vfs` release + a cross-session coordination just to get a variant. The
   contract crate should not have to know about every concrete filesystem.
2. **Inconsistent representation** — some filesystems are first-class variants
   (`FsKind::Xfs`) while the long tail is stringly-typed `FsKind::Other`. btrfs already
   ships as `FsKind::Other` while xfs is `FsKind::Xfs` — two representations for the
   same concept. (This is the specific complaint that triggered this handoff.)

**The fix:** filesystem identity is *knowledge* ("what filesystems exist, their
canonical names + magics") and belongs in `forensicnomicon`, the KNOWLEDGE leaf — right
next to the existing per-format modules (`ntfs.rs`, `ewf.rs`, `gpt.rs`, `apm.rs`, …).
Add a **string-backed typed `FsKind` newtype with named constants** here; `forensic-vfs`
then re-exports/derives from it (its enum → this newtype). After that, **adding a
filesystem is one `const` in forensicnomicon** — no contract release, no variant/`Other`
split, ever.

## Design — build this in `crates/core` (lean, so `forensic-vfs` can depend on it)

Put the type in **`crates/core`** (`forensicnomicon-core`, the zero-dep sub-crate) so
`forensic-vfs` — itself a foundational leaf — can depend on it without pulling the full
`forensicnomicon` tree. Re-export it from the root `forensicnomicon` crate for existing
consumers.

```rust
// crates/core/src/filesystem.rs  (new module; add `pub mod filesystem;` to crates/core lib)

/// Canonical identity of a filesystem, content-addressed by a stable lowercase name.
/// A newtype (not an enum) so the set is OPEN: adding a filesystem is a new `const`
/// here, never a breaking change to any contract crate.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FsKind(&'static str);

impl FsKind {
    // Every filesystem is a constant — uniform; none is "special", none is `Other`.
    pub const NTFS:     FsKind = FsKind("ntfs");
    pub const FAT:      FsKind = FsKind("fat");
    pub const EXFAT:    FsKind = FsKind("exfat");
    pub const EXT:      FsKind = FsKind("ext");        // ext2/3/4 family
    pub const XFS:      FsKind = FsKind("xfs");
    pub const APFS:     FsKind = FsKind("apfs");
    pub const HFS_PLUS: FsKind = FsKind("hfsplus");
    pub const ISO9660:  FsKind = FsKind("iso9660");
    pub const UDF:      FsKind = FsKind("udf");
    pub const BTRFS:    FsKind = FsKind("btrfs");      // ← retires btrfs's `Other`
    pub const ZFS:      FsKind = FsKind("zfs");
    pub const UFS:      FsKind = FsKind("ufs");
    pub const REFS:     FsKind = FsKind("refs");
    pub const ZIP:      FsKind = FsKind("zip");
    pub const AD1:      FsKind = FsKind("ad1");
    pub const DAR:      FsKind = FsKind("dar");
    // …extend by adding a const; nothing else changes.

    /// The stable lowercase identifier — round-trips, safe for logs / JSON / URIs.
    #[must_use] pub const fn as_str(&self) -> &'static str { self.0 }

    /// Construct from a runtime name (returns a known constant when it matches, else a
    /// borrowed-name kind). Keep this total and allocation-free; see `known()`.
    #[must_use] pub fn from_name(name: &'static str) -> FsKind { FsKind(name) }

    /// All registered kinds — lets consumers enumerate/validate without a closed enum.
    #[must_use] pub fn known() -> &'static [FsKind] { KNOWN }
}
static KNOWN: &[FsKind] = &[FsKind::NTFS, FsKind::FAT, /* … all consts … */];
```

Add `Display`, `Debug`, and (behind the existing `serde` feature, matching the crate's
convention) `Serialize`/`Deserialize` as the transparent string. Follow the crate's
existing module style (look at `gpt.rs`/`ntfs.rs` for the local idiom — doc comments,
`#[must_use]`, no `unwrap`/`expect`, `forbid(unsafe)`).

**Optional but recommended (leverage existing knowledge):** since forensicnomicon already
holds per-format magics, add a lightweight `magic`/`detect` association so identity and
detection live together — e.g. `FsKind::from_boot_signature(&[u8]) -> Option<FsKind>`
driven by the constants already in `ntfs.rs` (`"NTFS    "`), `iso9660`, `xfs` (`XFSB`),
etc. Keep this a thin lookup, not a parser. **Only build this if it's a clean fit** — the
newtype + constants are the required deliverable; detection is a nice-to-have. Do not
speculatively add fields nobody consumes (YAGNI).

## TDD (mandatory — RED then GREEN, separate signed commits)

1. **RED:** tests asserting `FsKind::XFS.as_str() == "xfs"`, round-trip
   `from_name(k.as_str()) == k` for every constant, `known()` contains all consts + has
   no duplicate `as_str`, serde round-trips to the bare string, `Display`/`Debug` shape.
   If you add detection: a real boot-signature → expected `FsKind` table. Commit failing.
2. **GREEN:** implement `filesystem.rs`, wire `pub mod`, re-export from root crate. Commit.
3. **REFACTOR:** keep green.

Validate against the crate's existing knowledge (Doer-Checker): the names/magics must
match what `ntfs.rs`/`gpt.rs`/etc. already encode — don't invent a second source of truth;
where a magic already exists in a sibling module, reference it, don't duplicate the bytes.

## Downstream (NOT this handoff — coordinate, do not do it here)

`forensic-vfs 0.3` will replace its `enum FsKind` with a re-export of / newtype over this
`forensicnomicon_core::FsKind`, gaining a dep on `forensicnomicon-core`. That is the
**other session's** contract crate — this handoff only lands the registry in
forensicnomicon so the redesign has something to point at. Note in the forensicnomicon
CHANGELOG that this type is intended as the source for `forensic-vfs::FsKind`.

## Scope fidelity / do-not

- **Only** add the identity registry (newtype + constants [+ optional thin detect]). Do
  NOT refactor unrelated modules, do NOT change `forensic-vfs` from here, do NOT add
  parsing/mounting logic — identity only.
- Keep `crates/core` **zero-dep** (no new external crates); the newtype is `&'static str`,
  no allocation.
- Match local conventions (read `gpt.rs`/`ntfs.rs` first). Minimal diffs.

## Release / gate

- Additive → **minor bump** `forensicnomicon` 1.6.0 → **1.7.0** (and `forensicnomicon-core`
  accordingly); it's `#[non_exhaustive]`-friendly by construction (open newtype).
- Full pre-publish gate before publishing (this crate is on crates.io + uses release-plz):
  `cargo test --workspace` · `clippy -D warnings` · `fmt --check` · `cargo deny check` ·
  100% coverage on the new module · fuzz stays green · docs build. Signed commits.
- release-plz publishes the library crates on merge to main (see the crate's
  `release-plz.toml` + `~/.claude/skills/release.md` → "release-plz").

## One-line task for the next agent

> Add an open, string-backed `FsKind` newtype + one `const` per known filesystem (ntfs,
> fat, exfat, ext, xfs, apfs, hfsplus, iso9660, udf, btrfs, zfs, ufs, refs, zip, ad1, dar)
> to `forensicnomicon-core::filesystem`, TDD, re-exported from the root crate, so
> `forensic-vfs 0.3` can retire its inconsistent named-variants+`Other` enum. Identity
> only; minor bump; full gate.
