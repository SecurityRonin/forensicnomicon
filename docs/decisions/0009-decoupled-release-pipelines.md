# 0009 — Two decoupled release pipelines (libraries vs. binaries)

**Status:** Accepted

## Context

The workspace ships two very different artifacts: three **library crates** to crates.io (which
want frequent, dependency-ordered, changelog-tracked releases, especially the fast-moving data
crate) and a **CLI binary** `4n6query` (which wants cross-platform builds, installers, and a
Homebrew tap, cut deliberately). Driving both from one trigger causes a library release to
rebuild binaries and vice versa, and library-release commits can trigger their own release loop.

## Decision

Run two independent pipelines with non-overlapping triggers:

- **Libraries → release-plz**, on push to `main`. It owns crates.io publishing, per-crate
  changelogs, and dependency-ordered version bumps, cutting per-package tags
  (`forensicnomicon-core-v…`). A `release_commits` allowlist restricts releases to
  `feat|fix|perf|refactor|doc|revert` — `chore`/`ci`/`test`/`style`/`build` never release —
  which kills the changelog-churn release loop and skips release-plz's own release commits.
  `ingest` is `release = false` / `publish = false` (mirrored, cross-checked).
- **Binaries → `release.yml`**, triggered **only by a manual `v*` tag** (deliberately distinct
  from the per-package library tags, so a library release never builds binaries). It cross-builds
  `4n6query` for macOS (aarch64/x86_64), Linux musl (incl. aarch64), and Windows (MSI via
  `cargo-wix`), emits sha256 checksums, creates a GitHub Release, and dispatches to the Homebrew
  tap.

Evidence: `release-plz.toml` (`release_commits` allowlist; `ingest` release/publish false);
`.github/workflows/release-plz.yml` and `release.yml` (tag filters); the comment recording that
crates.io publishing "now lives in release-plz.yml".

## Consequences

- **+** Library releases (frequent, additive) and binary releases (deliberate, cross-platform)
  never interfere; each triggers only its own pipeline.
- **+** The commit-type allowlist prevents release loops and keeps `test`/`chore` commits (e.g.
  coverage backfill) from cutting versions.
- **+** Downstream library consumers and binary users are served on their own cadences.
- **−** Two mechanisms and two tag conventions to understand; the `publish`/`release` flags must
  stay mirrored between Cargo.toml and release-plz.toml (cross-checked, but a manual invariant).
