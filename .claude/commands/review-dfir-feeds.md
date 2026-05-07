# /review-dfir-feeds

Read one unreviewed DFIR blog post from `archive/sources/pending-review.md`,
deeply comprehend it, and **implement** all artifact knowledge into the
forensicnomicon catalog via strict TDD. This is an implementation skill, not
a gap-finder. Every session produces committed Rust code.

## Core principle

**Review = implement.** If a post teaches you something about a forensic
artifact — a field schema, a registry path, a MITRE mapping, a triage
rationale, a related artifact pair — that knowledge goes into the catalog
*this session*, not a task list. The blog post is the primary source; the
descriptor is the output.

Process **one post per session**. Depth over throughput.

---

## Steps

### 1. Select the next item

Read `archive/sources/pending-review.md`. Take the **first** `- [ ]` or
`- [!]` item only.

- **`[!]` (broken URL):** Search `site:<domain> "<title>"` via WebSearch.
  If a working URL or archive.org mirror exists, update the URL and proceed.
  If genuinely dead with no mirror, mark `[x] <!-- dead link, no mirror -->` and pick the next `[ ]` item.

- **`[ ]`:** Proceed directly.

### 2. Fetch and fully read

Use `ctx_fetch_and_index(url, source="dfir-review")` to fetch the post.
Then `ctx_search` to read it completely.

For YouTube URLs (`youtube.com/watch?v=VIDEO_ID`):
```python
python -c "from scripts.fetch_all_sources import fetch_youtube_transcript; print(fetch_youtube_transcript('VIDEO_ID'))"
```

Read every word. You are a DFIR analyst ingesting primary source material.

### 3. Extract ALL artifact knowledge

For each artifact mentioned (by name, path, registry key, GUID, tool output,
or implication), extract:

| Field | What to look for |
|---|---|
| `id` | canonical artifact identifier |
| `key_path` / `file_path` | exact registry path or filesystem path |
| `value_name` | registry value name if applicable |
| `decoder` | encoding (FILETIME, DwordLe, Rot13, etc.) |
| `fields[]` | field names, types, offsets, descriptions |
| `meaning` | what this artifact proves forensically |
| `mitre_techniques` | T-numbers mentioned or implied |
| `triage_priority` | Critical/High/Medium/Low — infer from context |
| `related_artifacts` | other artifacts used together in this investigation |
| `sources` | this post's URL (must be https://) |

Ask: which artifacts does this investigation use *together*? That's the
`related` field. A post discussing ShimCache + Prefetch at the same timestamp
means each should list the other in `related_artifacts`.

### 4. Check against existing catalog

For each artifact found:

```bash
grep -r '"<artifact_id>"' src/catalog/descriptors/
grep -r '<ArtifactName>' src/lolbins.rs
```

Three outcomes:

**A. New artifact — not in catalog at all**
→ Implement with full TDD (steps 5–7 below)

**B. Existing artifact — post adds knowledge**
→ Enrich with TDD: add/correct fields, sources, MITRE, related, meaning
→ If only adding a source URL or related link (no schema change), a single
  enrichment commit is acceptable; still run full test suite

**C. Existing artifact — fully covered, nothing new**
→ Note `[x]` — no code change needed

### 5. RED — write failing tests

For **new artifacts**, add to `src/catalog/tests.rs`:

```rust
#[cfg(test)]
mod tests_<artifact_id> {
    use super::*;

    #[test]
    fn <artifact_id>_exists() {
        assert!(CATALOG.by_id("<artifact_id>").is_some());
    }

    #[test]
    fn <artifact_id>_os_scope() { /* OsScope::Windows / MacOS / Linux / All */ }

    #[test]
    fn <artifact_id>_triage_priority() { /* Critical / High / Medium / Low */ }

    #[test]
    fn <artifact_id>_has_<key_field>_field() { /* most important field */ }

    #[test]
    fn <artifact_id>_cites_source() {
        let d = CATALOG.by_id("<artifact_id>").unwrap();
        assert!(d.sources.iter().any(|s| s.contains("<domain>")));
    }

    // ... cover every field the post documents
}
```

Update the catalog count assertion in `tests.rs`:
```rust
assert_eq!(CATALOG.list().len(), <new_count>);
```

Run and confirm RED:
```bash
cargo test --lib -p forensicnomicon tests_<artifact_id> 2>&1 | grep -E "FAILED|error"
```

Commit RED:
```bash
git add src/catalog/tests.rs
git commit -m "test(RED): <artifact_id> — <one-line description>"
```

### 6. GREEN — implement the descriptor

Add the descriptor to the appropriate file in `src/catalog/descriptors/`:
- Windows registry → `windows_registry_ext*.rs`
- Windows files → `windows_files_ext.rs`
- macOS → `macos_ext.rs`
- Linux → `linux_ext.rs`
- iOS/Android → `mobile_ext.rs` (create if needed)
- EVTX channels → `windows_evtx_ext.rs`

Register it in `src/catalog/descriptors/mod.rs` `CATALOG_ENTRIES`.

Run and confirm GREEN:
```bash
cargo test --lib -p forensicnomicon tests_<artifact_id> 2>&1 | grep "test result"
cargo test --lib -p forensicnomicon 2>&1 | grep "test result"  # no regressions
```

Commit GREEN:
```bash
cargo fmt --all
git add src/catalog/descriptors/<file>.rs src/catalog/descriptors/mod.rs src/catalog/tests.rs
git commit -m "feat(GREEN): <artifact_id> — <rich description of what was added>"
```

### 7. Mark and commit pending-review.md

After all artifacts from the post are implemented:

- Mark the post `[x]` if fully implemented
- Mark `[→]` only if the post deserves a follow-up session (e.g. a multi-part
  series where only part 1 was implemented)

Update the file and commit:
```bash
git add archive/sources/pending-review.md
git commit -m "chore(feeds): mark post reviewed — <N> artifact(s) implemented"
```

Push:
```bash
git push
```

### 8. Report

Print a table:

| Artifact | Action | Tests | Triage |
|---|---|---|---|
| `<id>` | new / enriched / covered | N | Critical/High/… |

---

## Accuracy standards (from CLAUDE.md)

- Read every URL in `sources[]` before committing — do not cite without verifying
- For GUID-keyed artifacts: add `// Source: <url>` comment on the `key_path`
- `sources[]` is for researcher blogs/specs — not MITRE URLs (those go in `mitre_techniques`)
- `// Source:` comments must contain `https://` — no vendor-name stubs
- All `related_artifacts` IDs must exist in the catalog (`all_related_artifacts_exist` test enforces this)

## Rules

- Never mark `[x]` for a URL you couldn't fetch — leave `[ ]` and note the error
- Never skip TDD — RED commit before any production code, GREEN after
- Never add a `sources[]` entry without reading that URL
- One post per session — do it properly or not at all
