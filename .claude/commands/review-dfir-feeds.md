# /review-dfir-feeds

Review unreviewed DFIR blog posts from `archive/sources/pending-review.md` and
extract artifact findings for the forensicnomicon catalog.

## Steps

1. Read `archive/sources/pending-review.md` — collect all `- [ ]` and `- [!]` items
2. If none pending: report "Nothing pending" and stop
3. For each unchecked item (batch at most 10 per session):
   a. **`[!]` items (broken URL):** Before giving up, search the source domain for
      the article title using WebSearch (`site:<domain> "<title>"`). If a working
      URL is found, replace the URL in the line and treat it as a normal `[ ]` item.
      If no working URL found, mark `[x]` with a note "<!-- dead link, no mirror found -->"
      and skip fetching.
   b. **`[ ]` items:** Use `mcp__plugin_context-mode_context-mode__ctx_fetch_and_index`
      to fetch the URL
   c. Use `ctx_search` to extract:
      - Windows registry key paths containing GUIDs
      - New LOLBins / LOLBAS entries not in `src/lolbins.rs`
      - MITRE ATT&CK technique IDs
      - Forensic artifact names (UserAssist, Prefetch, MFT, etc.)
      - **Co-occurring artifact pairs** (e.g. post discusses ShimCache + Prefetch
        together → both are `related` candidates for each other's descriptor)
   d. For each finding: grep `src/catalog/descriptors/` and `src/lolbins.rs`
      to check if already covered
   e. For co-occurrences: check whether the `related` field in each descriptor
      already lists the co-occurring artifact. If not, note it as a `related`
      enrichment task (lower priority than new artifact gaps).
   f. If gap found: create a TDD task with artifact ID, key_path/file, source URL
   g. Mark item `[→]` (task created) or `[x]` (reviewed, no gaps)
4. Write updated `pending-review.md` back with checkboxes updated
5. Commit: `chore(feeds): mark N posts reviewed — M gaps found`
6. Print findings table

## Co-occurrence extraction (for `related` field enrichment)

**Use your own comprehension — not a keyword list.** You understand DFIR
artifacts in context. A keyword matcher misses "the journal" (UsnJrnl),
"the hive" (registry), "shadow copies" (VSS), and any artifact not on a
predetermined list. You catch all of these.

When reading a post, ask: which artifacts does this investigation use
*together*? That co-occurrence is what the `related` field should encode.

**For each post:**
1. Read the content and identify every forensic artifact mentioned —
   by name, path, registry key, tool output, or implication
2. Note which artifacts appear *together in the same investigation context*
   (e.g. "ShimCache and Prefetch both showed calc.exe at the same timestamp")
3. For each co-occurring pair (A, B): run
   `python -c "from scripts.backfill_archives import check_related_gaps; print(check_related_gaps('A', ['B']))"`
   to check if the link already exists in the catalog's `related` array
4. If missing: flag as a low-priority enrichment task

**For YouTube entries:** the URL is `youtube.com/watch?v=VIDEO_ID`. Run:
```
python -c "from scripts.backfill_archives import fetch_youtube_transcript; print(fetch_youtube_transcript('VIDEO_ID')[:500])"
```
This fetches the spoken transcript (via youtube-transcript-api), which
contains far more artifact signal than the HTML page. Read the transcript
and apply the same comprehension-based analysis.

The `related` field builds an investigation graph. Real cases are the
authoritative source — hardcoded lists are a poor substitute.

## Finding extraction patterns

| Look for | Example | Check against |
|---|---|---|
| Registry GUID key | `{CEBFF5CD-...}\Count` | `key_path` fields in descriptors |
| LOLBin name | `certutil.exe`, `curl` | `LOLBAS_WINDOWS` / `LOLBAS_LINUX` / `LOLBAS_MACOS` |
| ATT&CK ID | `T1547.001` | `mitre_techniques` in descriptors |
| File artifact | `$MFT`, `Prefetch`, `SRUM` | catalog by `id` / `name` |
| New GUID | not in any descriptor | new descriptor needed |

## URL status markers

| Marker | Meaning | Action |
|--------|---------|--------|
| `[ ]`  | Unreviewed | Full review — gaps + related + LOLBins + MITRE |
| `[!]`  | URL returned 404/410 at accumulation time | Search for mirror before giving up |
| `[→]`  | Reviewed — TDD task created | Skip |
| `[x]`  | Reviewed — complete | Skip |

## Rules

- Never mark `[x]` for a URL you couldn't fetch — leave `[ ]` and note the error
- For `[!]` items: try `site:<domain> "<title>"` WebSearch first; only mark `[x]` dead if no mirror found
- Every proposed task needs: artifact ID, source URL, OS scope, key_path or file_path
- All `// Source:` comments must be URLs, not vendor names
- Verify findings against actual code before creating tasks
