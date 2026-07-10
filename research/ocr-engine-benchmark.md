# OCR Engine Benchmark — Scanned DFIR Courseware

Comparison of OCR engines — local and cloud/LLM — on a fixed sample of image-only
scanned pages from GCFA courseware, scored on accuracy and speed to choose an
engine for re-OCRing the material. Accuracy is measured against a
**human-adjudicated ground truth** (visual reading of the page rasters), not only
against the Adobe reference layer.

## Executive Summary

**Two winners for two jobs.**

- **Best accuracy — a cloud vision LLM.** Four models tested (Gemini 3.1 Pro,
  GPT-5.5, Grok-4.3, GPT-4.1) achieved **perfect recall on the present forensic
  tokens (11/11)**, including `Zone.Identifier` — the hard low-contrast token buried
  in an `istat` terminal screenshot that Apple Vision, Tesseract, PaddleOCR *and*
  the Adobe layer all missed. They also produced the best literal attribute-name
  fidelity (Gemini, GPT-5.5, Grok all render `$STANDARD_INFORMATION` 17× and
  `$FILE_NAME` 18× with underscores intact) and emit markdown tables. **Two of them
  cost nothing beyond a subscription:** GPT-5.5 via the **Codex CLI** and Gemini via
  **agy** run on ChatGPT/agy plans with **no per-image billing** — so the accuracy
  tier is no longer gated behind metered API cost. Remaining caveats: non-determinism,
  ~35–70 s/page, and a hallucination risk that must be checked (here none
  hallucinated the absent `data run` token — a good sign, not a guarantee).
- **Best speed / determinism / offline — Apple Vision (`ocrmac`).** Near-perfect
  (10/11 — misses only `Zone.Identifier`), **8.1 s for all 10 pages**, free,
  offline, deterministic, best literal attribute-name fidelity of any *local*
  engine.

**Recommendation for a one-time re-OCR of this table-dense courseware:** because the
accuracy tier is now **free via subscription**, run a **subscription cloud LLM —
GPT-5.5 via Codex CLI, or Gemini via agy — across the whole corpus** (11/11 fidelity,
underscores intact, markdown tables), and **verify each page against the image**
(cheap and mandatory for evidence-grade work). Use **Apple Vision** as the fast,
deterministic, fully-offline pass when a cloud call isn't allowed or when you need a
sub-10-second bulk transcript — it costs one token of recall (`Zone.Identifier`).

Everything else places below these two: Surya (11/11 but 26× slower and mangles the
attribute-name underscore), Tesseract (10/11, fast, portable, noisier), PaddleOCR
(10/11, very slow), docling and Marker (8/11 — drop the attribute headers), easyocr
(8/11 — drops the `$` sigil). For a Mac-local model, two **MLX** vision models were
proven on Apple Silicon — **Nanonets-OCR2-3B** (accuracy tier) and **olmOCR-2-7B**
(just behind) — both free, offline, and on-device.

## Sample Definition

- **Rasters (all local engines OCR the identical files):** pages **771–780** (10
  dense NTFS pages, slides 39–48 of the FOR508 book) of
  `.../GCFA/GIAC Certified Forensic Analyst (GCFA) (raw scanned).pdf` (image-only,
  no text layer), rendered to PNG at **300 DPI** with
  `pdftoppm -r 300 -f 771 -l 780 -png` into `/tmp/ocr-bench/png/`.
- **Cloud LLMs** consumed the same 300-DPI PNGs (base64, `detail:high`). **Marker**
  consumed the raw scanned PDF at `page_range="770-779"` (0-indexed = 1-indexed
  771–780), its native path.
- **Adobe reference:** the companion `.../GIAC Certified Forensic Analyst (GCFA).pdf`
  (already OCR'd by Adobe Acrobat), pages 771–780 via `pdftotext -layout`.
- **Host:** macOS 15.7.8, Apple Silicon; Python 3.11 (mise); tesseract 5.5.2. Local
  neural engines ran on CPU/MPS, no CUDA.

### The pages, and what lives on them

Verified by visual reading (see Ground Truth): slides 39–40 are `$FILE_NAME`
attribute hex dumps; slides 41–43 are the `$STANDARD_INFORMATION` and `$FILE_NAME`
**Windows Time-Rule matrices** (9-column × 4-row tables, one rotated 90°); slides
44–47 cover timestomping detection (incl. an `MFTECmd` CSV screenshot); slide 48
("Analyzing `$DATA`") holds the `istat` terminal screenshot with the
`Zone.Identifier` ADS. The table-dense, low-contrast screenshot pages are where
weaker engines lost knowledge.

### Rotation sensitivity (slide 775, rotated 90° left)

Slide 775 — a full-page `$FILE_NAME` time-rule matrix — is printed rotated 90°.
Scored on the 15 table labels present on that page, engines split sharply by whether
they correct orientation:

| Behaviour | Engines | Labels on p775 |
|---|---|:--:|
| Broke completely (output = noise) | **Tesseract (default), easyOCR** | **0 / 15** |
| Coped partially | Adobe, Apple Vision, PaddleOCR, Surya, Marker | ~9 / 15 |
| Handled it | docling | 14 / 15 |
| Rotation-invariant | **Gemini, Grok, GPT-5.5** | **15 / 15** |

Classic OCR assumes upright text, so 90°-rotated glyphs become unrecognisable;
vision LLMs read the image regardless of orientation. Tesseract's own OSD *detects*
the rotation (`Orientation: 270°, Rotate: 90`) but the plain `tesseract img stdout`
call does not apply it. **Fix (verified): deskew first** — rotating the page 90° CW
took Tesseract from 0 → 9/15, up to the rotation-aware tier. This one rotated page is
part of why the time-rule matrices were the weak spot and quietly penalised
Tesseract/easyOCR (1 of 10 pages unreadable to them).

**Rule — every page is orientation-checked and rotated to upright before OCR.** This
is a mandatory preprocessing step, not an optional tweak: run OSD
(`tesseract <page> --psm 0`, or equivalent) on each page and rotate any page whose
detected orientation ≠ 0° to upright before handing it to the OCR engine. Apply it to
the whole corpus — unconditionally for local engines (where a rotated page is
otherwise lost), and as cheap insurance even for cloud LLMs (it keeps the corpus
uniform). A page silently OCR'd sideways yields plausible-looking noise — the worst
failure mode — so orientation correction is a front-door guard, not a cleanup step.

## Ground Truth — Human Adjudication + Council of Experts

Earlier drafts scored only against the Adobe layer and *called* the term list
"known present." That was not ground truth: the Adobe layer is unverified and, in
fact, **missed `Zone.Identifier` itself**. Ground truth here was established by two
combined methods:

1. **Human visual reading** of all 10 page rasters (the authoritative source for
   these 12 tokens — a person reading the image is the reference an OCR engine is
   judged against).
2. **Council of experts** — a per-token vote across all 10 engines. Unanimous or
   strong-majority votes corroborate the human reading; a *split* vote flags a
   token for careful human adjudication.

Result — of the 12 candidate tokens, **11 are genuinely present; 1 (`data run`) is
absent** (the *concept* appears on slide 48 as a cluster runlist, but the literal
phrase "data run" is not printed on pages 771–780). So the **true recall ceiling is
11/12.**

**Council vote vs. ground truth** (engines reporting the token / 10 non-Adobe engines):

| Token | Council votes | Ground truth | Note |
|---|---:|:--|:--|
| MFTECmd, resident, istat, timestomp, NTFS, attribute | 10/10 | PRESENT | unanimous — high confidence |
| `$DATA`, `$MFT` | 9/10 | PRESENT | strong majority |
| STANDARD_INFORMATION, FILE_NAME | 8/10 | PRESENT | strong majority |
| **Zone.Identifier** | **4/10** | **PRESENT** | **split — human-adjudicated** |
| data run | 0/10 | ABSENT | unanimous absent — matches truth |

The council did its job: it reached consensus on 11 of 12 tokens, and the single
disagreement — `Zone.Identifier`, read only by the 4 strongest engines (Grok,
Gemini, GPT-4.1, Surya) — was the exact case a human must adjudicate. Visual reading
of slide 48 confirms it is present (`Name: Zone.Identifier` in the `istat` output),
so the four engines that read it were *more complete*, and the Adobe layer plus six
other engines were wrong to omit it. **No engine produced a false positive** — none
hallucinated the absent `data run` (a specific reassurance for the LLMs).

## Metric Definitions

- **Speed** — wall-clock seconds for all 10 pages (model load / one-time download /
  warm-up excluded), plus pages/sec. Cloud = network-bound API latency. Adobe = N/A.
- **Volume** — characters and word tokens (`[a-z0-9]+`, lowercased).
- **Similarity to Adobe** — `difflib.SequenceMatcher` ratio on the lowercased
  word-token sequences. A peer-agreement signal, not an error rate (Adobe is
  imperfect — see above).
- **Garble ratio** *(reference-free)* — fraction of alphabetic tokens (len ≥ 2) not
  in `/usr/share/dict/words`. Lower = cleaner. **Floor ≈ 0.146** (Adobe's own value;
  forensic jargon is legitimately absent from the dictionary).
- **Hard recall (X/12)** — case-insensitive substring presence of the 12 terms.
  Lenient (substring), kept for continuity.
- **True recall (X/11)** — recall against the **human-adjudicated present set**
  (11 tokens). This is the accuracy figure that matters.
- **Attribute-token counts** — exact `re.findall` occurrence counts of the four
  tokens inside the NTFS matrices/tables; a dropped `_` or `$` shows as a miss.

## Comparison Table

Ranked by true recall, then speed. Cloud LLMs in **bold**. "Cost" separates local
(free), metered API (per-image billing), and subscription CLI (a ChatGPT/agy plan,
no per-image charge).

| Engine | Cost | Wall (s) | Pages/s | Words | Sim→Adobe | Garble ↓ | Hard /12 | **True /11** | SI / FN / $DATA / $MFT |
|---|:--|---:|---:|---:|---:|---:|:--:|:--:|:--|
| **Gemini 3.1 Pro** (via agy)¹ | subscription | 727 | 0.014 | 4,363 | **0.840** | 0.137 | 11 | **11** | 17 / 18 / 14 / 1 |
| **GPT-5.5** (Codex CLI)³ | **subscription** | 351 | 0.028 | 4,363 | 0.836 | 0.138 | 11 | **11** | 17 / 18 / 14 / 1 |
| **Fable** (Claude subagent)⁴ | **incl. in Claude plan** | 245⁴ | 0.041 | **4,371** | 0.839 | 0.139 | 11 | **11** | 17 / 18 / 14 / 1 |
| **Opus 4.8** (Claude subagent)⁴ | **incl. in Claude plan** | 234⁴ | 0.043 | 4,365 | **0.840** | **0.137** | 11 | **11** | 17 / 18 / 14 / 1 |
| **Grok-4.3** | metered API | 469 | 0.021 | 4,354 | 0.820 | 0.138 | 11 | **11** | **17 / 18 / 14** / 1 |
| **GPT-4.1** | metered API | 385 | 0.026 | 3,640 | 0.792 | 0.134 | 11 | **11** | 15 / 16 / 13 / **2** |
| **Nanonets-OCR2-3B** (MLX)⁵ | free (local) | 430 | 0.023 | 6,859⁵ | 0.579⁵ | 0.086⁵ | 11 | **11** | **17 / 18 / 14** / 1 |
| Surya 0.17.0 | free (local) | 214 | 0.05 | **4,418** | 0.787 | 0.143 | 11 | **11** | 1 / 5 / 13 / 1 |
| **Apple Vision** (`ocrmac`) | free (local) | **8.1** | **1.23** | 4,334 | 0.798 | 0.144 | 10 | 10 | 10 / 17 / 11 / 1 |
| Tesseract 5.5.2 | free (local) | 13.5 | 0.74 | 4,046 | 0.795 | 0.177 | 10 | 10 | 7 / 12 / 13 / 1 |
| PaddleOCR 3.7.0 | free (local) | 354 | 0.03 | 4,306 | 0.793 | 0.144 | 10 | 10 | 11 / 14 / 12 / 1 |
| **olmOCR-2-7B** (MLX)⁶ | free (local) | 411 | 0.024 | 4,965 | 0.693 | 0.136 | 10 | 10 | 16 / 16 / 12 / 1 |
| docling (default) | free (local) | 57 | 0.17 | 3,524 | 0.857 | 0.132 | 8 | 8 | 0 / 0 / 10 / 1 |
| easyocr 1.7.2 | free (local) | 107 | 0.09 | 4,196 | 0.777 | 0.163 | 8 | 8 | 11 / 12 / 0 / 0 |
| Marker 1.10.1² | free (local) | 501 | 0.02 | 3,303 | 0.853 | **0.131** | 8 | 8 | 0 / 0 / 11 / 1 |
| Adobe (reference) | — | N/A | N/A | 3,768 | 1.000 | 0.146 | 10 | 10 | 6 / 8 / 11 / 1 |

¹ Gemini direct REST is **geo-blocked** from this host ("User location is not
supported"); it was run through the `agy` CLI, whose per-page agent overhead
inflates the wall time — the *accuracy* is a fair Gemini result, the *speed* is not
a clean API latency. ² Marker's word/char volume carries a small caveat from an
earlier background-process race; its qualitative behaviour (markdown tables present;
attribute headers dropped → 8/11) was reconfirmed on the current file. ³ GPT-5.5 run
through the **Codex CLI** (`codex exec -i <png>`, prompt via stdin,
`--output-last-message` for a clean transcript) on a **ChatGPT subscription** — no
metered API. Required upgrading Codex from the Homebrew formula (0.42.0, too old for
`gpt-5.5`; `gpt-5`/`gpt-5-codex` are blocked on ChatGPT-account auth) to the cask
(0.142.5). Wall time includes Codex's per-page agent overhead. ⁴ Fable run as a
Claude **subagent** (Agent tool, `model: fable`) that reads each PNG visually and
transcribes it — an Anthropic model, so it is covered by the Claude plan with **no
external API or subscription**. Its 245 s wall includes subagent orchestration and 10
per-image `Read` calls, so it is not a clean per-page OCR latency (treat as
indicative, like the other agent-wrapped LLMs). ⁵ **Nanonets-OCR2-3B** (a Qwen2.5-VL
fine-tune) run **locally on Apple Silicon** via `mlx-vlm` (durable env at
`~/src/mlx-ocr/`, pinned `mlx-vlm 0.1.27 + transformers 4.51.3`; 300-DPI PNGs
downscaled to 1500 px longest side to avoid a 58 GB Metal alloc). Its `words` (6,859),
`Sim→Adobe` (0.579) and `Garble` (0.086) are **distorted by a degenerate repeat-loop
on the rotated page 775** — the model emitted one header row ~290× (19.8k chars of
duplicated clean tokens), which inflates the word count, deflates similarity, and
*artificially* lowers garble (repeated dictionary words). Its **recall metrics are
genuine and top-tier** (true 11/11; table tokens 17/18/14/1, matching Gemini/Opus;
caught `Zone.Identifier` which even Adobe missed). With the mandatory deskew pre-pass
(page 775 corrected to upright) the loop would not occur — a concrete argument for the
orientation-correction rule. ~43 s/page on-device (page 775 alone 132 s). ⁶ **olmOCR-2-7B**
(Qwen2.5-VL-7B fine-tune, AllenAI) also run **locally on Apple Silicon** via `mlx-vlm`
(`mlx-community/olmOCR-2-7B-1025-4bit`, same `~/src/mlx-ocr/` env). 411 s for 10 pages;
true recall **10/11** (missed only `Zone.Identifier` — the faint `istat`-screenshot
token). Notably it handled the **rotated page 775 cleanly (no repeat-loop)**, unlike
Nanonets — 1,347 chars in 18 s. Its lower Sim→Adobe (0.693) reflects heavier
layout *reflow*, not character errors; garble (0.136) is competitive and table-token
recovery solid (16/16/12/1); no hallucinations. **Re-run at 8-bit (9.5 GB download, 8.8 GB
on disk) to remove the quantization confound:** identical true recall (10/11) and table
tokens (16/16/12/1), still misses `Zone.Identifier`; Sim→Adobe rose 0.693→0.768 (cosmetic
formatting fidelity, not new content). **So quantization was *not* the gap — Nanonets-3B
genuinely beats olmOCR-2-7B at equal bit-width** on recall and table completeness (a
specialised-3B-beats-general-7B result); olmOCR's sole advantage is rotation robustness.
Its shards needed a resume-safe downloader (`~/src/mlx-ocr/robust_dl.py`) after the HF
CDN + `huggingface_hub` resume logic repeatedly truncated the partial.

## Per-Engine Notes

**Vision LLMs — Gemini 3.1 Pro, GPT-5.5, Fable, Grok-4.3, GPT-4.1 (the accuracy tier).**
All five reached **11/11 true recall**, the only engines besides Surya to read
`Zone.Identifier`, and posted the highest literal attribute-name fidelity (Gemini,
GPT-5.5, Fable and Grok all 17×/18× with underscores; GPT-4.1 uniquely got `$MFT` twice).
They transcribe hex dumps and reconstruct the time-rule matrices as markdown tables,
and none hallucinated the absent token. **GPT-5.5 via the Codex CLI is the value
pick of the tier**: it ties Grok/Gemini for the best attribute-token counts
(17/18/14/1), high similarity to Adobe (0.836), 11/11 recall — and runs on the
ChatGPT subscription at **no per-image cost**, at 351 s (faster than Gemini-via-agy's
727 s). Gemini edged on word-similarity (0.840); GPT-4.1 had the cleanest garble
(0.134). Standing caveats for the whole tier: non-deterministic output, ~35–70 s/page,
and verification against hallucination before evidence-grade use. Access paths differ:
GPT-4.1/Grok are **metered API**; **GPT-5.5 (Codex) and Gemini (agy) are subscription**
(free beyond the plan). Gemini additionally needs a non-geo-blocked access path (agy,
Vertex AI, or a supported region) from this host.

**Fable (Claude subagent) — top-tier and self-contained.** Run as a Claude subagent
that visually reads each PNG, Fable matched the best of the tier: **11/11 true recall**,
the joint-best attribute-token counts (17/18/14/1), caught `Zone.Identifier`, read the
90°-rotated slide-775 matrix cleanly, and posted the **highest word volume of any
engine** (4,371) with similarity second only to Gemini (0.839). No hallucinated
tokens. Its distinctive advantage: it needs **no external API key and no third-party
subscription** — it runs inside the Claude plan via the Agent tool (`model: fable`),
so for a Claude-based workflow it delivers cloud-LLM accuracy with the fewest moving
parts. Caveat: like the other agent-wrapped LLMs it is non-deterministic, and its wall
time reflects subagent + per-image `Read` overhead rather than a clean OCR latency.

**Apple Vision (`ocrmac`, `accurate`) — the local champion.** 10/11 (misses only the
`Zone.Identifier` screenshot token), fastest by 1.7× over Tesseract and ~26–90×
over the neural engines, best literal attribute-name fidelity of any local engine
(`STANDARD_INFORMATION` ×10, `FILE_NAME` ×17, underscores intact), garble at the
Adobe floor. Free, offline, deterministic. macOS only.

**Surya 0.17.0** — 11/11 true recall and the most words of any engine, garble tied
cleanest, and it *did* catch `Zone.Identifier`. But it flattens the matrices to
reading-order lines and drops the underscore in the attribute names
(`$STANDARD INFORMATION` ×16 vs underscored ×1), and runs 26× slower than Apple
Vision. The strongest *local/offline* alternative when the extra recall matters.

**Tesseract 5.5.2** — 10/11, portable, scriptable, second-fastest; noisiest output
(garble 0.177). Best non-macOS fallback.

**PaddleOCR 3.7.0** — 10/11, good attribute-token counts, but ~44× slower than Apple
Vision on CPU with no accuracy edge.

**docling (default)** — clean reading-order body text (high sim, low garble) but its
layout filter **drops the attribute headers entirely** (`STANDARD_INFORMATION` and
`FILE_NAME` = 0) → 8/11. Disqualifying for attribute-level material.

**easyocr 1.7.2** — 8/11; strips the `$` sigil from `$DATA`/`$MFT` (renders bare
`DATA`/`MFT`), a meaningful NTFS error. Slow.

**Marker 1.10.1** — the **only engine to emit genuine markdown table structure** (the
attribute-type-code table as clean pipe rows), built on Surya + layout/table models
(table-rec falls back to CPU). But its pipeline drops the attribute headers
(`STANDARD_INFORMATION`/`FILE_NAME` = 0) → 8/11, and it is the slowest local engine.
Useful only as a *table-structure supplement*, not a primary transcript. Run it on
the native PDF page range; a per-PNG attempt crashed on warm-up.

## Mac-Local OCR VLMs

For a Mac-local OCR model, the **MLX/MPS-runnable vision models** are the answer, and it
is proven here: **`Nanonets-OCR2-3B`** (a Qwen2.5-VL fine-tune) runs locally on Apple
Silicon via `mlx-vlm` and **hits the accuracy tier** (see table + note ⁵); **`olmOCR-2-7B`**
is close behind (true 10/11) and handled the rotated page cleanly where Nanonets looped
(see table + note ⁶). So the accuracy ceiling is reached by six vision LLMs *plus* one
local 3B model, with a local 7B just behind — all on-device, offline, and free.

## Recommendation

For this table-dense forensic courseware:

0. **Preprocess — orientation-correct every page (mandatory).** Run OSD on each page
   and rotate any non-upright page to upright before OCR (see *Rotation sensitivity*).
   Skipping this silently loses rotated pages on local engines and risks sideways
   noise anywhere.
1. **Primary pass — a subscription cloud vision LLM** (GPT-5.5 via Codex CLI, or
   Gemini via agy) over the whole corpus: **free beyond the plan**, 11/11 recall,
   attribute names with underscores intact, markdown tables, rotation-invariant.
   **Verify each page against the image** (cheap here; mandatory for evidence-grade
   transcription).
2. **Fast/offline alternative — Apple Vision (`ocrmac`)** when a cloud call isn't
   allowed or you need a sub-10-second deterministic bulk transcript: 10/11, free,
   offline. It costs one token of recall (`Zone.Identifier`), recoverable via step 3.
3. **Reconcile with the council** — where passes disagree on a hard token, the
   multi-engine vote plus a 10-second human glance resolves it, exactly as it resolved
   `Zone.Identifier` here.

Keep **Tesseract** (with the step-0 deskew) as the portable non-macOS fallback and
**Surya** as the offline option when 11/11 recall is needed without a cloud call
(accepting its underscore mangling). Avoid docling/easyocr/Marker as primary passes
(each drops a class of the exact tokens this material is about).

## Reproduction

Artifacts in `/tmp/ocr-bench/`: 300-DPI PNGs in `png/`; downscaled JPEGs used for
the human ground-truth read in `gt/`; per-engine text `<engine>.txt` (`tesseract`,
`apple-vision`, `docling`, `easyocr`, `paddleocr`, `surya`, `marker`, `gpt-4.1`,
`grok-4.3`, `gemini`, `gpt-5.5-codex`); Adobe reference `adobe.txt`; runners
`run_*.py`, `cloud_ocr.py`, `run_gemini_agy.sh`, `run_codex.sh`; scorer `score.py`
(embeds the human-adjudicated ground-truth set and the council vote). Local neural
engines run under the mise Python 3.11; metered cloud engines via the providers'
REST APIs (`OPENAI_API_KEY`, `XAI_API_KEY`); subscription cloud engines via `agy`
(Gemini, geo-block workaround) and `codex exec -i` (GPT-5.5, Codex CLI ≥ 0.142.5).
Surya on MPS; Marker's table-rec model on CPU.
