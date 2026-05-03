#!/usr/bin/env python3
"""Fetch entries from filesec.io for file extensions exploited by attackers.

Source: https://filesec.io/

For each extension listed on the index page the script follows the detail
page at https://filesec.io/<ext>/ and collects:

    extension     (str)   e.g. ".bat"
    functions     (list)  e.g. ["Executable", "Script"]
    os            (list)  e.g. ["Windows"]
    description   (str)   prose description from the detail page
    recommendation(str)   analyst guidance from the detail page
    resources     (list)  href URLs from the Resources section

Output:
    archive/sources/filesec_extensions.json

Example:
    python3 scripts/fetch_filesec.py
    python3 scripts/fetch_filesec.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html import unescape
from html.parser import HTMLParser


USER_AGENT = (
    "forensic-catalog-filesec-fetcher/0.1 "
    "(+https://github.com/SecurityRonin/forensic-catalog)"
)
BASE_URL = "https://filesec.io/"
DELAY = 0.5


# ---------------------------------------------------------------------------
# HTML parsers
# ---------------------------------------------------------------------------

class IndexTableParser(HTMLParser):
    """Parse the filesec.io index page.

    The index contains a table (or card list) with columns:
        Extension | Function tags | OS

    Each extension cell contains a link to the detail page.
    We collect (extension_text, detail_href, functions_raw, os_raw) per row.
    """

    def __init__(self) -> None:
        super().__init__()
        self._in_table = False
        self._in_thead = False
        self._in_tbody = False
        self._in_tr = False
        self._in_td = False
        self._in_link = False
        self._td_index = 0
        self._cell_buf: list[str] = []
        self._row: list[str] = []
        self._current_href = ""
        self._row_href = ""
        # results: list of (extension, href, functions_raw, os_raw)
        self.rows: list[tuple[str, str, str, str]] = []

    # --- tag handlers -------------------------------------------------------

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        amap = {k: (v or "") for k, v in attrs}
        if tag == "table":
            self._in_table = True
        if tag == "thead":
            self._in_thead = True
        if tag == "tbody":
            self._in_tbody = True
        if self._in_tbody and tag == "tr":
            self._in_tr = True
            self._row = []
            self._row_href = ""
            self._td_index = 0
        if self._in_tr and tag == "td":
            self._in_td = True
            self._cell_buf = []
        if self._in_td and tag == "a":
            href = amap.get("href", "")
            if href and not self._row_href:
                self._row_href = href
            self._in_link = True
        # treat <br> as whitespace separator
        if self._in_td and tag == "br":
            self._cell_buf.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag == "table":
            self._in_table = False
        if tag == "thead":
            self._in_thead = False
        if tag == "tbody":
            self._in_tbody = False
        if self._in_tr and tag == "tr":
            self._in_tr = False
            if len(self._row) >= 3:
                self.rows.append(
                    (self._row[0], self._row_href, self._row[1], self._row[2])
                )
        if self._in_td and tag == "td":
            self._in_td = False
            cell = re.sub(r"\s+", " ", " ".join(self._cell_buf)).strip()
            self._row.append(cell)
            self._td_index += 1
        if self._in_link and tag == "a":
            self._in_link = False

    def handle_data(self, data: str) -> None:
        if self._in_td:
            self._cell_buf.append(unescape(data))


class DetailPageParser(HTMLParser):
    """Parse a filesec.io detail page, e.g. https://filesec.io/bat/.

    The page structure (as of 2025) is roughly:
        <h1 class="...">Extension name</h1>
        <p>Description paragraph(s)</p>
        <h2>Recommendation</h2>
        <p>Recommendation paragraph(s)</p>
        <h2>Resources</h2>
        <ul><li><a href="...">...</a></li></ul>

    We collect description text (paragraphs before the first h2), the
    recommendation text (paragraphs after "Recommendation" h2), and resource
    hrefs (links after "Resources" h2).
    """

    def __init__(self) -> None:
        super().__init__()
        self._section = "preamble"   # preamble | description | recommendation | resources
        self._in_p = False
        self._in_a = False
        self._in_h1 = False
        self._in_h2 = False
        self._buf: list[str] = []

        self.extension_name = ""
        self._desc_parts: list[str] = []
        self._rec_parts: list[str] = []
        self.resources: list[str] = []

    # --- internal helpers ---------------------------------------------------

    def _flush_buf(self) -> str:
        text = re.sub(r"\s+", " ", " ".join(self._buf)).strip()
        self._buf = []
        return text

    # --- tag handlers -------------------------------------------------------

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        amap = {k: (v or "") for k, v in attrs}
        if tag == "h1":
            self._in_h1 = True
            self._buf = []
        if tag == "h2":
            self._in_h2 = True
            self._buf = []
        if tag == "p":
            self._in_p = True
            self._buf = []
        if tag == "a":
            href = amap.get("href", "")
            if self._section == "resources" and href.startswith("http"):
                self.resources.append(href)
            self._in_a = True
        if tag == "br":
            self._buf.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag == "h1":
            self._in_h1 = False
            name = self._flush_buf()
            if name and not self.extension_name:
                self.extension_name = name
            self._section = "description"
        if tag == "h2":
            self._in_h2 = False
            heading = self._flush_buf().lower()
            if "recommend" in heading:
                self._section = "recommendation"
            elif "resource" in heading:
                self._section = "resources"
            else:
                # any other h2 ends description section
                self._section = "other"
        if tag == "p":
            self._in_p = False
            text = self._flush_buf()
            if not text:
                return
            if self._section == "description":
                self._desc_parts.append(text)
            elif self._section == "recommendation":
                self._rec_parts.append(text)
        if tag == "a":
            self._in_a = False

    def handle_data(self, data: str) -> None:
        if self._in_h1 or self._in_h2 or self._in_p or self._in_a:
            self._buf.append(unescape(data))

    # --- result properties --------------------------------------------------

    @property
    def description(self) -> str:
        return " ".join(self._desc_parts).strip()

    @property
    def recommendation(self) -> str:
        return " ".join(self._rec_parts).strip()


# ---------------------------------------------------------------------------
# Tag / OS normalisation
# ---------------------------------------------------------------------------

FUNCTION_ALIASES: dict[str, str] = {
    "executable": "Executable",
    "script": "Script",
    "phishing": "Phishing",
    "double click": "Double Click",
    "doubleclick": "Double Click",
    "macros": "Macros",
    "macro": "Macros",
    "file archiver": "File Archiver",
    "archiver": "File Archiver",
    "exploit": "Exploit",
}

OS_ALIASES: dict[str, str] = {
    "windows": "Windows",
    "win": "Windows",
    "mac": "Mac",
    "macos": "Mac",
    "osx": "Mac",
    "linux": "Linux",
}


def split_pipe_or_comma(raw: str) -> list[str]:
    """Split on pipes, commas, slashes, or newlines; strip whitespace."""
    return [t.strip() for t in re.split(r"[|,/\n]+", raw) if t.strip()]


def normalise_functions(raw: str) -> list[str]:
    tokens = split_pipe_or_comma(raw)
    result: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        key = token.lower()
        mapped = FUNCTION_ALIASES.get(key, token.title())
        if mapped not in seen:
            seen.add(mapped)
            result.append(mapped)
    return sorted(result)


def normalise_os(raw: str) -> list[str]:
    tokens = split_pipe_or_comma(raw)
    result: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        key = token.lower()
        mapped = OS_ALIASES.get(key, token.title())
        if mapped not in seen:
            seen.add(mapped)
            result.append(mapped)
    return sorted(result)


def normalise_extension(raw: str) -> str:
    """Ensure extension starts with a dot and is lower-case."""
    ext = raw.strip().lower()
    if ext and not ext.startswith("."):
        ext = "." + ext
    return ext


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def fetch(url: str, *, retries: int = 1) -> bytes:
    """Fetch *url*, retrying once on transient failure."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            last_exc = exc
            print(
                f"  HTTP {exc.code} fetching {url} (attempt {attempt + 1})",
                file=sys.stderr,
            )
        except urllib.error.URLError as exc:
            last_exc = exc
            print(
                f"  URL error fetching {url}: {exc.reason} (attempt {attempt + 1})",
                file=sys.stderr,
            )
        if attempt < retries:
            time.sleep(DELAY)
    raise RuntimeError(f"failed to fetch {url}: {last_exc}") from last_exc


# ---------------------------------------------------------------------------
# Scraping logic
# ---------------------------------------------------------------------------

def parse_index(html: bytes, base_url: str) -> list[dict]:
    """Return list of stub dicts with extension, functions, os, detail_url."""
    parser = IndexTableParser()
    parser.feed(html.decode("utf-8", errors="replace"))

    stubs: list[dict] = []
    for raw_ext, raw_href, raw_functions, raw_os in parser.rows:
        extension = normalise_extension(raw_ext)
        if not extension or extension == ".":
            continue
        # Build absolute detail URL
        if raw_href:
            detail_url = urllib.parse.urljoin(base_url, raw_href)
        else:
            # Fall back: derive from extension text (strip leading dot)
            slug = extension.lstrip(".")
            detail_url = urllib.parse.urljoin(base_url, f"/{slug}/")
        stubs.append(
            {
                "extension": extension,
                "functions": normalise_functions(raw_functions),
                "os": normalise_os(raw_os),
                "detail_url": detail_url,
            }
        )
    return stubs


def scrape_detail(url: str) -> tuple[str, str, list[str]]:
    """Fetch and parse a detail page.  Returns (description, recommendation, resources)."""
    try:
        html = fetch(url)
    except RuntimeError as exc:
        print(f"  skipping detail {url}: {exc}", file=sys.stderr)
        return "", "", []
    time.sleep(DELAY)
    parser = DetailPageParser()
    parser.feed(html.decode("utf-8", errors="replace"))
    return parser.description, parser.recommendation, parser.resources


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="fetch index only, then print the first 5 entries and exit without writing",
    )
    p.add_argument(
        "--output",
        default=None,
        help="output JSON path (default: archive/sources/filesec_extensions.json)",
    )
    p.add_argument(
        "--url",
        default=BASE_URL,
        help=f"filesec.io base URL (default: {BASE_URL})",
    )
    return p.parse_args()


def default_output_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "..", "archive", "sources", "filesec_extensions.json")


def main() -> int:
    args = parse_args()
    output_path = args.output or default_output_path()
    output_path = os.path.normpath(output_path)

    print(f"fetching index {args.url} …", file=sys.stderr)
    try:
        index_html = fetch(args.url)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    time.sleep(DELAY)

    stubs = parse_index(index_html, args.url)
    if not stubs:
        print(
            "error: no extensions parsed from index — site structure may have changed",
            file=sys.stderr,
        )
        return 1

    print(f"found {len(stubs)} extensions in index", file=sys.stderr)

    if args.dry_run:
        # For dry-run, fetch detail pages for the first 5 only.
        sample = stubs[:5]
        entries: list[dict] = []
        for i, stub in enumerate(sample, start=1):
            print(
                f"  [{i}/{len(sample)}] fetching detail for {stub['extension']} …",
                file=sys.stderr,
            )
            desc, rec, resources = scrape_detail(stub["detail_url"])
            entry = {
                "extension": stub["extension"],
                "functions": stub["functions"],
                "os": stub["os"],
                "description": desc,
                "recommendation": rec,
                "resources": resources,
            }
            entries.append(entry)
        print(json.dumps(entries, indent=2, ensure_ascii=False))
        return 0

    # Full fetch.
    entries = []
    total = len(stubs)
    for i, stub in enumerate(stubs, start=1):
        print(
            f"  [{i}/{total}] fetching detail for {stub['extension']} …",
            file=sys.stderr,
        )
        desc, rec, resources = scrape_detail(stub["detail_url"])
        entry = {
            "extension": stub["extension"],
            "functions": stub["functions"],
            "os": stub["os"],
            "description": desc,
            "recommendation": rec,
            "resources": resources,
        }
        entries.append(entry)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"wrote {len(entries)} entries to {output_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
