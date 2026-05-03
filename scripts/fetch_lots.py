#!/usr/bin/env python3
"""Fetch entries from the Living Off Trusted Sites (LOTS) project for cloud/CDN domains abused by attackers.

Source: https://lots-project.com/

Produces:
    archive/sources/lots_sites.json  — JSON array of objects with keys:
        domain   (str)   bare domain or wildcard, e.g. "raw.githubusercontent.com"
        tags     (list)  sorted, normalised list, e.g. ["C2", "Download", "Phishing"]
        provider (str)   cloud/CDN service name, e.g. "Github"

Example:
    python3 scripts/fetch_lots.py
    python3 scripts/fetch_lots.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from html import unescape
from html.parser import HTMLParser


USER_AGENT = (
    "forensic-catalog-lots-fetcher/0.1 "
    "(+https://github.com/SecurityRonin/forensic-catalog)"
)
LOTS_URL = "https://lots-project.com/"
DELAY = 0.5

# Normalisation map applied to each raw tag token.
TAG_ALIASES: dict[str, str] = {
    "c&c": "C2",
    "c2": "C2",
    "phishing": "Phishing",
    "download": "Download",
    "exfiltration": "Exfiltration",
    "exploit": "Exploit",
}


# ---------------------------------------------------------------------------
# HTML parser
# ---------------------------------------------------------------------------

class LotsTableParser(HTMLParser):
    """Extract rows from the LOTS project HTML table.

    The table structure is:
        <table>
          <thead><tr><th>Website</th><th>Tags</th><th>Service Provider</th></tr></thead>
          <tbody>
            <tr><td>domain</td><td>Tag1, Tag2</td><td>Provider</td></tr>
            ...
          </tbody>
        </table>

    We collect text from <td> cells and group them in threes.
    """

    def __init__(self) -> None:
        super().__init__()
        self._in_tbody = False
        self._in_td = False
        self._depth = 0          # nesting depth inside <td>
        self._cell_buf: list[str] = []
        self._row_cells: list[str] = []
        self.rows: list[tuple[str, str, str]] = []  # (domain, tags_raw, provider)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "tbody":
            self._in_tbody = True
        if self._in_tbody and tag == "tr":
            self._row_cells = []
        if self._in_tbody and tag == "td":
            self._in_td = True
            self._depth = 1
            self._cell_buf = []
        elif self._in_td:
            # nested element inside <td>
            self._depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "tbody":
            self._in_tbody = False
        if self._in_td:
            if tag == "td":
                self._depth -= 1
                if self._depth == 0:
                    self._in_td = False
                    cell_text = " ".join(self._cell_buf).strip()
                    cell_text = re.sub(r"\s+", " ", cell_text)
                    self._row_cells.append(cell_text)
                    if len(self._row_cells) == 3:
                        self.rows.append(
                            (self._row_cells[0], self._row_cells[1], self._row_cells[2])
                        )
                        self._row_cells = []
            else:
                self._depth -= 1

    def handle_data(self, data: str) -> None:
        if self._in_td:
            text = unescape(data)
            if text.strip():
                self._cell_buf.append(text.strip())

    def handle_entityref(self, name: str) -> None:
        if self._in_td:
            self._cell_buf.append(unescape(f"&{name};"))

    def handle_charref(self, name: str) -> None:
        if self._in_td:
            self._cell_buf.append(unescape(f"&#{name};"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fetch(url: str, *, retries: int = 1) -> bytes:
    """Fetch *url*, retrying once on failure. Raises RuntimeError on hard fail."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            last_exc = exc
            print(f"  HTTP {exc.code} fetching {url} (attempt {attempt + 1})", file=sys.stderr)
        except urllib.error.URLError as exc:
            last_exc = exc
            print(f"  URL error fetching {url}: {exc.reason} (attempt {attempt + 1})", file=sys.stderr)
        if attempt < retries:
            time.sleep(DELAY)
    raise RuntimeError(f"failed to fetch {url}: {last_exc}") from last_exc


def normalize_tags(raw: str) -> list[str]:
    """Split, alias, and sort tag tokens from a raw comma-separated string."""
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    normalised: list[str] = []
    for token in tokens:
        key = token.lower().strip()
        mapped = TAG_ALIASES.get(key)
        if mapped:
            normalised.append(mapped)
        else:
            # best-effort: title-case anything we don't recognise
            normalised.append(token.title())
    seen: set[str] = set()
    deduped: list[str] = []
    for tag in normalised:
        if tag not in seen:
            seen.add(tag)
            deduped.append(tag)
    return sorted(deduped)


def clean_domain(raw: str) -> str:
    """Strip leading asterisks/dots/spaces from a wildcard or plain domain."""
    domain = raw.strip()
    # Remove protocol prefixes occasionally present in source data
    domain = re.sub(r"^https?://", "", domain, flags=re.IGNORECASE)
    return domain


def parse_entries(html: bytes) -> list[dict]:
    """Parse the LOTS HTML page and return a list of normalised entry dicts."""
    parser = LotsTableParser()
    parser.feed(html.decode("utf-8", errors="replace"))

    entries: list[dict] = []
    for raw_domain, raw_tags, raw_provider in parser.rows:
        domain = clean_domain(raw_domain)
        if not domain:
            continue
        tags = normalize_tags(raw_tags)
        provider = raw_provider.strip()
        entries.append({"domain": domain, "tags": tags, "provider": provider})
    return entries


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the first 5 entries to stdout and exit without writing",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="output JSON path (default: archive/sources/lots_sites.json relative to this script)",
    )
    parser.add_argument(
        "--url",
        default=LOTS_URL,
        help=f"LOTS project URL (default: {LOTS_URL})",
    )
    return parser.parse_args()


def default_output_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "..", "archive", "sources", "lots_sites.json")


def main() -> int:
    args = parse_args()
    output_path = args.output or default_output_path()
    output_path = os.path.normpath(output_path)

    print(f"fetching {args.url} …", file=sys.stderr)
    try:
        html = fetch(args.url)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("parsing table …", file=sys.stderr)
    entries = parse_entries(html)

    if not entries:
        print("error: no entries fetched — site structure may have changed", file=sys.stderr)
        return 1

    print(f"fetched {len(entries)} entries", file=sys.stderr)

    if args.dry_run:
        print(json.dumps(entries[:5], indent=2, ensure_ascii=False))
        return 0

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"wrote {len(entries)} entries to {output_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
