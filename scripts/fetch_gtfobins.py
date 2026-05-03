#!/usr/bin/env python3
"""Fetch GTFOBins entries for Unix/Linux LOL binary entries.

Source:
    https://gtfobins.github.io/
    GitHub: https://github.com/GTFOBins/GTFOBins.github.io
    (YAML data: _gtfobins/<name>.md — front-matter contains function list)

Produces:
    archive/sources/gtfobins_linux.json  — JSON array of objects with keys:
        name      (str)   binary name, e.g. "curl"
        functions (list)  abuse function types, e.g. ["file-download", "shell"]
        url       (str)   canonical GTFOBins page URL

The GitHub API is used to list all _gtfobins/ files and fetch their
YAML front-matter without cloning the entire repo.

Example:
    python3 scripts/fetch_gtfobins.py
    python3 scripts/fetch_gtfobins.py --dry-run
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


USER_AGENT = (
    "forensic-catalog-gtfobins-fetcher/0.1 "
    "(+https://github.com/SecurityRonin/forensicnomicon)"
)
GITHUB_API = "https://api.github.com/repos/GTFOBins/GTFOBins.github.io"
GTFOBINS_BASE = "https://gtfobins.github.io/gtfobins"
DELAY = 0.3


def fetch(url: str, *, retries: int = 2) -> bytes:
    """Fetch URL with retries. Raises RuntimeError on hard failure."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
        },
    )
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            last_exc = exc
            # GitHub rate-limit: back off
            if isinstance(exc, urllib.error.HTTPError) and exc.code == 403:
                print("  GitHub rate-limited — sleeping 60s", file=sys.stderr)
                time.sleep(60)
            else:
                print(f"  attempt {attempt + 1}: {exc}", file=sys.stderr)
        if attempt < retries:
            time.sleep(DELAY)
    raise RuntimeError(f"failed to fetch {url}: {last_exc}") from last_exc


def list_gtfobin_names() -> list[str]:
    """Return sorted list of binary names from the _gtfobins/ directory."""
    url = f"{GITHUB_API}/contents/_gtfobins"
    raw = fetch(url)
    files = json.loads(raw.decode("utf-8"))
    names: list[str] = []
    for f in files:
        fname = f.get("name", "")
        if fname.endswith(".md"):
            names.append(fname[:-3])  # strip .md
    return sorted(names)


def parse_functions_from_frontmatter(content: str) -> list[str]:
    """Extract function list from YAML front-matter in a GTFOBins page."""
    # Front-matter is between --- delimiters
    match = re.match(r"^---\s*\n(.*?\n)---", content, re.DOTALL)
    if not match:
        return []
    yaml_block = match.group(1)
    # functions:
    # - shell
    # - file-download
    funcs: list[str] = []
    in_functions = False
    for line in yaml_block.splitlines():
        stripped = line.strip()
        if stripped == "functions:":
            in_functions = True
        elif in_functions:
            if stripped.startswith("- "):
                funcs.append(stripped[2:].strip())
            elif stripped and not stripped.startswith("#"):
                in_functions = False
    return funcs


def scrape_all(names: list[str], token: str | None = None) -> list[dict]:
    """Fetch each binary's raw page and extract functions."""
    entries: list[dict] = []
    headers: dict[str, str] = {"User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"token {token}"

    for i, name in enumerate(names):
        url = f"https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/{name}.md"
        if i > 0:
            time.sleep(DELAY)
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            print(f"  warn: skipping {name}: {exc}", file=sys.stderr)
            continue

        funcs = parse_functions_from_frontmatter(content)
        entries.append({
            "name": name,
            "functions": funcs,
            "url": f"{GTFOBINS_BASE}/{name}/",
        })
        if (i + 1) % 50 == 0:
            print(f"  scraped {i + 1}/{len(names)} …", file=sys.stderr)

    return entries


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true",
                   help="list names only (no fetch of individual pages)")
    p.add_argument("--output", default=None,
                   help="output path (default: archive/sources/gtfobins_linux.json)")
    p.add_argument("--token", default=None,
                   help="GitHub personal access token to raise rate-limit ceiling")
    return p.parse_args()


def default_output_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(
        os.path.join(script_dir, "..", "archive", "sources", "gtfobins_linux.json")
    )


def main() -> int:
    args = parse_args()
    output_path = args.output or default_output_path()

    print("fetching GTFOBins file list …", file=sys.stderr)
    try:
        names = list_gtfobin_names()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"found {len(names)} binaries", file=sys.stderr)

    if args.dry_run:
        print(json.dumps(names[:10], indent=2))
        return 0

    print("fetching individual pages …", file=sys.stderr)
    entries = scrape_all(names, token=args.token)

    if not entries:
        print("error: no entries scraped", file=sys.stderr)
        return 1

    print(f"scraped {len(entries)} entries", file=sys.stderr)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"wrote {len(entries)} entries to {output_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
