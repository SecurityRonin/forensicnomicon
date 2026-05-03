#!/usr/bin/env python3
"""Fetch entries from the LOFL Project for Windows Living Off Foreign Land binary entries.

Source:
    https://lofl-project.github.io/
    GitHub: https://github.com/lofl-project/lofl-project.github.io

The LOFL Project catalogs binaries from legitimate third-party tools (Sysinternals,
vendor CLIs, cloud agents) that are abused in post-exploitation just like built-in
LOLBins — the key distinction is that they are not shipped with Windows itself.

Produces:
    archive/sources/lofl_windows.json  — JSON array of objects with keys:
        name          (str)   binary name, e.g. "psexec.exe"
        description   (str)   one-line abuse summary
        mitre         (list)  ATT&CK technique IDs
        url           (str)   canonical LOFL page URL

Strategy: reads the LOFL project's _lofl/ YAML directory via the GitHub API
(same pattern as LOOBins fetch script).

Example:
    python3 scripts/fetch_lofl.py
    python3 scripts/fetch_lofl.py --dry-run
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
    "forensic-catalog-lofl-fetcher/0.1 "
    "(+https://github.com/SecurityRonin/forensicnomicon)"
)
GITHUB_OWNER = "lofl-project"
GITHUB_REPO = "lofl-project.github.io"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}"
LOFL_BASE = "https://lofl-project.github.io"
DELAY = 0.4

# The LOFL repo may store YAML under _lofl/ or _data/ — try both
CANDIDATE_DIRS = ["_lofl", "_data/lofl", "data"]


def fetch(url: str, *, retries: int = 2) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
    )
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            last_exc = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code == 403:
                print("  rate-limited — sleeping 60s", file=sys.stderr)
                time.sleep(60)
            else:
                print(f"  attempt {attempt + 1}: {exc}", file=sys.stderr)
        if attempt < retries:
            time.sleep(DELAY)
    raise RuntimeError(f"failed to fetch {url}: {last_exc}") from last_exc


def find_yaml_dir() -> tuple[str, list[str]]:
    """Probe candidate directories; return (path, [filenames])."""
    for candidate in CANDIDATE_DIRS:
        url = f"{GITHUB_API}/contents/{candidate}"
        try:
            raw = fetch(url, retries=1)
            files = json.loads(raw.decode())
            if isinstance(files, list):
                yamls = [f["name"] for f in files if f.get("name", "").endswith((".yml", ".yaml"))]
                if yamls:
                    return candidate, sorted(yamls)
        except RuntimeError:
            pass
    raise RuntimeError(
        f"could not locate YAML directory in {GITHUB_OWNER}/{GITHUB_REPO}; "
        "check CANDIDATE_DIRS or inspect repo structure manually"
    )


def parse_entry_yaml(text: str, fname: str) -> dict:
    """Extract fields from LOFL YAML (stdlib regex, no yaml dependency)."""
    def scalar(key: str) -> str:
        m = re.search(rf"^{key}:\s*(.+)", text, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip().strip("\"'") if m else ""

    name = scalar("Name") or scalar("name") or fname.replace(".yml", "").replace(".yaml", "")
    description = scalar("Description") or scalar("description")
    mitre = re.findall(r"T\d{4}(?:\.\d{3})?", text)
    # Deduplicate preserving order
    seen: set[str] = set()
    mitre_dedup = [t for t in mitre if not (t in seen or seen.add(t))]  # type: ignore[func-returns-value]

    slug = name.lower().replace(".exe", "").replace(" ", "-")
    url = f"{LOFL_BASE}/{slug}/" if slug else ""

    return {
        "name": name,
        "description": description,
        "mitre": mitre_dedup,
        "url": url,
    }


def scrape_all(yaml_dir: str, filenames: list[str]) -> list[dict]:
    entries: list[dict] = []
    branch = "main"
    for i, fname in enumerate(filenames):
        url = (
            f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}"
            f"/{branch}/{yaml_dir}/{fname}"
        )
        if i > 0:
            time.sleep(DELAY)
        try:
            raw = fetch(url, retries=1)
            text = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            print(f"  warn: skipping {fname}: {exc}", file=sys.stderr)
            continue
        entry = parse_entry_yaml(text, fname)
        if entry.get("name"):
            entries.append(entry)
        if (i + 1) % 20 == 0:
            print(f"  scraped {i + 1}/{len(filenames)} …", file=sys.stderr)
    return entries


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true",
                   help="list filenames and exit without writing")
    p.add_argument("--output", default=None,
                   help="output path (default: archive/sources/lofl_windows.json)")
    return p.parse_args()


def default_output_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(
        os.path.join(script_dir, "..", "archive", "sources", "lofl_windows.json")
    )


def main() -> int:
    args = parse_args()
    output_path = args.output or default_output_path()

    print(f"probing {GITHUB_OWNER}/{GITHUB_REPO} for YAML directory …", file=sys.stderr)
    try:
        yaml_dir, filenames = find_yaml_dir()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"found {len(filenames)} YAML files in {yaml_dir}/", file=sys.stderr)

    if args.dry_run:
        print(json.dumps(filenames[:10], indent=2))
        return 0

    entries = scrape_all(yaml_dir, filenames)
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
