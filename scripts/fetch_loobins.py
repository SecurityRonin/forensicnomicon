#!/usr/bin/env python3
"""Fetch LOOBins entries for macOS Living Off the Orchard binary entries.

Source:
    https://www.loobins.io/
    GitHub: https://github.com/infosecB/LOOBins

Produces:
    archive/sources/loobins_macos.json  — JSON array of objects with keys:
        name          (str)   binary name, e.g. "osascript"
        description   (str)   one-line summary of abuse potential
        mitre         (list)  ATT&CK technique IDs
        use_cases     (list)  list of {name, description} dicts
        url           (str)   canonical LOOBins page URL

Uses the GitHub API to read YAML files from the LOOBins repo
(_loobins/<name>.yml) without cloning the entire repository.

Example:
    python3 scripts/fetch_loobins.py
    python3 scripts/fetch_loobins.py --dry-run
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
    "forensic-catalog-loobins-fetcher/0.1 "
    "(+https://github.com/SecurityRonin/forensicnomicon)"
)
GITHUB_API = "https://api.github.com/repos/infosecB/LOOBins"
LOOBINS_BASE = "https://www.loobins.io/binaries"
DELAY = 0.4


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
                print("  GitHub rate-limited — sleeping 60s", file=sys.stderr)
                time.sleep(60)
            else:
                print(f"  attempt {attempt + 1}: {exc}", file=sys.stderr)
        if attempt < retries:
            time.sleep(DELAY)
    raise RuntimeError(f"failed to fetch {url}: {last_exc}") from last_exc


def list_loobins_files() -> list[str]:
    """Return list of YAML file names from the LOOBins repository."""
    url = f"{GITHUB_API}/contents/LOOBins"
    raw = fetch(url)
    files = json.loads(raw.decode("utf-8"))
    return sorted(
        f["name"] for f in files
        if isinstance(f, dict) and f.get("name", "").endswith(".yml")
    )


def parse_simple_yaml_entry(text: str) -> dict:
    """Very lightweight YAML parser for LOOBins entry format.

    LOOBins YAML is structured enough that we can use regex extraction
    without a full YAML dependency (staying stdlib-only).
    """
    def extract_scalar(key: str) -> str:
        m = re.search(rf"^{key}:\s*(.+)", text, re.MULTILINE)
        return m.group(1).strip().strip("\"'") if m else ""

    name = extract_scalar("Name")
    description = extract_scalar("Description")

    # ATT&CK techniques: lines like "  - T1059.002"
    mitre = re.findall(r"mitre_attack_technique:\s*(T\d{4}(?:\.\d{3})?)", text)
    # Also catch inline list style: [T1059.002, T1547]
    inline = re.findall(r"\[([^\]]*T\d{4}[^\]]*)\]", text)
    for group in inline:
        for tid in re.findall(r"T\d{4}(?:\.\d{3})?", group):
            if tid not in mitre:
                mitre.append(tid)

    # Use cases: list items under "Usage:" or "Use Cases:" blocks
    use_cases: list[dict] = []
    for block in re.finditer(
        r"^\s*-\s+Name:\s+(.+?)\n(?:.*?Description:\s+(.+?)(?:\n|$))?",
        text,
        re.MULTILINE | re.DOTALL,
    ):
        uc_name = block.group(1).strip()
        uc_desc = (block.group(2) or "").strip()
        if uc_name:
            use_cases.append({"name": uc_name, "description": uc_desc})

    slug = name.lower().replace(" ", "-") if name else ""
    url = f"{LOOBINS_BASE}/{slug}/" if slug else ""

    return {
        "name": name,
        "description": description,
        "mitre": mitre,
        "use_cases": use_cases,
        "url": url,
    }


def scrape_all(filenames: list[str]) -> list[dict]:
    entries: list[dict] = []
    for i, fname in enumerate(filenames):
        url = (
            "https://raw.githubusercontent.com/infosecB/LOOBins/main/LOOBins/"
            + fname
        )
        if i > 0:
            time.sleep(DELAY)
        try:
            raw = fetch(url)
            text = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            print(f"  warn: skipping {fname}: {exc}", file=sys.stderr)
            continue
        entry = parse_simple_yaml_entry(text)
        if entry.get("name"):
            entries.append(entry)
        if (i + 1) % 20 == 0:
            print(f"  scraped {i + 1}/{len(filenames)} …", file=sys.stderr)
    return entries


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true",
                   help="list file names only and exit without writing")
    p.add_argument("--output", default=None,
                   help="output path (default: archive/sources/loobins_macos.json)")
    return p.parse_args()


def default_output_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(
        os.path.join(script_dir, "..", "archive", "sources", "loobins_macos.json")
    )


def main() -> int:
    args = parse_args()
    output_path = args.output or default_output_path()

    print("fetching LOOBins file list …", file=sys.stderr)
    try:
        filenames = list_loobins_files()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"found {len(filenames)} YAML files", file=sys.stderr)

    if args.dry_run:
        print(json.dumps(filenames[:10], indent=2))
        return 0

    print("fetching individual entries …", file=sys.stderr)
    entries = scrape_all(filenames)

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
