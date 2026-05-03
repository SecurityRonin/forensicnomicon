#!/usr/bin/env python3
"""Fetch entries from the LOLBAS Project JSON API for Windows LOL binaries.

Source:
    https://lolbas-project.github.io/api/lolbas.json
    GitHub: https://github.com/LOLBAS-Project/LOLBAS

Produces:
    archive/sources/lolbas_windows.json  — JSON array of objects with keys:
        name          (str)   binary name, e.g. "certutil.exe"
        description   (str)   one-line abuse summary
        commands      (list)  list of documented use-case command examples
        mitre         (list)  ATT&CK technique IDs, e.g. ["T1218.004"]
        url           (str)   canonical LOLBAS page URL

Example:
    python3 scripts/fetch_lolbas.py
    python3 scripts/fetch_lolbas.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


USER_AGENT = (
    "forensic-catalog-lolbas-fetcher/0.1 "
    "(+https://github.com/SecurityRonin/forensicnomicon)"
)
LOLBAS_API_URL = "https://lolbas-project.github.io/api/lolbas.json"
DELAY = 0.5


def fetch(url: str, *, retries: int = 2) -> bytes:
    """Fetch *url* with retries. Raises RuntimeError on hard failure."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            last_exc = exc
            print(f"  attempt {attempt + 1}: {exc}", file=sys.stderr)
        if attempt < retries:
            time.sleep(DELAY)
    raise RuntimeError(f"failed to fetch {url}: {last_exc}") from last_exc


def parse_entries(raw: bytes) -> list[dict]:
    """Parse LOLBAS JSON API response into normalised entry dicts."""
    data = json.loads(raw.decode("utf-8"))
    entries: list[dict] = []
    for item in data:
        name = (item.get("Name") or "").strip()
        if not name:
            continue
        description = (item.get("Description") or "").strip()
        # Commands is a list of {Command, Description, Usecase, ...}
        commands = [
            {
                "command": (c.get("Command") or "").strip(),
                "usecase": (c.get("Usecase") or "").strip(),
                "description": (c.get("Description") or "").strip(),
            }
            for c in (item.get("Commands") or [])
            if (c.get("Command") or "").strip()
        ]
        # Detection list may contain ATT&CK technique references
        mitre: list[str] = []
        for det in item.get("Detection") or []:
            for field in ("IOC", "Description"):
                val = str(det.get(field) or "")
                import re
                for tid in re.findall(r"T\d{4}(?:\.\d{3})?", val):
                    if tid not in mitre:
                        mitre.append(tid)
        # Normalise URL
        url = (item.get("url") or "").strip()
        if not url and name:
            slug = name.lower().replace(".exe", "").replace(".", "-")
            url = f"https://lolbas-project.github.io/{slug}/"
        entries.append({
            "name": name,
            "description": description,
            "commands": commands,
            "mitre": mitre,
            "url": url,
        })
    return entries


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true",
                   help="print first 5 entries to stdout and exit without writing")
    p.add_argument("--output", default=None,
                   help="output JSON path (default: archive/sources/lolbas_windows.json)")
    p.add_argument("--url", default=LOLBAS_API_URL,
                   help=f"LOLBAS API URL (default: {LOLBAS_API_URL})")
    return p.parse_args()


def default_output_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(
        os.path.join(script_dir, "..", "archive", "sources", "lolbas_windows.json")
    )


def main() -> int:
    args = parse_args()
    output_path = args.output or default_output_path()

    print(f"fetching {args.url} …", file=sys.stderr)
    try:
        raw = fetch(args.url)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("parsing …", file=sys.stderr)
    entries = parse_entries(raw)
    if not entries:
        print("error: no entries parsed — API may have changed", file=sys.stderr)
        return 1

    print(f"parsed {len(entries)} entries", file=sys.stderr)

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
