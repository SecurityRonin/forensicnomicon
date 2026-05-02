#!/usr/bin/env python3
"""Sync URLhaus active malware-distribution URLs to a local JSON snapshot.

Downloads the URLhaus recent-URLs CSV (updated every 5 minutes by abuse.ch),
extracts unique domains from active C2 and malware-download entries, and
writes a compact JSON file suitable for incorporation into forensicnomicon's
``abusable_sites`` module.

Sources:
- URLhaus project: https://urlhaus.abuse.ch/
- CSV spec:        https://urlhaus.abuse.ch/api/#csv
- CSV download:    https://urlhaus.abuse.ch/downloads/csv_recent/

Output: archive/sources/urlhaus_domains.json

Usage::

    python3 scripts/sync_urlhaus.py
    python3 scripts/sync_urlhaus.py --dry-run
    python3 scripts/sync_urlhaus.py --output /tmp/urlhaus.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

USER_AGENT = (
    "forensicnomicon-urlhaus-sync/0.1 "
    "(+https://github.com/SecurityRonin/forensicnomicon)"
)

CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# Threat tags that indicate active C2 or payload delivery.
# URLhaus tags are free-form; these are the canonical abuse.ch-defined tags.
C2_THREAT_TAGS = {
    "botnet_cc",
    "c2",
    "c&c",
    "malware_download",
    "malspam",
    "payload_delivery",
}

# Only include URLs that are currently online (reduces stale noise).
ACTIVE_STATUSES = {"online"}

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def fetch_bytes(url: str, retries: int = 2) -> bytes:
    """Fetch *url* and return raw bytes; retry up to *retries* times."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except urllib.error.URLError as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed to fetch {url}: {last_exc}") from last_exc


# ---------------------------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------------------------


def extract_domain(url_str: str) -> str | None:
    """Return the bare hostname from *url_str*, or None if unparseable."""
    # Avoid importing urllib.parse; simple prefix stripping is sufficient.
    for scheme in ("https://", "http://"):
        if url_str.lower().startswith(scheme):
            rest = url_str[len(scheme):]
            # strip path / query / port
            domain = rest.split("/")[0].split("?")[0].split("#")[0]
            domain = domain.split(":")[0].lower().strip()
            if domain:
                return domain
    return None


def parse_urlhaus_csv(raw: bytes) -> list[dict]:
    """Parse URLhaus CSV bytes and return qualifying domain records.

    URLhaus CSV columns (comment lines start with ``#``):
    id, dateadded, url, url_status, last_online, threat, tags,
    urlhaus_link, reporter
    """
    text = raw.decode("utf-8", errors="replace")
    # Strip comment lines (URLhaus prepends a large header block)
    data_lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
    reader = csv.DictReader(data_lines)

    seen_domains: set[str] = set()
    records: list[dict] = []

    for row in reader:
        status = (row.get("url_status") or "").strip().lower()
        if status not in ACTIVE_STATUSES:
            continue

        threat = (row.get("threat") or "").strip().lower()
        raw_tags = (row.get("tags") or "").strip().lower()
        tag_set = {t.strip() for t in raw_tags.split(",")} | {threat}

        if not (tag_set & C2_THREAT_TAGS):
            continue

        url_str = (row.get("url") or "").strip().strip('"')
        domain = extract_domain(url_str)
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)

        records.append({
            "domain": domain,
            "threat": threat,
            "tags": sorted(t for t in tag_set if t),
            "urlhaus_link": (row.get("urlhaus_link") or "").strip().strip('"'),
            "date_added": (row.get("dateadded") or "").strip().strip('"'),
        })

    return records


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Sync URLhaus active malware-distribution URLs to a local JSON snapshot. "
            "Source: https://urlhaus.abuse.ch/ "
            "Produces: archive/sources/urlhaus_domains.json"
        )
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="fetch and parse but print the first 10 entries; do not write",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "output JSON path "
            "(default: archive/sources/urlhaus_domains.json relative to this script)"
        ),
    )
    parser.add_argument(
        "--url",
        default=CSV_URL,
        help=f"URLhaus CSV download URL (default: {CSV_URL})",
    )
    args = parser.parse_args()

    # Resolve default output path relative to this script.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    output_path = args.output or os.path.join(
        repo_root, "archive", "sources", "urlhaus_domains.json"
    )

    print(f"[urlhaus] Fetching {args.url} …", file=sys.stderr)
    raw = fetch_bytes(args.url)

    # URLhaus serves a zip archive for the CSV download.
    if raw[:2] == b"PK":
        print("[urlhaus] Decompressing ZIP …", file=sys.stderr)
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            csv_name = next(
                (n for n in zf.namelist() if n.endswith(".csv")), zf.namelist()[0]
            )
            raw = zf.read(csv_name)

    print("[urlhaus] Parsing CSV …", file=sys.stderr)
    records = parse_urlhaus_csv(raw)
    print(f"[urlhaus] Found {len(records)} active C2/malware-download domains.", file=sys.stderr)

    if args.dry_run:
        for rec in records[:10]:
            print(json.dumps(rec, indent=2))
        return 0

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2)
        fh.write("\n")
    print(f"[urlhaus] Written → {output_path}", file=sys.stderr)
    return 0


raise SystemExit(main())
