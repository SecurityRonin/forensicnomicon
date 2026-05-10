#!/usr/bin/env python3
"""migrate_to_jsonl.py — convert pending-review.md to pending-review.jsonl.

One-time migration. Reads the markdown checklist and writes one JSON object
per line to the JSONL file. Existing JSONL entries are preserved (URL-keyed
dedup); only entries whose URL is not already in the JSONL file are added.

Usage:
    python3 scripts/migrate_to_jsonl.py [--dry-run] [--md PATH] [--jsonl PATH]

Output JSONL schema:
    {
      "url":             str   — canonical URL (dedup key)
      "title":           str
      "source":          str   — feed source name (e.g. "Windows Incident Response")
      "status":          str   — "pending" | "reviewed" | "broken"
      "discovered":      str?  — ISO date first seen (null if unknown)
      "reviewed_date":   str?  — ISO date reviewed (null if pending)
      "artifacts_found": int?  — count of new artifacts implemented (null = not recorded)
      "heuristics_found":int?  — count of new heuristics implemented (null = not recorded)
      "notes":           str   — free-text annotation (was the HTML comment)
    }
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def parse_md_line(line: str) -> dict | None:
    """Parse one pending-review.md list line into a dict.

    Handles formats:
        - [ ] [title](url) — source <!-- notes -->
        - [x] [title](url) — source <!-- notes -->
        - [!] [title](url) — source <!-- notes -->
        - [→] [title](url) — source <!-- notes -->
        - [>] [title](url) — source <!-- notes -->  (ascii arrow variant)
    """
    line = line.strip()
    if not line.startswith("- ["):
        return None

    status_m = re.match(r"^- \[(.)\]", line)
    if not status_m:
        return None
    char = status_m.group(1)

    if char == "x":
        status = "reviewed"
    elif char == "!":
        status = "broken"
    elif char in ("→", ">"):
        status = "reviewed"
    else:
        status = "pending"

    link_m = re.search(r"\[([^\]]*)\]\(([^)]+)\)", line)
    if not link_m:
        return None
    title = link_m.group(1).strip()
    url = link_m.group(2).strip()

    # Source: text after ") —" up to "<" or end of line
    src_m = re.search(r"\)\s*—\s*([^<\n\[]+?)(?:\s*<!|\s*$)", line)
    source = src_m.group(1).strip() if src_m else ""

    # Collect all <!-- ... --> annotation blocks
    notes_parts = re.findall(r"<!--(.*?)-->", line, re.DOTALL)
    notes = " ".join(p.strip() for p in notes_parts).strip()

    return {
        "url": url,
        "title": title,
        "source": source,
        "status": status,
        "discovered": None,
        "reviewed_date": None,
        "artifacts_found": None,
        "heuristics_found": None,
        "notes": notes,
    }


def load_existing_jsonl(path: Path) -> dict[str, dict]:
    """Load existing JSONL entries keyed by URL."""
    if not path.exists():
        return {}
    entries: dict[str, dict] = {}
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if "url" in entry:
                    entries[entry["url"]] = entry
            except json.JSONDecodeError as exc:
                print(f"WARNING: skipping malformed JSONL line {lineno}: {exc}", file=sys.stderr)
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--md", default="archive/sources/pending-review.md", help="source markdown file")
    parser.add_argument("--jsonl", default="archive/sources/pending-review.jsonl", help="output JSONL file")
    parser.add_argument("--dry-run", action="store_true", help="print what would be written, don't write")
    parser.add_argument("--overwrite-notes", action="store_true",
                        help="update notes for already-present entries (default: preserve existing JSONL entry)")
    args = parser.parse_args()

    md_path = Path(args.md)
    jsonl_path = Path(args.jsonl)

    if not md_path.exists():
        print(f"ERROR: markdown file not found: {md_path}", file=sys.stderr)
        return 1

    existing = load_existing_jsonl(jsonl_path)
    print(f"Existing JSONL entries: {len(existing)}")

    md_entries: list[dict] = []
    skipped = 0
    with open(md_path, encoding="utf-8") as fh:
        for line in fh:
            entry = parse_md_line(line)
            if entry is None:
                continue
            md_entries.append(entry)
    print(f"Parsed {len(md_entries)} entries from {md_path}")

    new_entries: list[dict] = []
    updated_entries: list[dict] = []
    for entry in md_entries:
        url = entry["url"]
        if url in existing:
            if args.overwrite_notes and entry["notes"]:
                existing[url]["notes"] = entry["notes"]
                updated_entries.append(existing[url])
            skipped += 1
        else:
            new_entries.append(entry)

    print(f"New entries to add: {len(new_entries)}")
    print(f"Already-present (skipped): {skipped}")
    if args.overwrite_notes:
        print(f"Notes updated: {len(updated_entries)}")

    if args.dry_run:
        print("\n--- DRY RUN: first 5 new entries ---")
        for entry in new_entries[:5]:
            print(json.dumps(entry, ensure_ascii=False))
        if len(new_entries) > 5:
            print(f"... and {len(new_entries) - 5} more")
        return 0

    # Write: existing entries (possibly with updated notes) + new entries
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    if args.overwrite_notes and updated_entries:
        # Rewrite full file to apply note updates
        all_entries = list(existing.values())
        for entry in new_entries:
            all_entries.append(entry)
            existing[entry["url"]] = entry
        with open(jsonl_path, "w", encoding="utf-8") as fh:
            for entry in all_entries:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"Rewrote {jsonl_path} with {len(all_entries)} entries")
    else:
        # Append-only: just add new entries
        with open(jsonl_path, "a", encoding="utf-8") as fh:
            for entry in new_entries:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        total = len(existing) + len(new_entries)
        print(f"Appended {len(new_entries)} entries to {jsonl_path} (total: {total})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
