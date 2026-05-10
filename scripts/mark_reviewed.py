#!/usr/bin/env python3
"""mark_reviewed.py — update a pending-review.jsonl entry by URL.

Used by /review-dfir-feeds and review_loop.sh after reviewing a post.

Usage:
    python3 scripts/mark_reviewed.py <url> [options]
    python3 scripts/mark_reviewed.py --next-pending

Options:
    --status STATUS        reviewed|broken|pending (default: reviewed)
    --reviewed-date DATE   ISO date (default: today UTC)
    --artifacts INT        count of new artifacts implemented
    --heuristics INT       count of new heuristics implemented
    --notes TEXT           append to notes field ("; "-separated)
    --next-pending         print JSON {url, title, status} of first
                           pending/broken entry, then exit (prints {} if none)
    --count-pending        print count of pending+broken entries, then exit
    --jsonl PATH           JSONL file (default: archive/sources/pending-review.jsonl)
    --dry-run              print what would change, don't write
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from pending_lock import locked_write  # noqa: E402


DEFAULT_JSONL = "archive/sources/pending-review.jsonl"


def today_str() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def iter_entries(path: str):
    """Yield (lineno, entry_dict) for each valid JSONL line in *path*."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                yield lineno, json.loads(stripped)
            except json.JSONDecodeError as exc:
                print(f"WARNING: malformed JSONL line {lineno}: {exc}", file=sys.stderr)


def count_pending(jsonl_path: str) -> int:
    return sum(
        1 for _, e in iter_entries(jsonl_path)
        if e.get("status") in ("pending", "broken")
    )


def next_pending_entry(jsonl_path: str) -> dict | None:
    for _, entry in iter_entries(jsonl_path):
        if entry.get("status") in ("pending", "broken"):
            return entry
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", nargs="?", help="URL of the entry to update")
    parser.add_argument("--jsonl", default=DEFAULT_JSONL)
    parser.add_argument("--status", default="reviewed",
                        choices=["reviewed", "broken", "pending"])
    parser.add_argument("--reviewed-date", default=None,
                        help="ISO date (default: today UTC)")
    parser.add_argument("--artifacts", type=int, default=None,
                        dest="artifacts", metavar="INT")
    parser.add_argument("--heuristics", type=int, default=None,
                        dest="heuristics", metavar="INT")
    parser.add_argument("--notes", default=None,
                        help="append to notes field")
    parser.add_argument("--next-pending", action="store_true",
                        help="print JSON of first pending/broken entry, then exit")
    parser.add_argument("--count-pending", action="store_true",
                        help="print count of pending+broken entries, then exit")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.count_pending:
        print(count_pending(args.jsonl))
        return 0

    if args.next_pending:
        entry = next_pending_entry(args.jsonl)
        if entry is None:
            print("{}", flush=True)
        else:
            print(json.dumps({
                "url": entry.get("url", ""),
                "title": entry.get("title", ""),
                "status": entry.get("status", ""),
            }, ensure_ascii=False))
        return 0

    if not args.url:
        print("ERROR: url is required (or use --next-pending / --count-pending)",
              file=sys.stderr)
        return 1

    target_url = args.url
    reviewed_date = args.reviewed_date or (today_str() if args.status == "reviewed" else None)

    if args.dry_run:
        match = next((e for _, e in iter_entries(args.jsonl)
                      if e.get("url") == target_url), None)
        if match:
            print(f"[dry-run] would update: {target_url}")
            print(f"  status: {match.get('status')!r} → {args.status!r}")
            if args.artifacts is not None:
                print(f"  artifacts_found: {match.get('artifacts_found')} → {args.artifacts}")
            if args.heuristics is not None:
                print(f"  heuristics_found: {match.get('heuristics_found')} → {args.heuristics}")
        else:
            print(f"[dry-run] WARNING: URL not found in {args.jsonl}: {target_url}")
        return 0

    if not os.path.exists(args.jsonl):
        print(f"ERROR: JSONL file not found: {args.jsonl}", file=sys.stderr)
        return 1

    found = False

    def _transform(content: str) -> str:
        nonlocal found
        new_lines: list[str] = []
        for raw_line in content.splitlines(keepends=True):
            stripped = raw_line.strip()
            if not stripped:
                new_lines.append(raw_line)
                continue
            try:
                entry = json.loads(stripped)
            except json.JSONDecodeError:
                new_lines.append(raw_line)
                continue
            if entry.get("url") == target_url:
                found = True
                entry["status"] = args.status
                if reviewed_date is not None:
                    entry["reviewed_date"] = reviewed_date
                if args.artifacts is not None:
                    entry["artifacts_found"] = args.artifacts
                if args.heuristics is not None:
                    entry["heuristics_found"] = args.heuristics
                if args.notes:
                    existing = entry.get("notes") or ""
                    entry["notes"] = (
                        existing + "; " + args.notes if existing else args.notes
                    )
                new_lines.append(json.dumps(entry, ensure_ascii=False) + "\n")
            else:
                new_lines.append(raw_line)
        return "".join(new_lines)

    locked_write(args.jsonl, _transform)

    if not found:
        print(f"WARNING: URL not found in {args.jsonl}: {target_url}", file=sys.stderr)
        return 1

    print(f"marked {target_url!r} as {args.status!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
