#!/usr/bin/env python3
"""Poll subscribed feeds and write a compact snapshot/report.

Reads `archive/sources/dfir-feeds.opml`, fetches feed entries for any outline
that has an `xmlUrl`, and writes:

- `archive/sources/feed-state.json`   — full snapshot (machine-readable)
- `archive/sources/feed-report.md`    — current-run new posts (overwritten each run)
- `archive/sources/pending-review.md` — accumulated unreviewed posts (append-only)

Designed for scheduled GitHub Actions runs. No third-party dependencies.

Pending review workflow
-----------------------
When new posts are detected they are appended to `pending-review.md` with
an unchecked checkbox `- [ ]`.  Review them weekly with Claude Code:

    make review-feeds          # show pending count
    /review-dfir-feeds         # Claude Code fetches posts and extracts artifact findings

Mark an item done by changing `- [ ]` to `- [x]` in pending-review.md.
Items already marked `[x]` or `[→]` are never re-added.
"""

from __future__ import annotations

import argparse
import email.utils
import json
import os
import re
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable


USER_AGENT = "forensic-catalog-feed-watcher/0.2 (+https://github.com/SecurityRonin/forensicnomicon)"
ATOM_NS = {"atom": "http://www.w3.org/2005/Atom"}


@dataclass
class FeedEntry:
    title: str
    url: str
    published: str


@dataclass
class FeedSnapshot:
    title: str
    html_url: str
    xml_url: str
    checked_at: str
    entries: list[FeedEntry]
    error: str | None


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


def iter_feed_outlines(opml_path: str) -> Iterable[dict[str, str]]:
    root = ET.parse(opml_path).getroot()
    for outline in root.findall(".//outline"):
        xml_url = outline.attrib.get("xmlUrl")
        if not xml_url:
            continue
        yield {
            "title": outline.attrib.get("title") or outline.attrib.get("text") or xml_url,
            "html_url": outline.attrib.get("htmlUrl", ""),
            "xml_url": xml_url,
        }


def parse_isoish(value: str) -> str:
    """Parse a date string in RFC 2822 or ISO 8601 format into ISO 8601.

    Blogspot/Atom feeds use ISO 8601 (``2026-03-10T06:23:32.332-05:00``).
    RSS feeds use RFC 2822 (``Mon, 10 Mar 2026 11:23:32 +0000``).
    We try both so neither format silently fails.
    """
    value = (value or "").strip()
    if not value:
        return ""
    # RFC 2822 (email / RSS pubDate)
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        if parsed is not None:
            return parsed.isoformat()
    except Exception:
        pass
    # ISO 8601 (Atom / blogspot) — Python 3.7+ fromisoformat handles offsets
    try:
        # Strip sub-second precision that older Python may not parse
        normalised = re.sub(r"\.\d+", "", value)
        parsed = datetime.fromisoformat(normalised)
        return parsed.isoformat()
    except Exception:
        pass
    # Return raw value rather than raising; caller logs as-is
    return value


def parse_atom(root: ET.Element) -> list[FeedEntry]:
    entries: list[FeedEntry] = []
    for entry in root.findall("atom:entry", ATOM_NS):
        title = entry.findtext("atom:title", default="", namespaces=ATOM_NS).strip()
        published = (
            entry.findtext("atom:updated", default="", namespaces=ATOM_NS)
            or entry.findtext("atom:published", default="", namespaces=ATOM_NS)
        )
        url = ""
        for link in entry.findall("atom:link", ATOM_NS):
            rel = link.attrib.get("rel", "alternate")
            if rel == "alternate":
                url = link.attrib.get("href", "")
                break
        entries.append(FeedEntry(title=title, url=url, published=parse_isoish(published)))
    return entries


def parse_rss(root: ET.Element) -> list[FeedEntry]:
    entries: list[FeedEntry] = []
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        url = (item.findtext("link") or "").strip()
        published = parse_isoish(item.findtext("pubDate") or "")
        entries.append(FeedEntry(title=title, url=url, published=published))
    return entries


def parse_feed(payload: bytes) -> list[FeedEntry]:
    root = ET.fromstring(payload)
    tag = root.tag.lower()
    if tag.endswith("feed"):
        return parse_atom(root)
    return parse_rss(root)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def today_str() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def load_previous(path: str) -> dict[str, dict]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_state(path: str, snapshots: list[FeedSnapshot]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({snap.xml_url: asdict(snap) for snap in snapshots}, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_report(path: str, snapshots: list[FeedSnapshot], previous: dict[str, dict]) -> list[tuple[str, str, str]]:
    """Write the per-run report. Returns list of (source_title, post_title, post_url) for new entries."""
    new_entries_all: list[tuple[str, str, str]] = []
    lines = [
        "# Feed Update Report",
        "",
        f"Generated: {now_iso()}",
        "",
    ]

    for snap in snapshots:
        lines.append(f"## {snap.title}")
        lines.append("")
        lines.append(f"- Site: {snap.html_url or 'unknown'}")
        lines.append(f"- Feed: {snap.xml_url}")
        if snap.error:
            lines.append(f"- Status: error: {snap.error}")
            lines.append("")
            continue
        previous_entries = previous.get(snap.xml_url, {}).get("entries", [])
        previous_urls = {entry.get("url", "") for entry in previous_entries}
        new_entries = [entry for entry in snap.entries if entry.url and entry.url not in previous_urls]
        lines.append(f"- Entries checked: {len(snap.entries)}")
        lines.append(f"- New since last snapshot: {len(new_entries)}")
        lines.append("")
        for entry in new_entries[:10]:
            lines.append(f"- {entry.published or 'unknown date'} — [{entry.title}]({entry.url})")
            new_entries_all.append((snap.title, entry.title, entry.url))
        if not new_entries:
            lines.append("- No new entries detected")
        lines.append("")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines).rstrip() + "\n")
    return new_entries_all


def load_reviewed_urls(pending_path: str) -> set[str]:
    """Return URLs already present in pending-review.md (reviewed or not)."""
    if not os.path.exists(pending_path):
        return set()
    urls: set[str] = set()
    with open(pending_path, "r", encoding="utf-8") as fh:
        for line in fh:
            # Match markdown link URLs: ](url)
            for m in re.finditer(r"\]\(([^)]+)\)", line):
                urls.add(m.group(1))
    return urls


def append_pending_review(pending_path: str, new_entries: list[tuple[str, str, str]]) -> int:
    """Append newly detected posts to pending-review.md.

    Only posts whose URL is not already in the file are appended.
    Returns the number of posts actually appended.
    """
    if not new_entries:
        return 0

    existing_urls = load_reviewed_urls(pending_path)
    to_add = [(src, title, url) for src, title, url in new_entries if url not in existing_urls]
    if not to_add:
        return 0

    header_needed = not os.path.exists(pending_path)
    with open(pending_path, "a", encoding="utf-8") as fh:
        if header_needed:
            fh.write("# DFIR Feed — Pending Review\n\n")
            fh.write("New posts detected by Feed Watch that may contain artifact findings.\n")
            fh.write("Mark `[x]` when reviewed, `[→]` when artifact tasks were created.\n\n")
        fh.write(f"\n## {today_str()}\n\n")
        for src, title, url in to_add:
            fh.write(f"- [ ] [{title}]({url}) — {src}\n")

    return len(to_add)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opml", default="archive/sources/dfir-feeds.opml")
    parser.add_argument("--state", default="archive/sources/feed-state.json")
    parser.add_argument("--report", default="archive/sources/feed-report.md")
    parser.add_argument("--pending", default="archive/sources/pending-review.md")
    parser.add_argument("--limit", type=int, default=10, help="max entries retained per feed")
    args = parser.parse_args()

    previous = load_previous(args.state)
    snapshots: list[FeedSnapshot] = []
    for outline in iter_feed_outlines(args.opml):
        error = None
        entries: list[FeedEntry] = []
        try:
            payload = fetch(outline["xml_url"])
            entries = parse_feed(payload)[: args.limit]
        except Exception as exc:
            error = str(exc)
        snapshots.append(
            FeedSnapshot(
                title=outline["title"],
                html_url=outline["html_url"],
                xml_url=outline["xml_url"],
                checked_at=now_iso(),
                entries=entries,
                error=error,
            )
        )

    os.makedirs(os.path.dirname(args.state), exist_ok=True)
    write_state(args.state, snapshots)
    new_entries = write_report(args.report, snapshots, previous)
    appended = append_pending_review(args.pending, new_entries)
    print(
        f"checked {len(snapshots)} feeds; "
        f"detected {len(new_entries)} new entries; "
        f"appended {appended} to pending-review"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
