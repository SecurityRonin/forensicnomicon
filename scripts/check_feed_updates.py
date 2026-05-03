#!/usr/bin/env python3
"""Poll subscribed feeds and web pages for new DFIR content.

Reads `archive/sources/dfir-feeds.opml`, and for every outline with either
`xmlUrl` (RSS/Atom) or `htmlUrl` + `type="web"` (HTML page monitor), checks
for new content since the last snapshot.  Writes:

- `archive/sources/feed-state.json`   — full snapshot (machine-readable)
- `archive/sources/feed-report.md`    — current-run new posts (overwritten each run)
- `archive/sources/pending-review.md` — accumulated unreviewed posts (append-only)

Two monitor types
-----------------
RSS/Atom (type="rss"):
    Standard feed parsing — entries from <item> or <entry> elements.

HTML page monitor (type="web"):
    Fetches the HTML page, extracts all same-domain blog/article links, and
    diffs against the previous snapshot.  Use for vendor blogs that have no
    RSS feed.  The `htmlUrl` attribute is the page to monitor; `xmlUrl` is
    omitted (or can equal htmlUrl for state-key purposes).

Pending review workflow
-----------------------
New posts are appended to `pending-review.md` with unchecked checkboxes.
Review them weekly inside Claude Code:

    make review-feeds          # show pending count + list
    /review-dfir-feeds         # Claude Code fetches posts and extracts findings

Mark items done by changing `- [ ]` → `- [x]` (reviewed, no gaps) or
`- [→]` (reviewed, TDD tasks created).  Already-present URLs are never
re-added regardless of status.

URL validation
--------------
Fix 1 (new entries): each newly discovered URL is HEAD-checked before it is
  written to pending-review.md.  URLs that return HTTP 404 or 410 are written
  as `[!]` (broken at discovery time) instead of `[ ]`.

Fix 2 (review skill): the `/review-dfir-feeds` skill instruction handles `[!]`
  items by searching the source domain for the article title before giving up.

Fix 3 (revalidation): pass `--revalidate-pending` to HEAD-check all existing
  `[ ]` entries in pending-review.md and mark newly-gone URLs as `[!]`.  Safe
  to run at any time; only 404/410 responses trigger a status change.
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


USER_AGENT = "forensic-catalog-feed-watcher/0.3 (+https://github.com/SecurityRonin/forensicnomicon)"
ATOM_NS = {"atom": "http://www.w3.org/2005/Atom"}

# HTTP status codes that definitively mean the URL is gone.
# 403/429/5xx may be transient; only 404 and 410 are permanent.
_GONE_CODES = frozenset({404, 410})

# Sources whose new entries are tracked in feed-state.json but must NOT be
# appended to pending-review.md.  These are either:
#   - IOC feeds (URLhaus/MalwareBazaar/ThreatFox) — machine-readable threat intel,
#     not artifact documentation; reviewed via dedicated sync scripts instead
#   - LOL dataset commit feeds — one entry per binary added; handled by the
#     dedicated fetch_*.py scripts (fetch_lolbas.py, fetch_gtfobins.py, etc.)
#   - MISP taxonomy commits — tooling/CI changes, not artifact docs
#
# Match against FeedSnapshot.title (= OPML text/title attribute).
_NO_PENDING_REVIEW: frozenset[str] = frozenset({
    # IOC feeds
    "URLhaus",
    "MalwareBazaar",
    "ThreatFox",
    # LOL dataset commit feeds
    "LOLBAS Project (Windows)",
    "GTFOBins (Linux)",
    "LOOBins (macOS)",
    "LOLDrivers (BYOVD)",
    "LOFL Project (RMM C2 indicators)",
    # Taxonomy / tooling commits
    "MISP Taxonomies",
})


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


def head_check(url: str, timeout: int = 15) -> tuple[str, str]:
    """HEAD-check a URL and return (status, note).

    Returns:
        ("gone", "HTTP 404") — definitively deleted (404 or 410)
        ("ok",   "HTTP 200") — reachable
        ("skip", reason)     — transient error or non-gone HTTP code;
                               do NOT mark as broken
    """
    try:
        req = urllib.request.Request(
            url, method="HEAD", headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return "ok", f"HTTP {resp.getcode()}"
    except urllib.error.HTTPError as exc:
        if exc.code in _GONE_CODES:
            return "gone", f"HTTP {exc.code}"
        # 403 Forbidden, 429 Rate Limited, 5xx server errors → transient
        return "skip", f"HTTP {exc.code}"
    except Exception as exc:
        # DNS failure, timeout, SSL error, etc. → treat as transient
        return "skip", str(exc)


def iter_feed_outlines(opml_path: str) -> Iterable[dict[str, str]]:
    root = ET.parse(opml_path).getroot()
    for outline in root.findall(".//outline"):
        kind = outline.attrib.get("type", "rss").lower()
        xml_url = outline.attrib.get("xmlUrl", "")
        html_url = outline.attrib.get("htmlUrl", "")
        title = outline.attrib.get("title") or outline.attrib.get("text") or xml_url or html_url

        if kind == "web":
            # HTML page monitor — no RSS feed; monitor the page directly
            if not html_url:
                continue
            yield {"title": title, "html_url": html_url, "xml_url": html_url, "kind": "web"}
        else:
            # RSS / Atom feed
            if not xml_url:
                continue
            yield {"title": title, "html_url": html_url, "xml_url": xml_url, "kind": "rss"}


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


def parse_html_links(payload: bytes, base_url: str) -> list[FeedEntry]:
    """Extract blog/article links from an HTML page for sites without RSS.

    Finds all ``<a href="...">`` links on the same domain that look like
    post URLs (not tag/category/author/page pagination URLs).  Returns them
    as FeedEntry with no publish date (we only know they exist today).
    """
    from urllib.parse import urljoin, urlparse

    base = urlparse(base_url)
    seen: set[str] = set()
    entries: list[FeedEntry] = []

    # Naive but stdlib-only HTML link extraction
    for m in re.finditer(r'<a\s[^>]*href=["\']([^"\']+)["\']', payload.decode("utf-8", errors="replace"), re.I):
        href = m.group(1).strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        full = urljoin(base_url, href).split("#")[0].rstrip("/")
        p = urlparse(full)
        if p.netloc != base.netloc:
            continue
        # Skip generic pages: tag, category, author, page, search, feed, rss
        if re.search(r"/(tag|category|author|page|search|feed|rss|wp-|cdn-cgi|#)", p.path, re.I):
            continue
        # Must have a non-trivial path (at least one slug segment)
        segments = [s for s in p.path.split("/") if s]
        if len(segments) < 1:
            continue
        if full in seen:
            continue
        seen.add(full)
        # Title: use the link text if available, otherwise the last path segment
        text_m = re.search(r'<a\s[^>]*href=["\']' + re.escape(m.group(1)) + r'["\'][^>]*>(.*?)</a>', payload.decode("utf-8", errors="replace"), re.I | re.S)
        title = re.sub(r"<[^>]+>", "", text_m.group(1)).strip() if text_m else segments[-1].replace("-", " ").replace("_", " ").title()
        if not title or len(title) > 300:
            title = segments[-1].replace("-", " ").title()
        entries.append(FeedEntry(title=title, url=full, published=""))

    return entries


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


def filter_pending_entries(
    entries: list[tuple[str, str, str]],
) -> list[tuple[str, str, str]]:
    """Remove entries whose source title is in _NO_PENDING_REVIEW.

    Keeps feed-state.json complete (all feeds tracked) while preventing
    IOC feeds and LOL dataset commit feeds from flooding pending-review.md.
    """
    return [(src, title, url) for src, title, url in entries if src not in _NO_PENDING_REVIEW]


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


def append_pending_review(
    pending_path: str,
    new_entries: list[tuple[str, str, str]],
    validate: bool = True,
) -> tuple[int, int]:
    """Append newly detected posts to pending-review.md.

    Only posts whose URL is not already in the file are appended.
    When *validate* is True (default), each URL is HEAD-checked:
      - HTTP 404/410 → written as ``[!]`` with a ``<!-- 404 on DATE -->`` annotation
      - reachable / transient error → written as ``[ ]`` (normal)

    Returns (appended_count, broken_count).
    """
    if not new_entries:
        return 0, 0

    existing_urls = load_reviewed_urls(pending_path)
    to_add = [(src, title, url) for src, title, url in new_entries if url not in existing_urls]
    if not to_add:
        return 0, 0

    broken = 0
    header_needed = not os.path.exists(pending_path)
    with open(pending_path, "a", encoding="utf-8") as fh:
        if header_needed:
            fh.write("# DFIR Feed — Pending Review\n\n")
            fh.write("New posts detected by Feed Watch that may contain artifact findings.\n")
            fh.write("Mark `[x]` when reviewed, `[→]` when artifact tasks were created.\n")
            fh.write("Mark `[!]` entries are 404/410 at discovery time — see retry instructions below.\n\n")
        fh.write(f"\n## {today_str()}\n\n")
        for src, title, url in to_add:
            if validate:
                status, note = head_check(url)
            else:
                status = "ok"
            if status == "gone":
                fh.write(f"- [!] [{title}]({url}) — {src} <!-- {note} on {today_str()} -->\n")
                broken += 1
            else:
                fh.write(f"- [ ] [{title}]({url}) — {src}\n")

    return len(to_add), broken


def revalidate_pending_urls(pending_path: str) -> tuple[int, int]:
    """HEAD-check all ``[ ]`` entries in pending-review.md.

    For each ``[ ]`` line whose URL returns HTTP 404 or 410, rewrite the line
    as ``[!]`` with a ``<!-- 404 on DATE -->`` annotation.

    Returns (checked_count, newly_broken_count).
    """
    if not os.path.exists(pending_path):
        return 0, 0

    with open(pending_path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    # Pattern: - [ ] [title](url) — source
    pending_re = re.compile(r"^- \[ \] \[([^\]]*)\]\(([^)]+)\)(.*)")
    checked = 0
    newly_broken = 0
    new_lines: list[str] = []
    today = today_str()

    for line in lines:
        m = pending_re.match(line)
        if not m:
            new_lines.append(line)
            continue
        title, url, rest = m.group(1), m.group(2), m.group(3)
        status, note = head_check(url)
        checked += 1
        if status == "gone":
            # Replace [ ] with [!] and append annotation
            rest_stripped = rest.rstrip("\n")
            new_lines.append(f"- [!] [{title}]({url}){rest_stripped} <!-- {note} on {today} -->\n")
            newly_broken += 1
        else:
            new_lines.append(line)

    if newly_broken > 0:
        with open(pending_path, "w", encoding="utf-8") as fh:
            fh.writelines(new_lines)

    return checked, newly_broken


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opml", default="archive/sources/dfir-feeds.opml")
    parser.add_argument("--state", default="archive/sources/feed-state.json")
    parser.add_argument("--report", default="archive/sources/feed-report.md")
    parser.add_argument("--pending", default="archive/sources/pending-review.md")
    parser.add_argument("--limit", type=int, default=10, help="max entries retained per feed")
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="skip HEAD-check for new URLs (faster; disables fix 1)",
    )
    parser.add_argument(
        "--revalidate-pending",
        action="store_true",
        help="HEAD-check all [ ] entries in pending-review.md and mark 404s as [!] (fix 3)",
    )
    args = parser.parse_args()

    # Fix 3: revalidate existing pending items if requested
    if args.revalidate_pending:
        checked, broken = revalidate_pending_urls(args.pending)
        print(f"revalidated {checked} pending URLs; {broken} newly marked [!]")
        if not args.opml:
            return 0

    previous = load_previous(args.state)
    snapshots: list[FeedSnapshot] = []
    for outline in iter_feed_outlines(args.opml):
        error = None
        entries: list[FeedEntry] = []
        try:
            payload = fetch(outline["xml_url"])
            if outline.get("kind") == "web":
                entries = parse_html_links(payload, outline["html_url"])[: args.limit]
            else:
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

    # Filter out IOC feeds and LOL dataset commits before writing pending-review.md.
    # feed-state.json already received the full snapshot above.
    pending_entries = filter_pending_entries(new_entries)

    # Fix 1: HEAD-check new URLs before appending
    validate = not args.no_validate
    appended, broken = append_pending_review(args.pending, pending_entries, validate=validate)

    print(
        f"checked {len(snapshots)} feeds; "
        f"detected {len(new_entries)} new entries; "
        f"appended {appended} to pending-review"
        + (f" ({broken} marked [!] — URL already gone)" if broken else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
