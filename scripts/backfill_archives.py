#!/usr/bin/env python3
"""
backfill_archives.py — Full-archive crawl for DFIR blog sources.

RSS feeds show only the last ~20 posts. This script fetches the full
post history for each blog using platform-aware pagination, then appends
new entries to archive/sources/pending-review.md for artifact review.

Usage:
    python scripts/backfill_archives.py [OPTIONS]

Options:
    --opml PATH           OPML feed file (default: archive/sources/dfir-feeds.opml)
    --pending PATH        pending-review.md (default: archive/sources/pending-review.md)
    --state PATH          feed-state.json (default: archive/sources/feed-state.json)
    --source BLOG_NAME    limit to one source (partial match on title)
    --no-validate         skip HEAD-checking new URLs
    --dry-run             print what would be added, don't write
    --max-pages N         max pagination pages per source (default: 50)

Platform support:
    blogger      Atom feed pagination: ?max-results=150&start-index=N
    wordpress    REST API: /wp-json/wp/v2/posts?per_page=100&page=N
                 Fallback: RSS paging /feed/?paged=N
    atom         Generic Atom (GitHub commits, YouTube) — first page only;
                 for LOL datasets use fetch_*.py scripts instead
    squarespace  Blog archive page scraping (mac4n6)
    unknown      Skipped with a warning

Blogs to SKIP for backfill (low artifact signal):
    SANS ISC        — mostly stormcast podcast summaries
    BleepingComputer, Krebs, Dark Reading — news aggregators, not DFIR
    Forensic Focus  — news aggregator
    HECF            — very high volume, mostly daily link roundups
    GitHub Atom feeds — use fetch_lolbas.py / fetch_gtfobins.py etc.
    URLhaus, MalwareBazaar, ThreatFox — IOC feeds, not artifact docs
    MISP taxonomies — taxonomy commits, not blog posts
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# ─── constants ────────────────────────────────────────────────────────────────

USER_AGENT = (
    "forensicnomicon-backfill/1.0 "
    "(https://github.com/SecurityRonin/forensicnomicon; DFIR research)"
)

# Only HTTP 404/410 are "definitively gone" — transient errors do not trigger [!]
_GONE_CODES = frozenset({404, 410})

# Sources with low artifact signal — skip for backfill
_SKIP_TITLES = frozenset({
    "SANS Internet Storm Center",
    "BleepingComputer",
    "Krebs on Security",
    "Dark Reading",
    "Forensic Focus",
    "HECF / Hacking Exposed Computer Forensics Blog",
    "URLhaus",
    "MalwareBazaar",
    "ThreatFox",
    "MISP taxonomies",
    "MSAB",
    "DFIR Training",
    "Amped Software blog",
    "The Sleuth Kit updates",
    "This Week In 4n6",
    "Forensic 4cast",
    "Forensic Multimedia Analysis Blog",
    "13cubed (YouTube)",
    # LOL datasets — use fetch_*.py scripts instead
    "LOLBAS Project (Windows)",
    "GTFOBins (Linux)",
    "LOOBins (macOS)",
    "LOLDrivers (BYOVD)",
    "LOFL Project (RMM C2 indicators)",
    "Blue_Team_Hunting_Field_Notes",
    # Vendor marketing — low DFIR artifact signal
    "Cellebrite Blog",
    "Binalyze Blog",
    "DFIR Science",
})

# Atom XML namespace
_ATOM_NS = "http://www.w3.org/2005/Atom"

# ─── artifact co-occurrence map ───────────────────────────────────────────────
# Maps phrases that appear in blog prose → catalog artifact IDs.
# Used by extract_related_artifacts() to populate the `related` field.
# Keep entries lowercase; matching is case-insensitive.
_ARTIFACT_PHRASES: list[tuple[str, str]] = [
    # Execution artifacts
    ("shimcache", "shimcache"),
    ("appcompatcache", "shimcache"),
    ("appcompat cache", "shimcache"),
    ("prefetch", "prefetch_dir"),
    ("userassist", "userassist_exe"),
    ("user assist", "userassist_exe"),
    ("amcache", "amcache_hve"),
    ("muicache", "muicache"),
    ("bam ", "bam_dam"),
    ("dam ", "bam_dam"),
    # Registry
    ("run key", "run_key"),
    ("runonce", "run_key"),
    ("hklm\\software\\microsoft\\windows\\currentversion\\run", "run_key"),
    # File system
    ("\\$mft", "mft_file"),
    ("$mft", "mft_file"),
    ("mft record", "mft_file"),
    ("usnjrnl", "usnjrnl"),
    ("usnjournal", "usnjrnl"),
    ("\\$usnjrnl", "usnjrnl"),
    ("logfile", "logfile_ntfs"),
    ("\\$logfile", "logfile_ntfs"),
    # Link / LNK
    ("lnk file", "lnk_file"),
    ("shell link", "lnk_file"),
    ("shortcut file", "lnk_file"),
    # Event logs
    ("evtx", "evtx_security"),
    ("event log", "evtx_security"),
    ("windows event log", "evtx_security"),
    ("security.evtx", "evtx_security"),
    ("system.evtx", "evtx_system"),
    ("application.evtx", "evtx_application"),
    # Network
    ("dns cache", "dns_cache"),
    ("arp cache", "arp_cache"),
    ("netstat", "netstat_snapshot"),
    # Browser
    ("browser history", "chrome_history"),
    ("chrome history", "chrome_history"),
    ("firefox history", "firefox_places"),
    # SRUM / WMI
    ("srum", "srudb"),
    ("srudb", "srudb"),
    ("wmi", "wmi_repository"),
    # Scheduled tasks
    ("scheduled task", "scheduled_tasks_xml"),
    # Memory
    ("lsass", "lsass_dump"),
    ("memory dump", "memory_raw"),
    ("pagefile", "pagefile_sys"),
    ("hibernation", "hiberfil_sys"),
    # macOS
    ("spotlight", "macos_spotlight_store"),
    ("fsevents", "macos_fsevents"),
    ("unified log", "macos_unified_log"),
    ("biome", "macos_biome"),
    ("btm", "fa_file_com_apple_backgroundtaskmanagement_backgrounditems_v"),
    ("background task management", "fa_file_com_apple_backgroundtaskmanagement_backgrounditems_v"),
    # Remote access
    ("rdp", "evtx_rdp_auth"),
    ("remote desktop", "evtx_rdp_auth"),
]


# ─── pure parsing functions ────────────────────────────────────────────────────

def parse_blogger_feed(xml_text: str) -> list[tuple[str, str, str]]:
    """Parse a Blogger/Atom feed. Returns list of (title, url, date YYYY-MM-DD)."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    entries = []
    ns = _ATOM_NS
    for entry in root.findall(f"{{{ns}}}entry"):
        # title
        title_el = entry.find(f"{{{ns}}}title")
        title = title_el.text.strip() if title_el is not None and title_el.text else ""

        # link rel="alternate"
        url = ""
        for link in entry.findall(f"{{{ns}}}link"):
            if link.get("rel") == "alternate":
                url = link.get("href", "")
                break

        # date: prefer <published>, fall back to <updated>
        date = _parse_atom_date(entry, ns)

        if url:
            entries.append((title, url, date))

    return entries


def parse_wordpress_posts(json_text: str) -> list[tuple[str, str, str]]:
    """Parse WordPress REST API response. Returns list of (title, url, date)."""
    try:
        posts = json.loads(json_text)
    except (json.JSONDecodeError, ValueError):
        return []

    if not isinstance(posts, list):
        return []

    entries = []
    for post in posts:
        try:
            title = post["title"]["rendered"]
            # Strip HTML entities
            title = re.sub(r"<[^>]+>", "", title).strip()
            url = post["link"]
            raw_date = post.get("date", "")
            date = raw_date[:10] if raw_date else ""
            if url:
                entries.append((title, url, date))
        except (KeyError, TypeError):
            continue

    return entries


def parse_atom_feed(xml_text: str) -> list[tuple[str, str, str]]:
    """Parse a generic Atom feed (GitHub commits, YouTube). Returns (title, url, date)."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    entries = []
    ns = _ATOM_NS
    for entry in root.findall(f"{{{ns}}}entry"):
        title_el = entry.find(f"{{{ns}}}title")
        title = title_el.text.strip() if title_el is not None and title_el.text else ""

        # GitHub commit Atom uses <link rel="alternate"> with href attribute
        url = ""
        for link in entry.findall(f"{{{ns}}}link"):
            href = link.get("href", "")
            if href:
                url = href
                break

        date = _parse_atom_date(entry, ns)

        if url:
            entries.append((title, url, date))

    return entries


def _parse_atom_date(entry: ET.Element, ns: str) -> str:
    """Extract YYYY-MM-DD from <published> or <updated>."""
    for tag in (f"{{{ns}}}published", f"{{{ns}}}updated"):
        el = entry.find(tag)
        if el is not None and el.text:
            # ISO 8601: 2024-01-15T10:00:00Z or 2024-01-15T10:00:00.000-05:00
            raw = el.text.strip()
            # Strip sub-second precision
            raw = re.sub(r"\.\d+", "", raw)
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                return dt.strftime("%Y-%m-%d")
            except ValueError:
                # Best-effort: just take the first 10 chars
                if len(raw) >= 10:
                    return raw[:10]
    return ""


# ─── dedup / seen-URL loading ──────────────────────────────────────────────────

_PENDING_URL_RE = re.compile(r"^\- \[[^\]]*\] \[[^\]]*\]\(([^)]+)\)")


def load_seen_urls(feed_state_path: str, pending_path: str) -> set[str]:
    """
    Return union of URLs from feed-state.json "seen" list and all URLs in
    pending-review.md (regardless of checkbox state).
    """
    seen: set[str] = set()

    # feed-state.json
    if os.path.exists(feed_state_path):
        try:
            with open(feed_state_path) as f:
                state = json.load(f)
            if isinstance(state, dict) and "seen" in state:
                seen.update(state["seen"])
        except (json.JSONDecodeError, OSError):
            pass

    # pending-review.md
    if os.path.exists(pending_path):
        try:
            with open(pending_path) as f:
                for line in f:
                    m = _PENDING_URL_RE.match(line)
                    if m:
                        seen.add(m.group(1))
        except OSError:
            pass

    return seen


def dedup_entries(
    entries: list[tuple[str, str, str]],
    seen_urls: set[str],
) -> list[tuple[str, str, str]]:
    """Remove entries whose URL is already in seen_urls."""
    return [(t, u, d) for t, u, d in entries if u not in seen_urls]


# ─── blog platform classifier ──────────────────────────────────────────────────

def classify_blog_source(html_url: str) -> str:
    """
    Classify a blog URL by its hosting platform without making an HTTP request.
    Returns: "blogger" | "wordpress" | "github" | "squarespace" | "unknown"

    Platform detection is best-effort; wordpress sites are probed at runtime
    since there is no reliable URL-only heuristic.
    """
    url_lower = html_url.lower()
    if "blogspot.com" in url_lower or "blogger.com" in url_lower:
        return "blogger"
    if "github.com" in url_lower:
        return "github"
    if "squarespace.com" in url_lower or "squarespace-cdn.com" in url_lower:
        return "squarespace"
    # WordPress can't be detected from the URL alone without an HTTP probe
    return "unknown"


# ─── artifact co-occurrence extraction ────────────────────────────────────────

def extract_related_artifacts(text: str) -> list[str]:
    """
    Scan blog post text for known artifact names/phrases and return
    a deduplicated list of catalog artifact IDs.

    This is the primary source for the `related` field in ArtifactDescriptor:
    when a post discusses ShimCache and Prefetch together, both appear in
    each other's related lists.
    """
    if not text:
        return []

    text_lower = text.lower()
    found: set[str] = set()

    for phrase, artifact_id in _ARTIFACT_PHRASES:
        if phrase in text_lower:
            found.add(artifact_id)

    return sorted(found)


# ─── HTTP helpers ──────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: int = 30) -> str | None:
    """Fetch URL, return text content or None on error."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="replace")
    except Exception as exc:
        print(f"  [WARN] fetch failed: {url} — {exc}", file=sys.stderr)
        return None


def head_check(url: str, timeout: int = 15) -> tuple[str, str]:
    """Returns ("gone", "HTTP 404"), ("ok", "HTTP 200"), or ("skip", reason)."""
    try:
        req = urllib.request.Request(
            url, method="HEAD", headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return "ok", f"HTTP {resp.getcode()}"
    except urllib.error.HTTPError as exc:
        if exc.code in _GONE_CODES:
            return "gone", f"HTTP {exc.code}"
        return "skip", f"HTTP {exc.code}"
    except Exception as exc:
        return "skip", str(exc)


# ─── platform-aware archive fetchers ──────────────────────────────────────────

def fetch_blogger_archive(
    feed_url: str,
    max_pages: int = 50,
) -> list[tuple[str, str, str]]:
    """
    Fetch all posts from a Blogger/Atom feed using start-index pagination.
    Returns list of (title, url, date).
    """
    all_entries: list[tuple[str, str, str]] = []
    page_size = 150
    start = 1

    for _ in range(max_pages):
        url = f"{feed_url}?max-results={page_size}&start-index={start}"
        text = _fetch(url)
        if not text:
            break
        page = parse_blogger_feed(text)
        if not page:
            break
        all_entries.extend(page)
        if len(page) < page_size:
            break  # last page
        start += page_size

    return all_entries


def fetch_wordpress_archive(
    html_url: str,
    max_pages: int = 50,
) -> list[tuple[str, str, str]]:
    """
    Fetch all posts via WordPress REST API (/wp-json/wp/v2/posts).
    Falls back to RSS page pagination if REST API is unavailable.
    Returns list of (title, url, date).
    """
    base = html_url.rstrip("/")
    all_entries: list[tuple[str, str, str]] = []

    # Try REST API first
    for page in range(1, max_pages + 1):
        api_url = f"{base}/wp-json/wp/v2/posts?per_page=100&page={page}&_fields=title,link,date"
        text = _fetch(api_url)
        if not text:
            break
        try:
            posts = json.loads(text)
        except json.JSONDecodeError:
            break
        if not isinstance(posts, list) or not posts:
            break
        all_entries.extend(parse_wordpress_posts(text))
        if len(posts) < 100:
            break  # last page

    if all_entries:
        return all_entries

    # Fallback: RSS pagination
    # Try to find the feed URL from the html_url by checking common paths
    for feed_path in ("/feed/", "/rss/", "/?feed=rss2"):
        feed_url = base + feed_path
        for page in range(1, max_pages + 1):
            paged_url = f"{feed_url}?paged={page}"
            text = _fetch(paged_url)
            if not text:
                break
            page_entries = parse_blogger_feed(text)  # Atom parser works for WP too
            if not page_entries:
                break
            all_entries.extend(page_entries)
            if len(page_entries) < 10:
                break
        if all_entries:
            break

    return all_entries


def fetch_atom_first_page(feed_url: str) -> list[tuple[str, str, str]]:
    """
    Fetch just the first page of a generic Atom feed (GitHub, YouTube).
    For LOL datasets, use fetch_*.py scripts for full current state instead.
    """
    text = _fetch(feed_url)
    if not text:
        return []
    return parse_atom_feed(text)


# ─── OPML reader ──────────────────────────────────────────────────────────────

def read_opml(opml_path: str) -> list[dict]:
    """
    Parse OPML and return list of {title, xml_url, html_url, type} dicts.
    Only type="rss" outlines are included.
    """
    tree = ET.parse(opml_path)
    root = tree.getroot()
    sources = []
    for outline in root.iter("outline"):
        if outline.get("type") == "rss":
            sources.append({
                "title": outline.get("title", outline.get("text", "")),
                "xml_url": outline.get("xmlUrl", ""),
                "html_url": outline.get("htmlUrl", ""),
            })
    return sources


# ─── pending-review writer ────────────────────────────────────────────────────

def today_str() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


def append_to_pending(
    pending_path: str,
    entries: list[tuple[str, str, str]],
    source_title: str,
    validate: bool = True,
    dry_run: bool = False,
) -> tuple[int, int]:
    """
    Append new entries to pending-review.md.
    Returns (appended, broken) counts.
    """
    appended = 0
    broken = 0
    lines = []

    for title, url, _date in entries:
        status = "ok"
        note = ""
        if validate:
            status, note = head_check(url)

        if status == "gone":
            line = f"- [!] [{title}]({url}) — {source_title} <!-- {note} on {today_str()} -->\n"
            broken += 1
        else:
            line = f"- [ ] [{title}]({url}) — {source_title}\n"
            appended += 1

        lines.append(line)

    if dry_run:
        for line in lines:
            print(line, end="")
        return appended, broken

    if lines:
        os.makedirs(os.path.dirname(os.path.abspath(pending_path)), exist_ok=True)
        with open(pending_path, "a") as f:
            f.writelines(lines)

    return appended, broken


# ─── main ─────────────────────────────────────────────────────────────────────

def _build_arg_parser():
    import argparse
    p = argparse.ArgumentParser(
        description="Full-archive backfill for DFIR blog sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--opml",
        default="archive/sources/dfir-feeds.opml",
        help="OPML feed file",
    )
    p.add_argument(
        "--pending",
        default="archive/sources/pending-review.md",
        help="pending-review.md path",
    )
    p.add_argument(
        "--state",
        default="archive/sources/feed-state.json",
        help="feed-state.json path",
    )
    p.add_argument(
        "--source",
        default=None,
        help="Limit to one source (partial match on title)",
    )
    p.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip HEAD-checking new URLs",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be added, don't write",
    )
    p.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Max pagination pages per source (default: 50)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    sources = read_opml(args.opml)
    seen = load_seen_urls(args.state, args.pending)

    total_appended = 0
    total_broken = 0

    for src in sources:
        title = src["title"]
        xml_url = src["xml_url"]
        html_url = src["html_url"]

        # Apply filter
        if args.source and args.source.lower() not in title.lower():
            continue

        # Skip low-signal sources
        if title in _SKIP_TITLES:
            print(f"[SKIP] {title}")
            continue

        print(f"[FETCH] {title} ...", end=" ", flush=True)

        platform = classify_blog_source(html_url)

        # Fetch based on platform
        if platform == "blogger":
            entries = fetch_blogger_archive(xml_url, max_pages=args.max_pages)
        elif platform == "github":
            # GitHub Atom: first page only — LOL datasets use fetch_*.py
            entries = fetch_atom_first_page(xml_url)
        else:
            # Attempt WordPress REST API (works for most custom domains too)
            entries = fetch_wordpress_archive(html_url, max_pages=args.max_pages)
            if not entries:
                # Fallback: parse the XML feed as Atom
                text = _fetch(xml_url)
                if text:
                    entries = parse_blogger_feed(text) or parse_atom_feed(text)
                else:
                    entries = []

        new = dedup_entries(entries, seen)
        # Update seen so we don't re-add within the same run
        seen.update(u for _, u, _ in new)

        print(f"{len(entries)} fetched, {len(new)} new")

        if new:
            added, broken = append_to_pending(
                args.pending,
                new,
                title,
                validate=not args.no_validate,
                dry_run=args.dry_run,
            )
            total_appended += added
            total_broken += broken

    print(f"\nDone: {total_appended} new entries appended, {total_broken} broken URLs marked [!]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
