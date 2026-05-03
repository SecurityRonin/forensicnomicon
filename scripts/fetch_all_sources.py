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

Sources SKIPPED (not blog posts — no artifact documentation content):
    URLhaus, MalwareBazaar, ThreatFox — IOC feeds, thousands of entries/day
    MISP taxonomies — taxonomy YAML commits, not investigative content
    LOL datasets (LOLBAS, GTFOBins, etc.) — use fetch_lolbas.py etc. for structured data
    YouTube — handled separately via --youtube-api-key flag
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Callable


def _load_dotenv(path: str = ".env") -> None:
    """Load KEY=VALUE pairs from .env into os.environ (stdlib only, no overwrite)."""
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()

# ─── constants ────────────────────────────────────────────────────────────────

USER_AGENT = (
    "forensicnomicon-backfill/1.0 "
    "(https://github.com/SecurityRonin/forensicnomicon; DFIR research)"
)

# Only HTTP 404/410 are "definitively gone" — transient errors do not trigger [!]
_GONE_CODES = frozenset({404, 410})

# Sources to skip for backfill.
# Rationale for each exclusion is documented — remove from this set
# if you want complete coverage (at the cost of more noise to review).
_SKIP_TITLES = frozenset({
    # Pure IOC/threat-intel feeds — not artifact documentation
    "URLhaus",
    "MalwareBazaar",
    "ThreatFox",
    "abuse.ch blog",  # abuse.ch suite hub — IOC feeds, not artifact walkthroughs
    # Taxonomy commits — not blog posts
    "MISP taxonomies",
    # LOL datasets — use fetch_*.py scripts for full current state
    "LOLBAS Project (Windows)",
    "GTFOBins (Linux)",
    "LOOBins (macOS)",
    "LOLDrivers (BYOVD)",
    "LOFL Project (RMM C2 indicators)",
    # YouTube — handled separately via --youtube-api-key flag
    # Without key: first-page Atom only (15 videos); with key: full channel history
})

# Blog platforms that have no WordPress REST API.
# For these, xmlUrl is the only viable source — do NOT attempt WP API fallback.
_XMLURL_ONLY_PLATFORMS = frozenset({
    "ghost.io",        # Ghost CMS (dfir.blog, salt4n6.com, etc.)
    "squarespace.com", # Squarespace (mac4n6.com)
    "hubspot.com",     # HubSpot (binalyze.com)
    "jekyll",          # Jekyll static sites (andreafortuna.org, dfir.science)
    "hugo",            # Hugo static sites
})

# Atom XML namespace
_ATOM_NS = "http://www.w3.org/2005/Atom"

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


def parse_github_commits(json_text: str) -> list[tuple[str, str, str]]:
    """Parse GitHub REST API commits response. Returns (title, url, date).

    title = first line of commit message (multi-line stripped).
    url   = html_url (commit page, fetchable for artifact signal).
    date  = YYYY-MM-DD from commit.author.date.
    """
    try:
        data = json.loads(json_text)
    except (json.JSONDecodeError, ValueError):
        return []

    entries = []
    for item in data:
        try:
            message = item["commit"]["message"]
            title = message.splitlines()[0].strip()
            url = item["html_url"]
            raw_date = item["commit"]["author"]["date"]  # 2024-04-01T08:00:00Z
            date = raw_date[:10]
            if title and url:
                entries.append((title, url, date))
        except (KeyError, IndexError):
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


def parse_rss_xml(xml_text: str) -> list[tuple[str, str, str]]:
    """Unified Atom + RSS 2.0 parser for any feed delivered via xmlUrl.

    Tries Atom namespace first (covers Blogger, GitHub, YouTube, most Jekyll/Hugo
    blogs). Falls back to RSS 2.0 <item> parsing for Ghost, Squarespace, and other
    platforms that emit standard RSS instead of Atom.

    Returns list of (title, url, date YYYY-MM-DD).
    """
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    # Atom feed: root tag contains Atom namespace
    if _ATOM_NS in (root.tag or ""):
        return parse_atom_feed(xml_text)  # already handles Atom

    # Blogger Atom: may also be parsed the same way
    ns = _ATOM_NS
    if root.findall(f"{{{ns}}}entry"):
        return parse_atom_feed(xml_text)

    # RSS 2.0: <rss> or <feed> root with <channel><item>
    return _parse_rss2(root)


def _parse_rss2(root: ET.Element) -> list[tuple[str, str, str]]:
    """Parse RSS 2.0 <channel><item> structure."""
    import email.utils

    entries = []
    # Handle both <rss><channel> and bare <channel>
    channels = root.findall("channel") or ([root] if root.tag == "channel" else [])
    for channel in channels:
        for item in channel.findall("item"):
            title_el = item.find("title")
            title = (title_el.text or "").strip() if title_el is not None else ""

            link_el = item.find("link")
            url = (link_el.text or "").strip() if link_el is not None else ""

            date = ""
            pubdate_el = item.find("pubDate")
            if pubdate_el is not None and pubdate_el.text:
                raw = pubdate_el.text.strip()
                try:
                    # RFC 2822: "Mon, 01 Apr 2024 12:00:00 GMT"
                    dt = email.utils.parsedate_to_datetime(raw)
                    date = dt.strftime("%Y-%m-%d")
                except Exception:
                    # Best-effort fallback
                    if len(raw) >= 10:
                        date = raw[:10]

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


def locked_write(path: str, transform_fn: Callable[[str], str]) -> None:
    """
    Read-modify-write `path` under an exclusive lockfile, cross-platform.

    Uses `path + ".lock"` as the lock. The lockfile contains the writer's PID
    so stale locks from crashed processes are detected and stolen.

    transform_fn receives the current file content (empty string if file does
    not exist) and returns the new content to write.
    """
    lock_path = path + ".lock"

    # Acquire lock — spin with 0.1s sleep until we own it or steal a dead one
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            break  # we own the lock
        except FileExistsError:
            # Check if the locking PID is still alive
            try:
                with open(lock_path) as lf:
                    pid_str = lf.read().strip()
                pid = int(pid_str)
                # os.kill(pid, 0) raises OSError if process doesn't exist
                os.kill(pid, 0)
                time.sleep(0.1)  # process alive — wait
            except (OSError, ValueError):
                # Dead PID or unreadable lockfile — steal it
                try:
                    os.remove(lock_path)
                except OSError:
                    pass

    try:
        # Read current content
        try:
            with open(path) as f:
                content = f.read()
        except OSError:
            content = ""

        new_content = transform_fn(content)

        # Atomic write via temp file + rename
        tmp_path = path + ".tmp"
        with open(tmp_path, "w") as f:
            f.write(new_content)
        os.replace(tmp_path, path)
    finally:
        try:
            os.remove(lock_path)
        except OSError:
            pass


def load_seen_urls(pending_path: str) -> set[str]:
    """
    Return all URLs already present in pending-review.md (any marker state).
    Used to prevent duplicate entries when re-running the fetch.
    """
    seen: set[str] = set()
    if not os.path.exists(pending_path):
        return seen
    try:
        with open(pending_path) as f:
            for line in f:
                m = _PENDING_URL_RE.match(line)
                if m:
                    seen.add(m.group(1))
    except OSError:
        pass
    return seen


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


def detect_is_wordpress(xml_text: str) -> bool:
    """Return True if the feed was generated by WordPress.

    Checks for a <generator> element whose text contains "wordpress.org"
    (case-insensitive). Works for both http:// and https:// variants.
    Returns False for empty input, non-XML text, or other generators.
    """
    if not xml_text:
        return False
    return "wordpress.org" in xml_text.lower()


def _should_try_wordpress(entries: list, xml_url: str) -> bool:
    """Return True iff the WordPress REST API fallback should be attempted.

    Logic:
    - If xmlUrl already returned entries: the feed is working → no WP needed.
    - If xmlUrl returned nothing AND xml_url is non-empty: try WP as fallback.
    - If there is no xml_url at all: no useful WP endpoint can be guessed.
    """
    if not xml_url:
        return False
    return len(entries) == 0


# ─── artifact co-occurrence extraction ────────────────────────────────────────

def check_related_gaps(artifact_id: str, co_occurring_ids: list[str]) -> list[str]:
    """
    Given an artifact ID and a list of co-occurring artifact IDs (from a blog post),
    return the subset that are NOT already listed in the artifact's `related` array.

    These are candidates to add to the descriptor's `related` field — they represent
    investigation-derived correlations that real DFIR cases show are relevant together.

    Returns [] if:
    - artifact_id is not in the catalog
    - co_occurring_ids is empty
    - all co-occurring IDs are already in related[]

    Reads descriptors by running `cargo run -p forensicnomicon-cli -- dump --dataset catalog`
    so it always reflects the current catalog state without importing Rust.
    """
    if not co_occurring_ids:
        return []

    import subprocess

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    try:
        result = subprocess.run(
            ["cargo", "run", "-q", "-p", "forensicnomicon-cli", "--",
             "dump", "--format", "json", "--dataset", "catalog"],
            capture_output=True, text=True, cwd=repo_root, timeout=60,
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout)
        catalog = data.get("catalog", [])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []

    # Find the target artifact
    target = next((a for a in catalog if a.get("id") == artifact_id), None)
    if target is None:
        return []

    already_related = set(target.get("related", []))
    gaps = [
        aid for aid in co_occurring_ids
        if aid != artifact_id and aid not in already_related
    ]
    return gaps


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


def fetch_youtube_transcript(video_id: str) -> str | None:
    """
    Fetch the transcript for a YouTube video using youtube-transcript-api.

    Returns the full transcript as a single string, or None if:
    - youtube-transcript-api is not installed
    - the video has no captions
    - the video ID does not exist

    The returned text feeds directly into extract_related_artifacts() to find
    artifact co-occurrences from spoken content, not just the sparse HTML page.

    Install: pip install youtube-transcript-api
    """
    try:
        from youtube_transcript_api import YouTubeTranscriptApi
        from youtube_transcript_api._errors import (
            NoTranscriptFound,
            TranscriptsDisabled,
            VideoUnavailable,
        )
    except ImportError:
        return None

    try:
        transcript = YouTubeTranscriptApi.get_transcript(video_id)
        return " ".join(segment["text"] for segment in transcript)
    except (NoTranscriptFound, TranscriptsDisabled, VideoUnavailable):
        return None
    except Exception:
        return None


def fetch_atom_first_page(feed_url: str) -> list[tuple[str, str, str]]:
    """
    Fetch just the first page of a generic Atom feed (YouTube, etc.).
    For LOL datasets, use fetch_*.py scripts for full current state instead.
    """
    text = _fetch(feed_url)
    if not text:
        return []
    return parse_atom_feed(text)


def fetch_github_commits(repo_url: str, max_pages: int = 100) -> list[tuple[str, str, str]]:
    """
    Fetch full commit history for a GitHub repo via the REST API.

    repo_url: any github.com URL for the repo (e.g. https://github.com/owner/repo
              or https://github.com/owner/repo/commits/main.atom)
    Uses GITHUB_TOKEN env var if set (5000 req/hr vs 60 req/hr unauthenticated).

    Each commit page returns up to 100 commits. Paginates until empty page or max_pages.
    """
    # Extract owner/repo from any github.com URL
    m = re.search(r"github\.com/([^/]+/[^/]+)", repo_url)
    if not m:
        return []
    owner_repo = m.group(1).split("/commits")[0].rstrip("/")

    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    all_entries: list[tuple[str, str, str]] = []
    for page in range(1, max_pages + 1):
        api_url = f"https://api.github.com/repos/{owner_repo}/commits?per_page=100&page={page}"
        req = urllib.request.Request(api_url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                text = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError):
            break
        entries = parse_github_commits(text)
        if not entries:
            break
        all_entries.extend(entries)

    return all_entries


def fetch_youtube_channel(channel_id: str, api_key: str, max_results: int = 5000) -> list[tuple[str, str, str]]:
    """
    Fetch full video history for a YouTube channel via YouTube Data API v3.

    Costs ~1 quota unit per 50 videos. Daily quota: 10,000 units.
    A channel with 500 videos costs ~10 units total.

    Args:
        channel_id: The channel ID from the YouTube URL or OPML xmlUrl param.
        api_key: YouTube Data API v3 key from console.cloud.google.com.
        max_results: Safety cap (default 5000).

    Returns:
        List of (title, url, date) tuples, newest-first.
    """
    # Step 1: get the channel's uploads playlist ID
    channel_url = (
        "https://www.googleapis.com/youtube/v3/channels"
        f"?part=contentDetails&id={channel_id}&key={api_key}"
    )
    text = _fetch(channel_url)
    if not text:
        return []
    try:
        data = json.loads(text)
        uploads_playlist = (
            data["items"][0]["contentDetails"]["relatedPlaylists"]["uploads"]
        )
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        print(f"  [WARN] YouTube channel lookup failed: {exc}", file=sys.stderr)
        return []

    # Step 2: paginate through the uploads playlist
    entries: list[tuple[str, str, str]] = []
    page_token = ""

    while len(entries) < max_results:
        playlist_url = (
            "https://www.googleapis.com/youtube/v3/playlistItems"
            f"?part=snippet&playlistId={uploads_playlist}"
            f"&maxResults=50&key={api_key}"
        )
        if page_token:
            playlist_url += f"&pageToken={page_token}"

        text = _fetch(playlist_url)
        if not text:
            break
        try:
            page = json.loads(text)
        except json.JSONDecodeError:
            break

        for item in page.get("items", []):
            snippet = item.get("snippet", {})
            title = snippet.get("title", "")
            video_id = snippet.get("resourceId", {}).get("videoId", "")
            published = snippet.get("publishedAt", "")[:10]
            if video_id and title != "Private video" and title != "Deleted video":
                url = f"https://www.youtube.com/watch?v={video_id}"
                entries.append((title, url, published))

        page_token = page.get("nextPageToken", "")
        if not page_token:
            break

    return entries


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
        kind = outline.get("type", "")
        if kind not in ("rss", "web"):
            continue
        sources.append({
            "title": outline.get("text", outline.get("title", "")),
            "xml_url": outline.get("xmlUrl", ""),
            "html_url": outline.get("htmlUrl", ""),
            "kind": kind,
        })
    return sources


# ─── pending-review writer ────────────────────────────────────────────────────

def today_str() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


def rescan_reviewed_entries(pending_path: str) -> int:
    """
    Re-queue all [x] entries as [ ] for a full rescan.

    A reviewed post yields the same knowledge however many times it is read.
    Re-queuing as [ ] (not a distinct [~] marker) keeps the skill simple:
    all pending items get the same full review regardless of origin.

    Returns the count of entries re-queued.
    """
    if not os.path.exists(pending_path):
        return 0

    reviewed_re = re.compile(r"^- \[x\] (.*)")
    requeued = 0

    def _transform(content: str) -> str:
        nonlocal requeued
        requeued = 0
        new_lines = []
        for line in content.splitlines(keepends=True):
            m = reviewed_re.match(line)
            if m:
                new_lines.append(f"- [ ] {m.group(1)}\n")
                requeued += 1
            else:
                new_lines.append(line)
        return "".join(new_lines)

    locked_write(pending_path, _transform)
    return requeued


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
        block = "".join(lines)
        locked_write(pending_path, lambda c: c + block)

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
    p.add_argument(
        "--youtube-api-key",
        default=os.environ.get("YOUTUBE_API_KEY", ""),
        help="YouTube Data API v3 key for full channel history (env: YOUTUBE_API_KEY)",
    )
    p.add_argument(
        "--rescan",
        action="store_true",
        help=(
            "Re-queue all [x] entries as [ ] so they are re-reviewed in full. "
            "Does not affect [ ], [→], or [!] entries."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Rescan mode: re-queue [x] entries as [~] then exit — no new fetching
    if args.rescan:
        n = rescan_reviewed_entries(args.pending)
        print(f"Re-queued {n} reviewed [x] entries as [ ]")
        print("Run /review-dfir-feeds to process them")
        return 0

    sources = read_opml(args.opml)
    seen = load_seen_urls(args.pending)

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

        kind = src.get("kind", "rss")
        platform = classify_blog_source(html_url)

        # Fetch based on source kind / platform
        if kind == "web":
            # Static HTML site with no RSS — scrape post links from the index page
            html_text = _fetch(html_url)
            entries = []
            if html_text:
                import re as _re
                base = html_url.rstrip("/")
                domain = html_url.split("/")[2]
                # Extract same-domain /post/* or /blog/* or /articles/* links
                hrefs = _re.findall(r'href=["\'](/(?:post|blog|articles)/[^"\'#?]+)["\']', html_text)
                seen_paths: set[str] = set()
                for href in hrefs:
                    if href in seen_paths:
                        continue
                    seen_paths.add(href)
                    full_url = f"https://{domain}{href}"
                    # Use path slug as title placeholder; will be updated on review
                    slug = href.rstrip("/").rsplit("/", 1)[-1].replace("-", " ").title()
                    entries.append((slug, full_url, ""))
        elif platform == "blogger":
            entries = fetch_blogger_archive(xml_url, max_pages=args.max_pages)
        elif platform == "github":
            entries = fetch_github_commits(xml_url)
        elif "youtube.com/feeds" in xml_url:
            # YouTube channel feed
            yt_key = getattr(args, "youtube_api_key", "")
            channel_id_match = re.search(r"channel_id=([A-Za-z0-9_-]+)", xml_url)
            if yt_key and channel_id_match:
                channel_id = channel_id_match.group(1)
                entries = fetch_youtube_channel(channel_id, yt_key)
            else:
                if not yt_key:
                    print("[no API key — fetching first page only]", end=" ", flush=True)
                entries = fetch_atom_first_page(xml_url)
        else:
            # Strategy: try the OPML xmlUrl first (works for Ghost, Squarespace,
            # Hugo, Jekyll, etc.).  Only fall back to WordPress REST API pagination
            # if the feed is missing or returns a small page (≤20 items = paginated).
            entries = []
            if xml_url:
                text = _fetch(xml_url)
                if text:
                    entries = parse_rss_xml(text)

            if _should_try_wordpress(entries, xml_url):
                # xmlUrl returned nothing — try WordPress REST API as fallback
                wp_entries = fetch_wordpress_archive(html_url, max_pages=args.max_pages)
                if wp_entries:
                    entries = wp_entries
            elif entries and xml_url and text and detect_is_wordpress(text):
                # xmlUrl returned some entries but the blog is WordPress — RSS only
                # shows the latest page. Fetch full archive via REST API instead.
                wp_entries = fetch_wordpress_archive(html_url, max_pages=args.max_pages)
                if len(wp_entries) > len(entries):
                    entries = wp_entries

        new = [e for e in entries if e[1] not in seen]
        # Update seen so we don't re-add within the same run
        seen.update(e[1] for e in new)

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
