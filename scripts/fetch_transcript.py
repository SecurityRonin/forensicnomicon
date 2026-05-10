#!/usr/bin/env python3
"""Fetch transcript or body text for podcast and video URLs.

Supports:
  - YouTube watch/short/embed URLs → auto-caption via timedtext API (no key needed)
  - Forensic Focus /podcast/* URLs → page body text (show notes / transcript)

Also provides is_noise_url() for classifying zero-value feed entries that
should be auto-skipped without review (vendor roundups, acquisition news, etc.).

Usage (CLI):
  python3 scripts/fetch_transcript.py <url>
  # exits 0 and prints transcript, or exits 1 if none available
"""

from __future__ import annotations

import re
import sys
import urllib.parse
import urllib.request
from html.parser import HTMLParser

USER_AGENT = "forensic-catalog-feed-watcher/0.3 (+https://github.com/SecurityRonin/forensicnomicon)"

# ── YouTube ID extraction ─────────────────────────────────────────────────────

_YT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:youtube\.com/watch\?[^#]*v=)([A-Za-z0-9_-]{11})"),
    re.compile(r"youtu\.be/([A-Za-z0-9_-]{11})"),
    re.compile(r"youtube\.com/embed/([A-Za-z0-9_-]{11})"),
]


def extract_youtube_id(url: str) -> str | None:
    """Return the 11-character video ID from a YouTube URL, or None."""
    for pattern in _YT_PATTERNS:
        m = pattern.search(url)
        if m:
            return m.group(1)
    return None


# ── VTT stripping ─────────────────────────────────────────────────────────────

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_TIMESTAMP_RE = re.compile(r"-->")
_SEQUENCE_RE = re.compile(r"^\d+$")


def _strip_vtt(vtt: str) -> str:
    """Strip VTT metadata and return deduplicated caption text as a single string."""
    seen: set[str] = set()
    parts: list[str] = []
    for line in vtt.splitlines():
        line = line.strip()
        if not line:
            continue
        if line == "WEBVTT":
            continue
        if _TIMESTAMP_RE.search(line):
            continue
        if _SEQUENCE_RE.match(line):
            continue
        line = _HTML_TAG_RE.sub("", line).strip()
        if line and line not in seen:
            seen.add(line)
            parts.append(line)
    return " ".join(parts)


# ── HTML text extractor ───────────────────────────────────────────────────────

class _TextExtractor(HTMLParser):
    """Extract visible body text from HTML, skipping chrome tags."""

    _SKIP: frozenset[str] = frozenset(
        {"script", "style", "nav", "header", "footer", "aside", "form"}
    )

    def __init__(self) -> None:
        super().__init__()
        self._depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:  # type: ignore[override]
        if tag in self._SKIP:
            self._depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._depth > 0:
            self._depth -= 1

    def handle_data(self, data: str) -> None:
        if self._depth == 0:
            text = data.strip()
            if text:
                self._parts.append(text)

    def get_text(self) -> str:
        return " ".join(self._parts)


# ── Fetchers ──────────────────────────────────────────────────────────────────

def fetch_youtube_transcript(video_id: str) -> str | None:
    """Fetch YouTube auto-caption transcript via the timedtext API.

    No API key required. Returns deduplicated plain text, or None if
    no captions are available or the request fails.
    """
    url = (
        f"https://www.youtube.com/api/timedtext"
        f"?v={video_id}&lang=en&fmt=vtt"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        if not raw.strip():
            return None
        return _strip_vtt(raw) or None
    except Exception:
        return None


def fetch_page_text(url: str) -> str | None:
    """Fetch a web page and return its visible text content.

    Strips nav, header, footer, script, style, and aside tags.
    Returns None if the page is empty or the request fails.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
        parser = _TextExtractor()
        parser.feed(html)
        return parser.get_text() or None
    except Exception:
        return None


# ── Noise URL classification ──────────────────────────────────────────────────

# Applied only to forensicfocus.com entries.  Other domains are never classified
# as noise here — their feeds are curated enough not to need blanket filtering.
_FF_NOISE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/news/digital-forensics-round-up-", re.I),
    re.compile(r"/news/forensic-focus-digest-", re.I),
    re.compile(r"-acquires-", re.I),
    re.compile(r"-partners-with-", re.I),
    re.compile(r"-joins-", re.I),
]


def is_noise_url(url: str) -> bool:
    """Return True if this URL is a known zero-artifact-value entry.

    Only classifies forensicfocus.com URLs; all other domains return False.
    Noise patterns: weekly roundups, digest newsletters, acquisition/partnership
    announcements — content that has no new artifact or forensic technique detail.

    Per CLAUDE.md scope boundary: tool release news (e.g. "Passware decrypts
    Samsung S10") is NOT noise — it names a platform artifact in context.
    """
    parsed = urllib.parse.urlparse(url)
    if "forensicfocus.com" not in parsed.netloc:
        return False
    return any(p.search(url) for p in _FF_NOISE_PATTERNS)


# ── Public dispatch ───────────────────────────────────────────────────────────

def fetch_transcript(url: str) -> str | None:
    """Return text content for a URL suitable for artifact review.

    - YouTube watch / short / embed URLs → auto-caption transcript
    - forensicfocus.com /podcast/* URLs → page body text (show notes)
    - Everything else → None (use standard fetch in the review skill)
    """
    if not url:
        return None

    vid = extract_youtube_id(url)
    if vid:
        return fetch_youtube_transcript(vid)

    parsed = urllib.parse.urlparse(url)
    if "forensicfocus.com" in parsed.netloc and parsed.path.startswith("/podcast/"):
        return fetch_page_text(url)

    return None


# ── CLI entrypoint ────────────────────────────────────────────────────────────

def main() -> int:
    if len(sys.argv) < 2:
        print("usage: fetch_transcript.py <url>", file=sys.stderr)
        return 1
    result = fetch_transcript(sys.argv[1])
    if result:
        print(result)
        return 0
    print("No transcript available for this URL.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
