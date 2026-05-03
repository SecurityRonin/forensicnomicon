#!/usr/bin/env python3
"""
discover_feeds.py — systematic blog discovery from DFIR aggregator sites.

Fetches known aggregator pages (AboutDFIR, DFIR Training, This Week In 4n6,
Forensic Focus), extracts external blog links, and reports which blogs are
not yet in dfir-feeds.opml.

Usage:
    python scripts/discover_feeds.py
    python scripts/discover_feeds.py --opml archive/sources/dfir-feeds.opml
    python scripts/discover_feeds.py --probe   # probe each gap for a feed URL
    python scripts/discover_feeds.py --add     # print OPML entries ready to paste
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from xml.etree import ElementTree

# ─── Aggregator pages to scan ────────────────────────────────────────────────

AGGREGATORS: list[dict] = [
    {
        "name": "AboutDFIR",
        "url": "https://aboutdfir.com/",
    },
    {
        "name": "DFIR Training — Blogs",
        "url": "https://www.dfir.training/dfir-training-categories-k2/itemlist/category/9-blogs",
    },
    {
        "name": "This Week In 4n6",
        "url": "https://thisweekin4n6.com/",
    },
    {
        "name": "Forensic Focus — Blogs",
        "url": "https://www.forensicfocus.com/blogs/",
    },
    {
        "name": "The DFIR Report — Resources",
        "url": "https://thedfirreport.com/resources/",
    },
]

# Common feed URL suffixes to probe, in priority order
_FEED_CANDIDATES = [
    "/feed/",
    "/feed.xml",
    "/rss/",
    "/rss.xml",
    "/atom.xml",
    "/feeds/posts/default",   # Blogger
    "/index.xml",
]

# Domains/patterns that are NOT blogs
_NON_BLOG_DOMAINS = {
    "twitter.com", "x.com", "facebook.com", "linkedin.com",
    "youtube.com", "youtu.be", "instagram.com", "reddit.com",
    "github.com", "gitlab.com", "bitbucket.org",
    "amazon.com", "aws.amazon.com", "microsoft.com", "google.com",
    "attack.mitre.org", "mitre.org",
    "nirsoft.net",
    "virustotal.com", "shodan.io",
    "cve.mitre.org", "nvd.nist.gov",
    "doi.org", "arxiv.org",
    "pastebin.com", "gist.github.com",
    "slack.com", "discord.com", "discord.gg",
}

_NON_BLOG_EXTENSIONS = {".pdf", ".zip", ".docx", ".pptx", ".xlsx", ".exe", ".png", ".jpg"}


# ─── Pure logic functions (fully testable, no HTTP) ──────────────────────────

def normalize_domain(url: str) -> str:
    """Return the bare domain (no www, no path, lowercase) for a URL."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def parse_opml_domains(opml_text: str) -> set[str]:
    """Return the set of normalized domains from all htmlUrl attributes in an OPML string."""
    try:
        root = ElementTree.fromstring(opml_text)
    except ElementTree.ParseError:
        return set()
    domains: set[str] = set()
    for outline in root.iter("outline"):
        html_url = outline.get("htmlUrl", "")
        if html_url:
            domains.add(normalize_domain(html_url))
    return domains


class _LinkExtractor(HTMLParser):
    def __init__(self, base_domain: str) -> None:
        super().__init__()
        self._base_domain = base_domain
        self._current_href: str | None = None
        self._current_text: list[str] = []
        self._links: dict[str, str] = {}  # domain → (text, url)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._current_href = None
            self._current_text = []
            for name, val in attrs:
                if name == "href" and val:
                    self._current_href = val

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href:
            text = " ".join(self._current_text).strip()
            url = self._current_href
            if text and url.startswith("http"):
                domain = normalize_domain(url)
                if domain and domain != self._base_domain and domain not in self._links:
                    self._links[domain] = (text, url)
            self._current_href = None
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def results(self) -> list[tuple[str, str]]:
        return [(text, url) for text, url in self._links.values()]


def extract_blog_links(html: str, base_url: str) -> list[tuple[str, str]]:
    """Extract (title, url) pairs of external links from aggregator HTML.

    Deduplicates by domain. Skips same-domain, empty-text, and relative links.
    """
    base_domain = normalize_domain(base_url)
    parser = _LinkExtractor(base_domain)
    parser.feed(html)
    return parser.results()


def is_blog_candidate(url: str) -> bool:
    """Return True if a URL looks like a personal/team blog rather than a tool/social site."""
    parsed = urllib.parse.urlparse(url)
    domain = normalize_domain(url)

    # Check non-blog domain list
    for blocked in _NON_BLOG_DOMAINS:
        if domain == blocked or domain.endswith("." + blocked):
            return False

    # Check file extension
    path = parsed.path.lower()
    for ext in _NON_BLOG_EXTENSIONS:
        if path.endswith(ext):
            return False

    return True


def find_gaps(
    links: list[tuple[str, str]],
    known_domains: set[str],
) -> list[tuple[str, str]]:
    """Return links whose domain is not in known_domains (www-normalised)."""
    gaps: list[tuple[str, str]] = []
    for text, url in links:
        domain = normalize_domain(url)
        if domain not in known_domains:
            gaps.append((text, url))
    return gaps


# ─── HTTP functions (not unit-tested) ────────────────────────────────────────

def _fetch(url: str, timeout: int = 15) -> str | None:
    """Fetch a URL and return text, or None on failure."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "forensicnomicon-discover-feeds/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            charset = "utf-8"
            ct = resp.headers.get_content_charset()
            if ct:
                charset = ct
            return resp.read().decode(charset, errors="replace")
    except Exception:
        return None


def probe_for_feed(url: str, timeout: int = 10) -> str | None:
    """Try common feed paths for a blog URL. Return the first 200 URL or None."""
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for suffix in _FEED_CANDIDATES:
        candidate = base + suffix
        try:
            req = urllib.request.Request(
                candidate,
                method="HEAD",
                headers={"User-Agent": "forensicnomicon-discover-feeds/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    return candidate
        except Exception:
            continue
    return None


# ─── Main ─────────────────────────────────────────────────────────────────────

def _load_opml_domains(opml_path: str) -> set[str]:
    try:
        with open(opml_path, encoding="utf-8") as f:
            return parse_opml_domains(f.read())
    except OSError as e:
        print(f"[ERROR] Cannot read OPML: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--opml",
        default="archive/sources/dfir-feeds.opml",
        help="Path to dfir-feeds.opml (default: archive/sources/dfir-feeds.opml)",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Probe each gap blog for a feed URL",
    )
    parser.add_argument(
        "--add",
        action="store_true",
        help="Print ready-to-paste OPML <outline> entries for each gap",
    )
    args = parser.parse_args()

    known = _load_opml_domains(args.opml)
    print(f"[OPML] {len(known)} domains already watched\n")

    all_gaps: list[tuple[str, str, str]] = []  # (source, title, url)

    for agg in AGGREGATORS:
        name = agg["name"]
        url = agg["url"]
        print(f"[FETCH] {name} ({url})")
        html = _fetch(url)
        if html is None:
            print(f"  [WARN] fetch failed\n")
            continue

        links = [
            (t, u) for t, u in extract_blog_links(html, url)
            if is_blog_candidate(u)
        ]
        gaps = find_gaps(links, known)
        print(f"  {len(links)} external blog links → {len(gaps)} not in OPML")
        for title, gap_url in gaps:
            all_gaps.append((name, title, gap_url))
        print()

    if not all_gaps:
        print("No gaps found — OPML is comprehensive.")
        return 0

    print(f"{'─'*60}")
    print(f"GAPS ({len(all_gaps)} blogs not in OPML)")
    print(f"{'─'*60}")

    for source, title, url in sorted(all_gaps, key=lambda x: x[2]):
        feed_url = ""
        if args.probe:
            feed_url = probe_for_feed(url) or ""
            feed_suffix = f"  feed: {feed_url}" if feed_url else "  feed: (not found)"
        else:
            feed_suffix = ""

        print(f"  [{source}] {title}")
        print(f"    {url}{feed_suffix}")

        if args.add and (feed_url or args.probe is False):
            xml_url = feed_url or "UNKNOWN"
            safe_title = title.replace('"', "&quot;").replace("&", "&amp;")
            safe_url = url.replace("&", "&amp;")
            safe_feed = xml_url.replace("&", "&amp;")
            print(f'    <outline type="rss" text="{safe_title}" title="{safe_title}"'
                  f' xmlUrl="{safe_feed}" htmlUrl="{safe_url}"/>')
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
