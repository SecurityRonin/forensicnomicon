#!/usr/bin/env python3
"""Archive a blog into structured JSON and Markdown.

The scraper is intentionally dependency-free so it can run in locked-down
environments. It supports:

- generic XML sitemaps
- generic Atom/RSS feeds
- Blogger/Blogspot feeds and year archives

Example:
    python3 scripts/scrape_blog.py \
        --url https://windowsir.blogspot.com \
        --output research/windowsir
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from html import unescape
from html.parser import HTMLParser
from typing import Iterable


USER_AGENT = "forensic-catalog-blog-scraper/0.1 (+https://github.com/SecurityRonin/forensic-catalog)"
ATOM_NS = {"atom": "http://www.w3.org/2005/Atom", "sitemap": "http://www.sitemaps.org/schemas/sitemap/0.9"}


@dataclass
class Post:
    url: str
    title: str
    published: str
    updated: str
    labels: list[str]
    text: str
    html: str


class BlogPostParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self.labels: list[str] = []
        self._in_title = False
        self._in_label = False
        self._capture_text = False
        self._fragments: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {key: value or "" for key, value in attrs}
        classes = attrs_map.get("class", "")
        if tag in {"h1", "h2", "h3"} and (
            "post-title" in classes or "entry-title" in classes or "title" == classes
        ):
            self._in_title = True
        if tag == "a" and "label" in classes.lower():
            self._in_label = True
        if tag in {"p", "li", "pre", "code", "blockquote", "h1", "h2", "h3", "h4"}:
            self._capture_text = True
        if tag == "br":
            self._fragments.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"h1", "h2", "h3"}:
            self._in_title = False
        if tag == "a":
            self._in_label = False
        if tag in {"p", "li", "pre", "code", "blockquote", "h1", "h2", "h3", "h4"}:
            self._fragments.append("\n")
            self._capture_text = False

    def handle_data(self, data: str) -> None:
        value = data.strip()
        if not value:
            return
        if self._in_title and not self.title:
            self.title = value
        if self._in_label and value not in self.labels:
            self.labels.append(value)
        if self._capture_text:
            self._fragments.append(value)

    @property
    def text(self) -> str:
        return normalize_text(" ".join(self._fragments))


def normalize_text(text: str) -> str:
    text = unescape(text)
    text = text.replace("\r", "")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-{2,}", "-", value)
    return value.strip("-") or "post"


def fetch(url: str, *, delay: float = 0.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{url} returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"failed to fetch {url}: {exc.reason}") from exc
    if delay:
        time.sleep(delay)
    return payload


def parse_atom_posts(feed_xml: bytes) -> list[Post]:
    root = ET.fromstring(feed_xml)
    posts: list[Post] = []
    for entry in root.findall("atom:entry", ATOM_NS):
        link = ""
        for candidate in entry.findall("atom:link", ATOM_NS):
            if candidate.attrib.get("rel") == "alternate":
                link = candidate.attrib.get("href", "")
                break
        if not link:
            continue
        title = entry.findtext("atom:title", default="", namespaces=ATOM_NS).strip()
        published = entry.findtext("atom:published", default="", namespaces=ATOM_NS).strip()
        updated = entry.findtext("atom:updated", default="", namespaces=ATOM_NS).strip()
        html = entry.findtext("atom:content", default="", namespaces=ATOM_NS)
        labels = [category.attrib.get("term", "") for category in entry.findall("atom:category", ATOM_NS)]
        posts.append(
            Post(
                url=link,
                title=title,
                published=published,
                updated=updated,
                labels=[label for label in labels if label],
                text=normalize_text(strip_html(html)),
                html=html,
            )
        )
    return posts


def strip_html(html: str) -> str:
    parser = BlogPostParser()
    parser.feed(html)
    return parser.text


def collect_blogger_feed(base_url: str, *, limit: int | None, delay: float) -> list[Post]:
    posts: list[Post] = []
    start_index = 1
    remaining = limit
    while remaining is None or remaining > 0:
        batch_size = 500 if remaining is None else min(500, remaining)
        feed_url = (
            f"{base_url.rstrip('/')}/feeds/posts/default"
            f"?alt=atom&redirect=false&start-index={start_index}&max-results={batch_size}"
        )
        batch = parse_atom_posts(fetch(feed_url, delay=delay))
        if not batch:
            break
        posts.extend(batch)
        if len(batch) < batch_size:
            break
        start_index += batch_size
        if remaining is not None:
            remaining -= len(batch)
    return dedupe_posts(posts)


def collect_from_sitemap(base_url: str, *, delay: float) -> list[str]:
    sitemap_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "sitemap.xml")
    root = ET.fromstring(fetch(sitemap_url, delay=delay))
    urls = [
        node.text.strip()
        for node in root.findall(".//sitemap:loc", ATOM_NS) + root.findall(".//loc")
        if node.text and "/20" in node.text
    ]
    return sorted(set(urls))


def collect_from_year_archives(base_url: str, *, first_year: int, last_year: int) -> list[str]:
    urls = []
    for year in range(first_year, last_year + 1):
        urls.append(f"{base_url.rstrip('/')}/{year}/")
    return urls


def collect_post_links_from_archive(url: str, *, delay: float) -> list[str]:
    html = fetch(url, delay=delay).decode("utf-8", errors="replace")
    matches = re.findall(r'href="(https?://[^"]+/20\d{2}/\d{2}/[^"]+\.html)"', html)
    return sorted(set(matches))


def parse_post_page(url: str, *, delay: float) -> Post:
    html = fetch(url, delay=delay).decode("utf-8", errors="replace")
    parser = BlogPostParser()
    parser.feed(html)
    title = parser.title or infer_title_from_html(html) or url.rsplit("/", 1)[-1]
    published = infer_meta(html, "published") or infer_meta_property(html, "article:published_time")
    updated = infer_meta(html, "updated") or infer_meta_property(html, "article:modified_time")
    return Post(
        url=url,
        title=title,
        published=published,
        updated=updated,
        labels=parser.labels,
        text=parser.text,
        html=html,
    )


def infer_title_from_html(html: str) -> str:
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return normalize_text(match.group(1)) if match else ""


def infer_meta(html: str, name: str) -> str:
    pattern = rf'<meta[^>]+name="{re.escape(name)}"[^>]+content="([^"]+)"'
    match = re.search(pattern, html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def infer_meta_property(html: str, prop: str) -> str:
    pattern = rf'<meta[^>]+property="{re.escape(prop)}"[^>]+content="([^"]+)"'
    match = re.search(pattern, html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def dedupe_posts(posts: Iterable[Post]) -> list[Post]:
    seen: dict[str, Post] = {}
    for post in posts:
        seen[post.url] = post
    return sorted(seen.values(), key=lambda post: (post.published, post.url))


def write_archive(posts: list[Post], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    posts_dir = os.path.join(output_dir, "posts")
    os.makedirs(posts_dir, exist_ok=True)

    index = []
    for index_number, post in enumerate(posts, start=1):
        slug = slugify(post.title)
        file_stem = f"{index_number:04d}-{slug}"
        md_path = os.path.join(posts_dir, f"{file_stem}.md")
        json_path = os.path.join(posts_dir, f"{file_stem}.json")
        with open(md_path, "w", encoding="utf-8") as handle:
            handle.write(f"# {post.title}\n\n")
            handle.write(f"- URL: {post.url}\n")
            handle.write(f"- Published: {post.published or 'unknown'}\n")
            handle.write(f"- Updated: {post.updated or 'unknown'}\n")
            handle.write(f"- Labels: {', '.join(post.labels) if post.labels else 'none'}\n\n")
            handle.write(post.text)
            handle.write("\n")
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(asdict(post), handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        index.append(
            {
                "title": post.title,
                "url": post.url,
                "published": post.published,
                "updated": post.updated,
                "labels": post.labels,
                "markdown_path": os.path.relpath(md_path, output_dir),
                "json_path": os.path.relpath(json_path, output_dir),
            }
        )

    with open(os.path.join(output_dir, "index.json"), "w", encoding="utf-8") as handle:
        json.dump(index, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="blog base URL, e.g. https://windowsir.blogspot.com")
    parser.add_argument("--output", required=True, help="directory where the archive will be written")
    parser.add_argument(
        "--mode",
        choices=["auto", "blogger-feed", "sitemap", "year-archives"],
        default="auto",
        help="discovery strategy",
    )
    parser.add_argument("--limit", type=int, default=None, help="optional maximum number of posts")
    parser.add_argument("--delay", type=float, default=0.25, help="sleep interval between requests")
    parser.add_argument("--first-year", type=int, default=2006, help="first year to probe for archive pages")
    parser.add_argument("--last-year", type=int, default=time.gmtime().tm_year, help="last year to probe for archive pages")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_url = args.url.rstrip("/")

    if args.mode in {"auto", "blogger-feed"} and "blogspot." in base_url:
        posts = collect_blogger_feed(base_url, limit=args.limit, delay=args.delay)
        if posts:
            write_archive(posts, args.output)
            print(f"archived {len(posts)} posts from Blogger feed into {args.output}")
            return 0
        if args.mode == "blogger-feed":
            print("no posts returned from Blogger feed", file=sys.stderr)
            return 1

    if args.mode in {"auto", "sitemap"}:
        try:
            urls = collect_from_sitemap(base_url, delay=args.delay)
        except Exception:
            urls = []
        if urls:
            posts = [parse_post_page(url, delay=args.delay) for url in urls[: args.limit]]
            write_archive(dedupe_posts(posts), args.output)
            print(f"archived {len(posts)} posts from sitemap into {args.output}")
            return 0
        if args.mode == "sitemap":
            print("no post URLs discovered from sitemap", file=sys.stderr)
            return 1

    if args.mode in {"auto", "year-archives"}:
        archive_urls = collect_from_year_archives(
            base_url,
            first_year=args.first_year,
            last_year=args.last_year,
        )
        post_urls: list[str] = []
        for archive_url in archive_urls:
            try:
                post_urls.extend(collect_post_links_from_archive(archive_url, delay=args.delay))
            except Exception:
                continue
        post_urls = sorted(set(post_urls))
        if args.limit is not None:
            post_urls = post_urls[: args.limit]
        if post_urls:
            posts = [parse_post_page(url, delay=args.delay) for url in post_urls]
            write_archive(dedupe_posts(posts), args.output)
            print(f"archived {len(posts)} posts from year archives into {args.output}")
            return 0
        print("no post URLs discovered from year archive pages", file=sys.stderr)
        return 1

    print("unsupported mode selection", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
