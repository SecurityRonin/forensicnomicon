"""
RED tests for scripts/discover_feeds.py

Systematic blog discovery from DFIR aggregator sites.
Pure-logic functions only — no HTTP in unit tests.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestNormalizeDomain:
    def test_strips_www(self):
        from discover_feeds import normalize_domain
        assert normalize_domain("https://www.andreafortuna.org/") == "andreafortuna.org"

    def test_strips_path(self):
        from discover_feeds import normalize_domain
        assert normalize_domain("https://dfir.blog/some/post/") == "dfir.blog"

    def test_lowercases(self):
        from discover_feeds import normalize_domain
        assert normalize_domain("https://DFIR.Blog/") == "dfir.blog"

    def test_no_www(self):
        from discover_feeds import normalize_domain
        assert normalize_domain("https://andreafortuna.org/feed.xml") == "andreafortuna.org"

    def test_blogspot_subdomain_preserved(self):
        from discover_feeds import normalize_domain
        # windowsir.blogspot.com is the identity — don't collapse to blogspot.com
        assert normalize_domain("https://windowsir.blogspot.com/") == "windowsir.blogspot.com"

    def test_strips_trailing_slash(self):
        from discover_feeds import normalize_domain
        assert normalize_domain("https://dfir.blog/") == "dfir.blog"


class TestParseOpmlDomains:
    OPML = """<?xml version="1.0"?>
<opml version="1.0">
  <body>
    <outline text="DFIR Blogs">
      <outline type="rss" text="Windows IR" htmlUrl="https://windowsir.blogspot.com/" xmlUrl="x"/>
      <outline type="rss" text="Andrea Fortuna" htmlUrl="https://www.andreafortuna.org/" xmlUrl="y"/>
    </outline>
    <outline text="Vendor Blogs">
      <outline type="rss" text="Binalyze" htmlUrl="https://www.binalyze.com/blog" xmlUrl="z"/>
    </outline>
  </body>
</opml>"""

    def test_extracts_all_domains(self):
        from discover_feeds import parse_opml_domains
        domains = parse_opml_domains(self.OPML)
        assert "windowsir.blogspot.com" in domains
        assert "andreafortuna.org" in domains
        assert "binalyze.com" in domains

    def test_strips_www(self):
        from discover_feeds import parse_opml_domains
        domains = parse_opml_domains(self.OPML)
        assert "www.andreafortuna.org" not in domains

    def test_empty_opml(self):
        from discover_feeds import parse_opml_domains
        assert parse_opml_domains("<opml><body></body></opml>") == set()

    def test_missing_htmlurl_skipped(self):
        from discover_feeds import parse_opml_domains
        opml = '<opml><body><outline type="rss" text="X" xmlUrl="y"/></body></opml>'
        assert parse_opml_domains(opml) == set()

    def test_returns_set(self):
        from discover_feeds import parse_opml_domains
        result = parse_opml_domains(self.OPML)
        assert isinstance(result, set)


class TestExtractBlogLinks:
    def test_extracts_href_with_text(self):
        from discover_feeds import extract_blog_links
        html = '<a href="https://dfir.blog/">DFIR Blog</a>'
        links = extract_blog_links(html, "https://aboutdfir.com/")
        assert ("DFIR Blog", "https://dfir.blog/") in links

    def test_skips_same_domain_links(self):
        from discover_feeds import extract_blog_links
        html = '<a href="https://aboutdfir.com/resources">Resources</a>'
        links = extract_blog_links(html, "https://aboutdfir.com/")
        assert not any("aboutdfir.com" in url for _, url in links)

    def test_skips_empty_text_links(self):
        from discover_feeds import extract_blog_links
        html = '<a href="https://dfir.blog/"></a>'
        links = extract_blog_links(html, "https://aboutdfir.com/")
        assert all(text.strip() for text, _ in links)

    def test_skips_whitespace_only_text(self):
        from discover_feeds import extract_blog_links
        html = '<a href="https://dfir.blog/">   </a>'
        links = extract_blog_links(html, "https://aboutdfir.com/")
        assert all(text.strip() for text, _ in links)

    def test_deduplicates_by_domain(self):
        from discover_feeds import extract_blog_links
        html = ('<a href="https://dfir.blog/">Blog</a>'
                '<a href="https://dfir.blog/post/1">Post 1</a>')
        links = extract_blog_links(html, "https://aboutdfir.com/")
        domains = [url.split("/")[2] for _, url in links]
        assert len(domains) == len(set(domains))

    def test_handles_relative_urls(self):
        from discover_feeds import extract_blog_links
        # relative links should be skipped (no cross-domain discovery possible)
        html = '<a href="/resources/blogs">Blogs</a>'
        links = extract_blog_links(html, "https://aboutdfir.com/")
        assert not any("aboutdfir.com" not in url for _, url in links
                       if url.startswith("http"))

    def test_multiple_distinct_blogs(self):
        from discover_feeds import extract_blog_links
        html = ('<a href="https://dfir.blog/">DFIR Blog</a>'
                '<a href="https://andreafortuna.org/">Andrea Fortuna</a>')
        links = extract_blog_links(html, "https://aboutdfir.com/")
        urls = [url for _, url in links]
        assert any("dfir.blog" in u for u in urls)
        assert any("andreafortuna.org" in u for u in urls)


class TestIsBlogCandidate:
    def test_plain_blog_accepted(self):
        from discover_feeds import is_blog_candidate
        assert is_blog_candidate("https://andreafortuna.org/") is True

    def test_blogspot_accepted(self):
        from discover_feeds import is_blog_candidate
        assert is_blog_candidate("https://windowsir.blogspot.com/") is True

    def test_twitter_rejected(self):
        from discover_feeds import is_blog_candidate
        assert is_blog_candidate("https://twitter.com/someone") is False

    def test_x_com_rejected(self):
        from discover_feeds import is_blog_candidate
        assert is_blog_candidate("https://x.com/someone") is False

    def test_github_rejected(self):
        from discover_feeds import is_blog_candidate
        assert is_blog_candidate("https://github.com/LOLBAS-Project") is False

    def test_youtube_rejected(self):
        from discover_feeds import is_blog_candidate
        assert is_blog_candidate("https://youtube.com/watch?v=abc") is False

    def test_linkedin_rejected(self):
        from discover_feeds import is_blog_candidate
        assert is_blog_candidate("https://linkedin.com/in/someone") is False

    def test_amazon_tool_rejected(self):
        from discover_feeds import is_blog_candidate
        assert is_blog_candidate("https://aws.amazon.com/s3/") is False

    def test_mitre_rejected(self):
        from discover_feeds import is_blog_candidate
        assert is_blog_candidate("https://attack.mitre.org/techniques/T1059/") is False

    def test_pdf_link_rejected(self):
        from discover_feeds import is_blog_candidate
        assert is_blog_candidate("https://example.com/whitepaper.pdf") is False

    def test_tool_download_rejected(self):
        from discover_feeds import is_blog_candidate
        # vendor tool pages, not blogs
        assert is_blog_candidate("https://www.nirsoft.net/utils/") is False


class TestFindGaps:
    def test_finds_missing_blog(self):
        from discover_feeds import find_gaps
        links = [("Andrea Fortuna", "https://andreafortuna.org/")]
        known = {"windowsir.blogspot.com", "dfir.blog"}
        gaps = find_gaps(links, known)
        assert any("andreafortuna.org" in url for _, url in gaps)

    def test_no_gap_if_known(self):
        from discover_feeds import find_gaps
        links = [("Windows IR", "https://windowsir.blogspot.com/")]
        known = {"windowsir.blogspot.com"}
        gaps = find_gaps(links, known)
        assert gaps == []

    def test_strips_www_before_compare(self):
        from discover_feeds import find_gaps
        links = [("Windows IR", "https://www.windowsir.blogspot.com/")]
        known = {"windowsir.blogspot.com"}
        gaps = find_gaps(links, known)
        assert gaps == []

    def test_multiple_gaps_returned(self):
        from discover_feeds import find_gaps
        links = [
            ("Blog A", "https://a.com/"),
            ("Blog B", "https://b.com/"),
            ("Blog C", "https://c.com/"),
        ]
        known = {"b.com"}
        gaps = find_gaps(links, known)
        gap_urls = [url for _, url in gaps]
        assert any("a.com" in u for u in gap_urls)
        assert any("c.com" in u for u in gap_urls)
        assert not any("b.com" in u for u in gap_urls)

    def test_empty_links_returns_empty(self):
        from discover_feeds import find_gaps
        assert find_gaps([], {"dfir.blog"}) == []

    def test_empty_known_returns_all_links(self):
        from discover_feeds import find_gaps
        links = [("Blog A", "https://a.com/"), ("Blog B", "https://b.com/")]
        gaps = find_gaps(links, set())
        assert len(gaps) == 2


class TestProbeForFeed:
    """probe_for_feed tries common RSS/Atom paths and returns the first that 200s."""

    def test_returns_none_for_clearly_invalid(self):
        from discover_feeds import probe_for_feed
        # Should return None or a string — never raise
        result = probe_for_feed("https://this-domain-does-not-exist-xyz987.com/")
        assert result is None

    def test_signature(self):
        from discover_feeds import probe_for_feed
        import inspect
        sig = inspect.signature(probe_for_feed)
        assert "url" in sig.parameters
