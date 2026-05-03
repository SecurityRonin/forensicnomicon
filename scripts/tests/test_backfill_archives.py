"""
RED tests for scripts/backfill_archives.py

Tests cover the pure-logic functions (no real HTTP):
  - parse_blogger_feed(xml_text)       → list[tuple[str,str,str]]
  - parse_wordpress_posts(json_text)   → list[tuple[str,str,str]]
  - parse_atom_feed(xml_text)          → list[tuple[str,str,str]]
  - load_seen_urls(feed_state_path, pending_path) → set[str]
  - dedup_entries(entries, seen_urls)  → list[tuple[str,str,str]]
  - classify_blog_source(html_url)     → str  ("blogger"|"wordpress"|"atom"|"squarespace"|"unknown")
  - extract_related_artifacts(text)    → list[str]  (artifact IDs found in text)
"""

import json
import os
import sys
import textwrap
import unittest

# backfill_archives.py lives one level up from this test file
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import backfill_archives as ba  # noqa: E402  (module under test)


BLOGGER_FEED_XML = textwrap.dedent("""\
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>ShimCache and AppCompatCache</title>
    <link rel="alternate" href="https://windowsir.blogspot.com/2024/01/shimcache.html"/>
    <published>2024-01-15T10:00:00Z</published>
  </entry>
  <entry>
    <title>UserAssist Deep Dive</title>
    <link rel="alternate" href="https://windowsir.blogspot.com/2023/12/userassist.html"/>
    <published>2023-12-01T10:00:00Z</published>
  </entry>
</feed>
""")

WORDPRESS_API_JSON = json.dumps([
    {
        "title": {"rendered": "Prefetch Analysis"},
        "link": "https://dfir.blog/prefetch-analysis/",
        "date": "2024-02-10T09:00:00",
    },
    {
        "title": {"rendered": "SRUM Database"},
        "link": "https://dfir.blog/srum-database/",
        "date": "2024-01-20T09:00:00",
    },
])

GITHUB_ATOM_XML = textwrap.dedent("""\
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Create certutil.yml</title>
    <link rel="alternate" href="https://github.com/LOLBAS-Project/LOLBAS/commit/abc123"/>
    <updated>2024-03-01T12:00:00Z</updated>
  </entry>
</feed>
""")

PENDING_MD = textwrap.dedent("""\
- [x] [Old Post](https://windowsir.blogspot.com/2023/12/userassist.html) — Windows IR
- [ ] [Another Post](https://windowsir.blogspot.com/2024/01/shimcache.html) — Windows IR
- [→] [Third Post](https://dfir.blog/prefetch-analysis/) — dfir.blog
""")

FEED_STATE_JSON = json.dumps({
    "https://windowsir.blogspot.com/feeds/posts/default": {
        "title": "Windows Incident Response",
        "entries": [
            {"url": "https://windowsir.blogspot.com/2023/12/userassist.html", "title": "UserAssist"}
        ],
    }
})


class TestParseBloggerFeed(unittest.TestCase):
    def test_returns_list_of_tuples(self):
        entries = ba.parse_blogger_feed(BLOGGER_FEED_XML)
        self.assertIsInstance(entries, list)

    def test_entry_count(self):
        entries = ba.parse_blogger_feed(BLOGGER_FEED_XML)
        self.assertEqual(len(entries), 2)

    def test_entry_shape(self):
        entries = ba.parse_blogger_feed(BLOGGER_FEED_XML)
        title, url, date = entries[0]
        self.assertEqual(title, "ShimCache and AppCompatCache")
        self.assertIn("windowsir.blogspot.com", url)
        self.assertEqual(date, "2024-01-15")

    def test_empty_feed_returns_empty_list(self):
        xml = '<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>'
        self.assertEqual(ba.parse_blogger_feed(xml), [])


class TestParseWordPressPosts(unittest.TestCase):
    def test_returns_list(self):
        entries = ba.parse_wordpress_posts(WORDPRESS_API_JSON)
        self.assertIsInstance(entries, list)

    def test_entry_count(self):
        entries = ba.parse_wordpress_posts(WORDPRESS_API_JSON)
        self.assertEqual(len(entries), 2)

    def test_entry_shape(self):
        entries = ba.parse_wordpress_posts(WORDPRESS_API_JSON)
        title, url, date = entries[0]
        self.assertEqual(title, "Prefetch Analysis")
        self.assertEqual(url, "https://dfir.blog/prefetch-analysis/")
        self.assertEqual(date, "2024-02-10")

    def test_empty_json_returns_empty_list(self):
        self.assertEqual(ba.parse_wordpress_posts("[]"), [])


class TestParseAtomFeed(unittest.TestCase):
    def test_returns_list(self):
        entries = ba.parse_atom_feed(GITHUB_ATOM_XML)
        self.assertIsInstance(entries, list)

    def test_entry_shape(self):
        entries = ba.parse_atom_feed(GITHUB_ATOM_XML)
        title, url, date = entries[0]
        self.assertEqual(title, "Create certutil.yml")
        self.assertIn("github.com", url)
        self.assertEqual(date, "2024-03-01")

    def test_updated_field_used_as_fallback(self):
        """Atom feeds use <updated> when <published> is absent."""
        entries = ba.parse_atom_feed(GITHUB_ATOM_XML)
        _, _, date = entries[0]
        self.assertRegex(date, r"\d{4}-\d{2}-\d{2}")


class TestLoadSeenUrls(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.state = os.path.join(self.tmp, "feed-state.json")
        self.pending = os.path.join(self.tmp, "pending-review.md")
        with open(self.state, "w") as f:
            f.write(FEED_STATE_JSON)
        with open(self.pending, "w") as f:
            f.write(PENDING_MD)

    def test_returns_set(self):
        seen = ba.load_seen_urls(self.state, self.pending)
        self.assertIsInstance(seen, set)

    def test_includes_feed_state_urls(self):
        seen = ba.load_seen_urls(self.state, self.pending)
        self.assertIn("https://windowsir.blogspot.com/2023/12/userassist.html", seen)

    def test_includes_pending_urls(self):
        seen = ba.load_seen_urls(self.state, self.pending)
        self.assertIn("https://windowsir.blogspot.com/2024/01/shimcache.html", seen)
        self.assertIn("https://dfir.blog/prefetch-analysis/", seen)

    def test_missing_state_file_returns_pending_only(self):
        seen = ba.load_seen_urls(os.path.join(self.tmp, "nonexistent.json"), self.pending)
        self.assertIn("https://windowsir.blogspot.com/2024/01/shimcache.html", seen)

    def test_missing_pending_file_returns_state_only(self):
        seen = ba.load_seen_urls(self.state, os.path.join(self.tmp, "nonexistent.md"))
        self.assertIn("https://windowsir.blogspot.com/2023/12/userassist.html", seen)


class TestDedupEntries(unittest.TestCase):
    def test_removes_seen_urls(self):
        entries = [
            ("ShimCache", "https://windowsir.blogspot.com/2024/01/shimcache.html", "2024-01-15"),
            ("UserAssist", "https://windowsir.blogspot.com/2023/12/userassist.html", "2023-12-01"),
        ]
        seen = {"https://windowsir.blogspot.com/2023/12/userassist.html"}
        result = ba.dedup_entries(entries, seen)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "ShimCache")

    def test_empty_seen_returns_all(self):
        entries = [("A", "https://a.com/", "2024-01-01")]
        result = ba.dedup_entries(entries, set())
        self.assertEqual(result, entries)

    def test_empty_entries_returns_empty(self):
        self.assertEqual(ba.dedup_entries([], {"https://anything.com"}), [])


class TestClassifyBlogSource(unittest.TestCase):
    def test_blogger_recognized(self):
        self.assertEqual(ba.classify_blog_source("https://windowsir.blogspot.com/"), "blogger")

    def test_wordpress_recognized_by_path_hint(self):
        # WordPress sites expose /wp-json/ — classified by probing, but
        # known WordPress hosts get classified directly
        result = ba.classify_blog_source("https://thedfirreport.com/")
        self.assertIn(result, ("wordpress", "unknown"))

    def test_github_atom_recognized(self):
        result = ba.classify_blog_source("https://github.com/LOLBAS-Project/LOLBAS")
        self.assertEqual(result, "github")

    def test_unknown_for_generic_site(self):
        result = ba.classify_blog_source("https://example.com/")
        self.assertEqual(result, "unknown")



if __name__ == "__main__":
    unittest.main()
