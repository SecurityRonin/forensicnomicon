"""
Tests for scripts/fetch_all_sources.py

Tests cover the pure-logic functions (no real HTTP):
  - parse_blogger_feed(xml_text)       → list[tuple[str,str,str]]
  - parse_wordpress_posts(json_text)   → list[tuple[str,str,str]]
  - parse_atom_feed(xml_text)          → list[tuple[str,str,str]]
  - parse_github_commits(json_text)    → list[tuple[str,str,str]]
  - load_seen_urls(pending_path) → set[str]  (dedup against pending-review.md)
  - classify_blog_source(html_url)     → str  ("blogger"|"wordpress"|"github"|"unknown")
  - rescan_reviewed_entries(path)      → int  (rewrites [x] → [ ])
"""

import json
import os
import sys
import textwrap
import unittest

# fetch_all_sources.py lives one level up from this test file
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import fetch_all_sources as ba  # noqa: E402  (module under test)


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

GITHUB_COMMITS_JSON = json.dumps([
    {
        "html_url": "https://github.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/commit/aaa111",
        "commit": {
            "message": "Add lateral movement via WMI\n\nDetailed notes on WMI-based lateral movement.",
            "author": {"date": "2024-04-01T08:00:00Z"},
        },
    },
    {
        "html_url": "https://github.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/commit/bbb222",
        "commit": {
            "message": "Add persistence via registry run keys",
            "author": {"date": "2024-03-15T10:30:00Z"},
        },
    },
    {
        "html_url": "https://github.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/commit/ccc333",
        "commit": {
            # Multi-line: only first line is the title
            "message": "Update README",
            "author": {"date": "2024-03-01T09:00:00Z"},
        },
    },
])

PENDING_MD = textwrap.dedent("""\
- [x] [Old Post](https://windowsir.blogspot.com/2023/12/userassist.html) — Windows IR
- [ ] [Another Post](https://windowsir.blogspot.com/2024/01/shimcache.html) — Windows IR
- [→] [Third Post](https://dfir.blog/prefetch-analysis/) — dfir.blog
""")


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


class TestParseGithubCommits(unittest.TestCase):
    def test_returns_list(self):
        entries = ba.parse_github_commits(GITHUB_COMMITS_JSON)
        self.assertIsInstance(entries, list)

    def test_entry_count(self):
        entries = ba.parse_github_commits(GITHUB_COMMITS_JSON)
        self.assertEqual(len(entries), 3)

    def test_entry_shape(self):
        entries = ba.parse_github_commits(GITHUB_COMMITS_JSON)
        title, url, date = entries[0]
        self.assertEqual(title, "Add lateral movement via WMI")
        self.assertIn("commit/aaa111", url)
        self.assertEqual(date, "2024-04-01")

    def test_multiline_message_uses_first_line_only(self):
        entries = ba.parse_github_commits(GITHUB_COMMITS_JSON)
        title, _, _ = entries[0]
        self.assertNotIn("\n", title)

    def test_empty_json_returns_empty(self):
        self.assertEqual(ba.parse_github_commits("[]"), [])

    def test_invalid_json_returns_empty(self):
        self.assertEqual(ba.parse_github_commits("not json"), [])


class TestLoadSeenUrls(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.pending = os.path.join(self.tmp, "pending-review.md")
        with open(self.pending, "w") as f:
            f.write(PENDING_MD)

    def test_returns_set(self):
        seen = ba.load_seen_urls(self.pending)
        self.assertIsInstance(seen, set)

    def test_includes_all_marker_states(self):
        seen = ba.load_seen_urls(self.pending)
        # [x], [ ], and [→] entries all count as seen
        self.assertIn("https://windowsir.blogspot.com/2023/12/userassist.html", seen)
        self.assertIn("https://windowsir.blogspot.com/2024/01/shimcache.html", seen)
        self.assertIn("https://dfir.blog/prefetch-analysis/", seen)

    def test_missing_file_returns_empty_set(self):
        seen = ba.load_seen_urls(os.path.join(self.tmp, "nonexistent.md"))
        self.assertEqual(seen, set())

    def test_dedup_prevents_duplicate_entries(self):
        """Re-running fetch must not add URLs already in pending-review.md."""
        seen = ba.load_seen_urls(self.pending)
        entries = [
            ("ShimCache", "https://windowsir.blogspot.com/2024/01/shimcache.html", "2024-01-15"),
            ("New Post", "https://windowsir.blogspot.com/2024/06/new.html", "2024-06-01"),
        ]
        new = [e for e in entries if e[1] not in seen]
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0][0], "New Post")


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


class TestRescanReviewedEntries(unittest.TestCase):
    """rescan_reviewed_entries() rewrites [x] → [ ] — no distinct [~] marker needed."""

    def _write_pending(self, tmp_path, content):
        with open(tmp_path, "w") as f:
            f.write(content)

    def test_reviewed_becomes_unreviewed(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("- [x] https://example.com/post1 <!-- reviewed -->\n")
            tmp = f.name
        count = ba.rescan_reviewed_entries(tmp)
        with open(tmp) as f:
            lines = f.readlines()
        self.assertEqual(count, 1)
        self.assertTrue(lines[0].startswith("- [ ] "), f"expected [ ], got: {lines[0]!r}")

    def test_task_created_entries_unchanged(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("- [→] https://example.com/post2\n")
            tmp = f.name
        count = ba.rescan_reviewed_entries(tmp)
        with open(tmp) as f:
            content = f.read()
        self.assertEqual(count, 0)
        self.assertIn("[→]", content)

    def test_missing_file_returns_zero(self):
        count = ba.rescan_reviewed_entries("/nonexistent/path/pending.md")
        self.assertEqual(count, 0)


class TestPendingFileLock(unittest.TestCase):
    """locked_write(path, transform_fn) serializes concurrent read-modify-writes."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "pending-review.md")
        with open(self.path, "w") as f:
            f.write("- [ ] https://example.com/post1\n")

    def test_locked_write_applies_transform(self):
        """transform_fn receives current content, returns new content."""
        ba.locked_write(self.path, lambda c: c + "- [ ] https://example.com/post2\n")
        with open(self.path) as f:
            content = f.read()
        self.assertIn("post1", content)
        self.assertIn("post2", content)

    def test_locked_write_is_atomic(self):
        """Two concurrent locked_write calls both apply without losing data."""
        import threading
        results = []

        def append(url):
            ba.locked_write(self.path, lambda c: c + f"- [ ] {url}\n")
            results.append(url)

        t1 = threading.Thread(target=append, args=("https://a.com/1",))
        t2 = threading.Thread(target=append, args=("https://b.com/2",))
        t1.start(); t2.start()
        t1.join(); t2.join()

        with open(self.path) as f:
            content = f.read()
        self.assertIn("https://a.com/1", content)
        self.assertIn("https://b.com/2", content)

    def test_lock_file_cleaned_up_after_write(self):
        """Lock file must not linger after locked_write completes."""
        lock_path = self.path + ".lock"
        ba.locked_write(self.path, lambda c: c)
        self.assertFalse(os.path.exists(lock_path),
                         "stale lockfile left behind after write")

    def test_stale_lock_from_dead_pid_is_stolen(self):
        """A lockfile containing a dead PID must not block forever."""
        lock_path = self.path + ".lock"
        # Write a lockfile with PID 1 (init/launchd — never our process)
        # On all platforms PID 1 exists but is not our process, so it's
        # effectively "dead" from our perspective for stealing purposes.
        # Use a guaranteed-dead PID instead: 99999999
        with open(lock_path, "w") as f:
            f.write("99999999")
        # Should complete without hanging
        ba.locked_write(self.path, lambda c: c + "- [ ] https://example.com/stolen\n")
        with open(self.path) as f:
            content = f.read()
        self.assertIn("stolen", content)
        self.assertFalse(os.path.exists(lock_path))



if __name__ == "__main__":
    unittest.main()
