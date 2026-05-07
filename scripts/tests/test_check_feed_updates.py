"""
Tests for scripts/check_feed_updates.py

Pure-logic tests — no real HTTP calls.
"""

import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check_feed_updates as cfu  # noqa: E402
import pending_lock  # noqa: E402


class TestNoReviewList(unittest.TestCase):
    """_NO_PENDING_REVIEW must exist and cover IOC/LOL-dataset sources."""

    def test_no_pending_review_constant_exists(self):
        self.assertTrue(
            hasattr(cfu, "_NO_PENDING_REVIEW"),
            "_NO_PENDING_REVIEW frozenset must exist in check_feed_updates",
        )

    def test_no_pending_review_is_frozenset(self):
        self.assertIsInstance(cfu._NO_PENDING_REVIEW, frozenset)

    def test_ioc_feeds_excluded(self):
        """URLhaus, MalwareBazaar, ThreatFox produce IOC entries, not artifact docs."""
        for title in ("URLhaus", "MalwareBazaar", "ThreatFox"):
            self.assertIn(
                title,
                cfu._NO_PENDING_REVIEW,
                f"'{title}' should be in _NO_PENDING_REVIEW — it is an IOC feed, not a DFIR blog",
            )

    def test_lol_dataset_commits_excluded(self):
        """LOL dataset GitHub commit feeds generate one entry per binary added.
        These are handled by fetch_*.py scripts and should not flood pending-review.md."""
        for title in ("LOLBAS Project (Windows)", "GTFOBins (Linux)", "LOOBins (macOS)", "LOLDrivers (BYOVD)", "LOFL Project (RMM C2 indicators)"):
            self.assertIn(
                title,
                cfu._NO_PENDING_REVIEW,
                f"'{title}' should be in _NO_PENDING_REVIEW — LOL dataset commits, not blog posts",
            )

    def test_misp_taxonomies_excluded(self):
        """MISP taxonomy commits are CI/tooling changes, not DFIR artifact documentation."""
        self.assertIn(
            "MISP Taxonomies",
            cfu._NO_PENDING_REVIEW,
            "'MISP Taxonomies' should be in _NO_PENDING_REVIEW",
        )

    def test_dfir_blog_feeds_not_excluded(self):
        """Real DFIR blogs must NOT be in _NO_PENDING_REVIEW."""
        for title in ("Windows Incident Response", "The DFIR Report", "Andrea Fortuna", "13cubed"):
            self.assertNotIn(
                title,
                cfu._NO_PENDING_REVIEW,
                f"'{title}' is a real DFIR blog and must not be in _NO_PENDING_REVIEW",
            )


class TestFilterBeforePending(unittest.TestCase):
    """new_entries must be filtered through _NO_PENDING_REVIEW before append_pending_review."""

    def _make_entries(self, *source_titles):
        """Return [(source, title, url)] tuples for given source names."""
        return [(src, f"Post from {src}", f"https://example.com/{src}") for src in source_titles]

    def test_filter_removes_no_review_entries(self):
        """filter_pending_entries() must drop entries whose source is in _NO_PENDING_REVIEW."""
        entries = self._make_entries("URLhaus", "Windows Incident Response", "MalwareBazaar")
        result = cfu.filter_pending_entries(entries)
        sources = [e[0] for e in result]
        self.assertNotIn("URLhaus", sources)
        self.assertNotIn("MalwareBazaar", sources)
        self.assertIn("Windows Incident Response", sources)

    def test_filter_keeps_lol_dataset_entries_out(self):
        entries = self._make_entries("LOLBAS Project (Windows)", "GTFOBins (Linux)", "Didier Stevens Blog")
        result = cfu.filter_pending_entries(entries)
        sources = [e[0] for e in result]
        self.assertNotIn("LOLBAS Project (Windows)", sources)
        self.assertNotIn("GTFOBins (Linux)", sources)
        self.assertIn("Didier Stevens Blog", sources)

    def test_filter_empty_input(self):
        self.assertEqual(cfu.filter_pending_entries([]), [])

    def test_filter_all_excluded(self):
        entries = self._make_entries("URLhaus", "MalwareBazaar", "ThreatFox")
        self.assertEqual(cfu.filter_pending_entries(entries), [])

    def test_filter_none_excluded(self):
        entries = self._make_entries("Windows Incident Response", "The DFIR Report")
        result = cfu.filter_pending_entries(entries)
        self.assertEqual(len(result), 2)


class TestBlueteamFieldNotesIncluded(unittest.TestCase):
    """Blue Team Field Notes is a legitimate DFIR notebook — must NOT be excluded."""

    def test_blue_team_field_notes_not_excluded(self):
        self.assertNotIn(
            "Blue_Team_Hunting_Field_Notes",
            cfu._NO_PENDING_REVIEW,
        )
        # Also check the title variant used in the OPML
        self.assertNotIn(
            "Blue Team Hunting Field Notes (bitbug0x55AA)",
            cfu._NO_PENDING_REVIEW,
        )


# ── Lock safety tests ─────────────────────────────────────────────────────────

class TestPendingLockModule(unittest.TestCase):
    """pending_lock.py — shared lockfile helper used by all pending-review writers."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "pending-review.md")
        self.lock_path = self.path + ".lock"

    def tearDown(self):
        for f in (self.path, self.lock_path, self.path + ".tmp"):
            try:
                os.remove(f)
            except OSError:
                pass

    def test_locked_write_creates_and_reads_back(self):
        """locked_write creates the file and the transform_fn receives current content."""
        pending_lock.locked_write(self.path, lambda _: "hello\n")
        with open(self.path) as f:
            self.assertEqual(f.read(), "hello\n")

    def test_locked_write_releases_lock_after_completion(self):
        """No .lock file must remain after locked_write returns."""
        pending_lock.locked_write(self.path, lambda _: "x\n")
        self.assertFalse(
            os.path.exists(self.lock_path),
            ".lock file must be removed after locked_write completes",
        )

    def test_locked_write_releases_lock_on_exception(self):
        """Lock is released even if transform_fn raises."""
        with self.assertRaises(RuntimeError):
            pending_lock.locked_write(self.path, lambda _: (_ for _ in ()).throw(RuntimeError("boom")))
        self.assertFalse(
            os.path.exists(self.lock_path),
            ".lock file must be removed even when transform_fn raises",
        )

    def test_locked_write_steals_stale_lock(self):
        """A .lock file with a dead PID must be stolen, not block forever."""
        # PID 99999999 is virtually guaranteed to not exist
        with open(self.lock_path, "w") as f:
            f.write("99999999")
        # Should complete without hanging
        pending_lock.locked_write(self.path, lambda _: "stolen\n")
        with open(self.path) as f:
            self.assertEqual(f.read(), "stolen\n")

    def test_locked_write_atomic_rename(self):
        """File is written via temp+rename so partial writes are never visible."""
        pending_lock.locked_write(self.path, lambda _: "atomic\n")
        tmp = self.path + ".tmp"
        self.assertFalse(os.path.exists(tmp), ".tmp file must be cleaned up")

    def test_locked_write_serialises_concurrent_writers(self):
        """Two threads calling locked_write must not corrupt the file."""
        pending_lock.locked_write(self.path, lambda _: "")
        errors = []

        def append_line(n):
            try:
                pending_lock.locked_write(
                    self.path,
                    lambda content: content + f"line{n}\n",
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=append_line, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertFalse(errors, f"concurrent locked_write raised: {errors}")
        with open(self.path) as f:
            lines = [l for l in f.read().splitlines() if l]
        self.assertEqual(len(lines), 8, f"expected 8 lines, got {lines}")


class TestAppendPendingReviewLocked(unittest.TestCase):
    """append_pending_review must acquire the lockfile before writing."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "pending-review.md")
        self.lock_path = self.path + ".lock"

    def tearDown(self):
        for f in (self.path, self.lock_path):
            try:
                os.remove(f)
            except OSError:
                pass

    def test_append_releases_lock_after_write(self):
        """No .lock file must remain after append_pending_review returns."""
        cfu.append_pending_review(
            self.path,
            [("TestSource", "Test Post", "https://example.com/post")],
            validate=False,
        )
        self.assertFalse(
            os.path.exists(self.lock_path),
            ".lock file must be removed after append_pending_review",
        )

    def test_append_steals_stale_lock(self):
        """append_pending_review must proceed even if a stale .lock exists."""
        with open(self.lock_path, "w") as f:
            f.write("99999999")
        # Must not hang or raise
        cfu.append_pending_review(
            self.path,
            [("TestSource", "Stale Lock Post", "https://example.com/stale")],
            validate=False,
        )
        with open(self.path) as f:
            content = f.read()
        self.assertIn("Stale Lock Post", content)

    def test_append_uses_shared_lock_convention(self):
        """Lock path must be pending_path + '.lock' — same convention as pending_lock.locked_write.

        We verify this by confirming that pending_lock.locked_write and
        append_pending_review contend on the same lock: if we hold the lock
        via pending_lock before calling append_pending_review in a thread, the
        thread must block until we release it.
        """
        import threading

        # Acquire the lock ourselves
        lock_path = self.path + ".lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)

        started = threading.Event()
        finished = threading.Event()

        def _append():
            started.set()
            cfu.append_pending_review(
                self.path,
                [("Src", "Title", "https://example.com/lock-test")],
                validate=False,
            )
            finished.set()

        t = threading.Thread(target=_append)
        t.start()
        started.wait(timeout=2)

        # Thread should be blocked — file must NOT be written yet
        time.sleep(0.15)
        self.assertFalse(finished.is_set(), "append must block while lock is held")

        # Release the lock — thread should proceed
        os.remove(lock_path)
        finished.wait(timeout=5)
        t.join(timeout=5)
        self.assertTrue(finished.is_set(), "append must complete after lock released")
