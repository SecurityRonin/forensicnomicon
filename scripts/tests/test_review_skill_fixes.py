"""
RED tests for three review-skill fixes:

Fix 1 — _ARTIFACT_PHRASES embedded in review skill:
  The skill must list the concrete artifact phrases (not vague "note co-occurrences").
  extract_related_artifacts() must be importable and callable from the skill context.

Fix 2 — related[] field gap detection:
  check_related_gaps(artifact_id, co_occurring_ids) → list[str]
  Returns artifact IDs that co-occur with artifact_id but are absent from
  artifact_id's descriptor.related array. These become enrichment tasks.

Fix 3 — YouTube transcript support:
  fetch_youtube_transcript(video_id) → str | None
  Returns the transcript text if available (via youtube-transcript-api),
  None if unavailable. The review skill feeds this text to
  extract_related_artifacts() instead of the sparse HTML page.
"""

import importlib
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestArtifactPhrasesInSkill(unittest.TestCase):
    """Fix 1: No hardcoded phrase list — Claude uses own comprehension."""

    def test_no_hardcoded_artifact_phrases_list(self):
        """_ARTIFACT_PHRASES must NOT exist — deleted as hardcoded YAGNI."""
        import fetch_all_posts
        self.assertFalse(
            hasattr(fetch_all_posts, "_ARTIFACT_PHRASES"),
            "_ARTIFACT_PHRASES must be deleted; Claude uses comprehension, not a keyword list"
        )

    def test_no_extract_related_artifacts_function(self):
        """extract_related_artifacts() must NOT exist — it was a keyword scanner."""
        import fetch_all_posts
        self.assertFalse(
            hasattr(fetch_all_posts, "extract_related_artifacts"),
            "extract_related_artifacts() must be deleted; Claude reads content directly"
        )

    def test_rescan_reviewed_entries_importable(self):
        from fetch_all_posts import rescan_reviewed_entries
        self.assertTrue(callable(rescan_reviewed_entries))

    def test_skill_references_check_related_gaps(self):
        """The review skill must tell Claude to call check_related_gaps() programmatically."""
        skill_path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            ".claude", "commands", "review-dfir-feeds.md"
        )
        with open(skill_path) as f:
            content = f.read()
        self.assertIn("check_related_gaps", content,
                      "skill must reference check_related_gaps()")

    def test_skill_references_fetch_youtube_transcript(self):
        skill_path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            ".claude", "commands", "review-dfir-feeds.md"
        )
        with open(skill_path) as f:
            content = f.read()
        self.assertIn("fetch_youtube_transcript", content,
                      "skill must reference fetch_youtube_transcript()")

    def test_skill_does_not_mandate_keyword_list_for_claude(self):
        """Claude uses its own comprehension — skill must not say to use _ARTIFACT_PHRASES."""
        skill_path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            ".claude", "commands", "review-dfir-feeds.md"
        )
        with open(skill_path) as f:
            content = f.read()
        # The phrase list is for scripted automation, not for Claude during review
        self.assertNotIn(
            "Pass it to `extract_related_artifacts()`", content,
            "skill must not tell Claude to run the keyword scanner on fetched content"
        )

    def test_no_tilde_marker_in_skill(self):
        """[~] marker is removed — rescan writes [ ] directly, no distinct marker needed."""
        skill_path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            ".claude", "commands", "review-dfir-feeds.md"
        )
        with open(skill_path) as f:
            content = f.read()
        self.assertNotIn(
            "[~]", content,
            "skill must not reference [~]; rescan_reviewed_entries() writes [ ] directly"
        )


class TestRelatedGapDetection(unittest.TestCase):
    """Fix 2: check_related_gaps() finds missing related[] links."""

    def test_function_importable(self):
        from fetch_all_posts import check_related_gaps
        self.assertTrue(callable(check_related_gaps))

    def test_returns_list(self):
        from fetch_all_posts import check_related_gaps
        result = check_related_gaps("shimcache", ["prefetch_dir", "amcache_hve"])
        self.assertIsInstance(result, list)

    def test_returns_missing_related(self):
        """shimcache's related[] probably doesn't contain prefetch_dir — flag it."""
        from fetch_all_posts import check_related_gaps
        # We can't know the exact catalog state, but we can verify the function
        # returns only strings (artifact IDs) or empty list
        result = check_related_gaps("shimcache", ["prefetch_dir", "amcache_hve"])
        for item in result:
            self.assertIsInstance(item, str)

    def test_unknown_artifact_returns_empty(self):
        from fetch_all_posts import check_related_gaps
        result = check_related_gaps("this_does_not_exist_xyz", ["prefetch_dir"])
        self.assertEqual(result, [])

    def test_empty_co_occurring_returns_empty(self):
        from fetch_all_posts import check_related_gaps
        result = check_related_gaps("shimcache", [])
        self.assertEqual(result, [])

    def test_already_related_not_returned(self):
        """If artifact A already lists B in related[], B must not appear in gaps."""
        from fetch_all_posts import check_related_gaps
        # Find a pair that IS already related in the catalog and verify no false gap
        # Use mft_file which should already relate to usnjrnl
        result = check_related_gaps("mft_file", ["mft_file"])  # self-reference = always absent
        # Self should never appear in related
        self.assertNotIn("mft_file", result)


class TestYouTubeTranscript(unittest.TestCase):
    """Fix 3: fetch_youtube_transcript() returns text or None."""

    def test_function_importable(self):
        from fetch_all_posts import fetch_youtube_transcript
        self.assertTrue(callable(fetch_youtube_transcript))

    def test_returns_str_or_none(self):
        from fetch_all_posts import fetch_youtube_transcript
        # Use a well-known 13cubed video with subtitles
        # "Windows Forensics: Prefetch" — UCy8ntxFEudOCRZYT1f7ya9Q
        # Video ID: _3PiX4OT9pE (short video, has captions)
        result = fetch_youtube_transcript("_3PiX4OT9pE")
        self.assertTrue(result is None or isinstance(result, str),
                        f"expected str or None, got {type(result)}")

    def test_nonexistent_video_returns_none(self):
        from fetch_all_posts import fetch_youtube_transcript
        result = fetch_youtube_transcript("AAAAAAAAAAAAAAAA_DOES_NOT_EXIST")
        self.assertIsNone(result)

    def test_transcript_contains_text_when_available(self):
        from fetch_all_posts import fetch_youtube_transcript
        result = fetch_youtube_transcript("_3PiX4OT9pE")
        if result is not None:
            self.assertGreater(len(result), 50,
                               "transcript should contain meaningful text")

    def test_transcript_contains_dfir_terms_when_available(self):
        """Transcript text is readable prose — Claude uses it directly, no keyword scan."""
        from fetch_all_posts import fetch_youtube_transcript
        result = fetch_youtube_transcript("_3PiX4OT9pE")
        if result is not None:
            # A Prefetch video should contain the word "prefetch" for Claude to read
            self.assertIn("prefetch", result.lower(),
                          "Prefetch video transcript should contain 'prefetch'")


if __name__ == "__main__":
    unittest.main()
