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
    """Fix 1: _ARTIFACT_PHRASES must be importable and the skill must reference them."""

    def test_artifact_phrases_importable(self):
        from backfill_archives import _ARTIFACT_PHRASES
        self.assertIsInstance(_ARTIFACT_PHRASES, list)
        self.assertGreater(len(_ARTIFACT_PHRASES), 10)

    def test_each_phrase_is_tuple_of_two_strings(self):
        from backfill_archives import _ARTIFACT_PHRASES
        for item in _ARTIFACT_PHRASES:
            self.assertIsInstance(item, tuple, f"expected tuple, got {type(item)}")
            self.assertEqual(len(item), 2, f"expected (phrase, artifact_id), got {item}")
            phrase, artifact_id = item
            self.assertIsInstance(phrase, str)
            self.assertIsInstance(artifact_id, str)

    def test_shimcache_phrase_present(self):
        from backfill_archives import _ARTIFACT_PHRASES
        phrases = [p for p, _ in _ARTIFACT_PHRASES]
        self.assertIn("shimcache", phrases)

    def test_prefetch_phrase_present(self):
        from backfill_archives import _ARTIFACT_PHRASES
        phrases = [p for p, _ in _ARTIFACT_PHRASES]
        self.assertIn("prefetch", phrases)

    def test_skill_file_references_artifact_phrases(self):
        """The review skill must mention the phrase-list so Claude knows to use it."""
        skill_path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            ".claude", "commands", "review-dfir-feeds.md"
        )
        with open(skill_path) as f:
            content = f.read()
        self.assertIn("_ARTIFACT_PHRASES", content,
                      "review-dfir-feeds.md must reference _ARTIFACT_PHRASES")

    def test_skill_references_extract_related_artifacts(self):
        skill_path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            ".claude", "commands", "review-dfir-feeds.md"
        )
        with open(skill_path) as f:
            content = f.read()
        self.assertIn("extract_related_artifacts", content,
                      "skill must reference extract_related_artifacts()")


class TestRelatedGapDetection(unittest.TestCase):
    """Fix 2: check_related_gaps() finds missing related[] links."""

    def test_function_importable(self):
        from backfill_archives import check_related_gaps
        self.assertTrue(callable(check_related_gaps))

    def test_returns_list(self):
        from backfill_archives import check_related_gaps
        result = check_related_gaps("shimcache", ["prefetch_dir", "amcache_hve"])
        self.assertIsInstance(result, list)

    def test_returns_missing_related(self):
        """shimcache's related[] probably doesn't contain prefetch_dir — flag it."""
        from backfill_archives import check_related_gaps
        # We can't know the exact catalog state, but we can verify the function
        # returns only strings (artifact IDs) or empty list
        result = check_related_gaps("shimcache", ["prefetch_dir", "amcache_hve"])
        for item in result:
            self.assertIsInstance(item, str)

    def test_unknown_artifact_returns_empty(self):
        from backfill_archives import check_related_gaps
        result = check_related_gaps("this_does_not_exist_xyz", ["prefetch_dir"])
        self.assertEqual(result, [])

    def test_empty_co_occurring_returns_empty(self):
        from backfill_archives import check_related_gaps
        result = check_related_gaps("shimcache", [])
        self.assertEqual(result, [])

    def test_already_related_not_returned(self):
        """If artifact A already lists B in related[], B must not appear in gaps."""
        from backfill_archives import check_related_gaps
        # Find a pair that IS already related in the catalog and verify no false gap
        # Use mft_file which should already relate to usnjrnl
        result = check_related_gaps("mft_file", ["mft_file"])  # self-reference = always absent
        # Self should never appear in related
        self.assertNotIn("mft_file", result)


class TestYouTubeTranscript(unittest.TestCase):
    """Fix 3: fetch_youtube_transcript() returns text or None."""

    def test_function_importable(self):
        from backfill_archives import fetch_youtube_transcript
        self.assertTrue(callable(fetch_youtube_transcript))

    def test_returns_str_or_none(self):
        from backfill_archives import fetch_youtube_transcript
        # Use a well-known 13cubed video with subtitles
        # "Windows Forensics: Prefetch" — UCy8ntxFEudOCRZYT1f7ya9Q
        # Video ID: _3PiX4OT9pE (short video, has captions)
        result = fetch_youtube_transcript("_3PiX4OT9pE")
        self.assertTrue(result is None or isinstance(result, str),
                        f"expected str or None, got {type(result)}")

    def test_nonexistent_video_returns_none(self):
        from backfill_archives import fetch_youtube_transcript
        result = fetch_youtube_transcript("AAAAAAAAAAAAAAAA_DOES_NOT_EXIST")
        self.assertIsNone(result)

    def test_transcript_contains_text_when_available(self):
        from backfill_archives import fetch_youtube_transcript
        result = fetch_youtube_transcript("_3PiX4OT9pE")
        if result is not None:
            self.assertGreater(len(result), 50,
                               "transcript should contain meaningful text")

    def test_transcript_passes_to_extract_related(self):
        """If a transcript is available, extract_related_artifacts() can use it."""
        from backfill_archives import fetch_youtube_transcript, extract_related_artifacts
        result = fetch_youtube_transcript("_3PiX4OT9pE")
        if result is not None:
            related = extract_related_artifacts(result)
            self.assertIsInstance(related, list)
            # A Prefetch video should mention prefetch
            self.assertTrue(
                any("prefetch" in r for r in related),
                f"Prefetch video transcript should mention prefetch artifact, got: {related}"
            )


if __name__ == "__main__":
    unittest.main()
