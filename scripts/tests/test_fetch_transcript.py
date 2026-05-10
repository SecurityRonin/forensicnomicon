"""
Tests for scripts/fetch_transcript.py

Pure-logic tests — no real HTTP calls.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import fetch_transcript as ft  # noqa: E402


class TestExtractYouTubeId(unittest.TestCase):
    def test_watch_url(self):
        self.assertEqual(
            ft.extract_youtube_id("https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
            "dQw4w9WgXcQ",
        )

    def test_short_url(self):
        self.assertEqual(
            ft.extract_youtube_id("https://youtu.be/dQw4w9WgXcQ"),
            "dQw4w9WgXcQ",
        )

    def test_embed_url(self):
        self.assertEqual(
            ft.extract_youtube_id("https://www.youtube.com/embed/dQw4w9WgXcQ"),
            "dQw4w9WgXcQ",
        )

    def test_url_with_extra_params(self):
        # Video IDs are exactly 11 chars; extra query params should be ignored
        url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLx&index=3"
        self.assertEqual(ft.extract_youtube_id(url), "dQw4w9WgXcQ")

    def test_non_youtube_url_returns_none(self):
        self.assertIsNone(ft.extract_youtube_id("https://example.com/video/abc"))

    def test_empty_string_returns_none(self):
        self.assertIsNone(ft.extract_youtube_id(""))


class TestStripVtt(unittest.TestCase):
    def test_strips_webvtt_header(self):
        self.assertNotIn("WEBVTT", ft._strip_vtt("WEBVTT\n\nHello\n"))

    def test_strips_timestamps(self):
        vtt = "WEBVTT\n\n1\n00:00:01.000 --> 00:00:03.000\nHello world\n"
        result = ft._strip_vtt(vtt)
        self.assertIn("Hello world", result)
        self.assertNotIn("-->", result)

    def test_strips_sequence_numbers(self):
        vtt = "WEBVTT\n\n1\nHello\n2\nWorld\n"
        result = ft._strip_vtt(vtt)
        self.assertNotIn("1", result.split())
        self.assertNotIn("2", result.split())

    def test_deduplicates_repeated_lines(self):
        vtt = "WEBVTT\nHello\nHello\nWorld\n"
        result = ft._strip_vtt(vtt)
        self.assertEqual(result.count("Hello"), 1)

    def test_strips_html_tags(self):
        vtt = "WEBVTT\n<c.color>Hello</c> <b>world</b>\n"
        result = ft._strip_vtt(vtt)
        self.assertIn("Hello", result)
        self.assertIn("world", result)
        self.assertNotIn("<", result)

    def test_empty_vtt_returns_empty(self):
        self.assertEqual(ft._strip_vtt("WEBVTT\n\n"), "")


class TestTextExtractor(unittest.TestCase):
    def test_extracts_paragraph_text(self):
        parser = ft._TextExtractor()
        parser.feed("<html><body><p>Hello world</p></body></html>")
        self.assertIn("Hello world", parser.get_text())

    def test_skips_script_content(self):
        parser = ft._TextExtractor()
        parser.feed("<html><script>var x = 1;</script><p>Visible</p></html>")
        text = parser.get_text()
        self.assertIn("Visible", text)
        self.assertNotIn("var x", text)

    def test_skips_style_content(self):
        parser = ft._TextExtractor()
        parser.feed("<style>.foo { color: red; }</style><p>Content</p>")
        text = parser.get_text()
        self.assertIn("Content", text)
        self.assertNotIn("color", text)

    def test_skips_nav_content(self):
        parser = ft._TextExtractor()
        parser.feed("<nav>Menu items</nav><main>Body content</main>")
        text = parser.get_text()
        self.assertIn("Body content", text)
        self.assertNotIn("Menu items", text)

    def test_skips_footer_content(self):
        parser = ft._TextExtractor()
        parser.feed("<footer>Copyright 2026</footer><article>Article</article>")
        text = parser.get_text()
        self.assertIn("Article", text)
        self.assertNotIn("Copyright", text)

    def test_skips_header_content(self):
        parser = ft._TextExtractor()
        parser.feed("<header>Site header</header><p>Page text</p>")
        text = parser.get_text()
        self.assertIn("Page text", text)
        self.assertNotIn("Site header", text)

    def test_nested_skip_tags_handled(self):
        parser = ft._TextExtractor()
        parser.feed("<nav><ul><li>Item</li></ul></nav><p>Real</p>")
        text = parser.get_text()
        self.assertIn("Real", text)
        self.assertNotIn("Item", text)

    def test_empty_html_returns_empty(self):
        parser = ft._TextExtractor()
        parser.feed("")
        self.assertEqual(parser.get_text(), "")


class TestFetchYouTubeTranscript(unittest.TestCase):
    def _make_mock_response(self, content: bytes):
        mock = MagicMock()
        mock.__enter__ = lambda s: s
        mock.__exit__ = MagicMock(return_value=False)
        mock.read.return_value = content
        return mock

    def test_returns_stripped_transcript_on_success(self):
        vtt = b"WEBVTT\n\nHello forensics world\n"
        with patch("urllib.request.urlopen", return_value=self._make_mock_response(vtt)):
            result = ft.fetch_youtube_transcript("dQw4w9WgXcQ")
        self.assertIsNotNone(result)
        self.assertIn("Hello forensics world", result)

    def test_returns_none_on_empty_response(self):
        with patch("urllib.request.urlopen", return_value=self._make_mock_response(b"")):
            result = ft.fetch_youtube_transcript("dQw4w9WgXcQ")
        self.assertIsNone(result)

    def test_returns_none_on_whitespace_only_response(self):
        with patch("urllib.request.urlopen", return_value=self._make_mock_response(b"   \n")):
            result = ft.fetch_youtube_transcript("dQw4w9WgXcQ")
        self.assertIsNone(result)

    def test_returns_none_on_network_error(self):
        with patch("urllib.request.urlopen", side_effect=OSError("network error")):
            result = ft.fetch_youtube_transcript("dQw4w9WgXcQ")
        self.assertIsNone(result)

    def test_constructs_correct_timedtext_url(self):
        captured = []

        def fake_urlopen(req, **kwargs):
            captured.append(req.full_url if hasattr(req, "full_url") else str(req))
            raise OSError("stop")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            ft.fetch_youtube_transcript("ABC123xyz01")

        self.assertTrue(any("ABC123xyz01" in u for u in captured))
        self.assertTrue(any("timedtext" in u for u in captured))


class TestFetchPageText(unittest.TestCase):
    def _make_mock_response(self, content: bytes):
        mock = MagicMock()
        mock.__enter__ = lambda s: s
        mock.__exit__ = MagicMock(return_value=False)
        mock.read.return_value = content
        return mock

    def test_returns_body_text_on_success(self):
        html = b"<html><body><p>Show notes here</p></body></html>"
        with patch("urllib.request.urlopen", return_value=self._make_mock_response(html)):
            result = ft.fetch_page_text("https://www.forensicfocus.com/podcast/ep1/")
        self.assertIsNotNone(result)
        self.assertIn("Show notes here", result)

    def test_returns_none_on_network_error(self):
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            result = ft.fetch_page_text("https://www.forensicfocus.com/podcast/ep1/")
        self.assertIsNone(result)

    def test_returns_none_on_empty_page(self):
        html = b"<html><body></body></html>"
        with patch("urllib.request.urlopen", return_value=self._make_mock_response(html)):
            result = ft.fetch_page_text("https://www.forensicfocus.com/podcast/ep1/")
        self.assertIsNone(result)


class TestFetchTranscriptDispatch(unittest.TestCase):
    def test_youtube_watch_url_routes_to_youtube_fetcher(self):
        with patch.object(ft, "fetch_youtube_transcript", return_value="yt transcript") as m:
            result = ft.fetch_transcript("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        m.assert_called_once_with("dQw4w9WgXcQ")
        self.assertEqual(result, "yt transcript")

    def test_youtu_be_short_url_routes_to_youtube_fetcher(self):
        with patch.object(ft, "fetch_youtube_transcript", return_value="yt short") as m:
            result = ft.fetch_transcript("https://youtu.be/dQw4w9WgXcQ")
        m.assert_called_once_with("dQw4w9WgXcQ")
        self.assertEqual(result, "yt short")

    def test_forensicfocus_podcast_url_routes_to_page_fetcher(self):
        url = "https://www.forensicfocus.com/podcast/dfir-2026-ai-episode/"
        with patch.object(ft, "fetch_page_text", return_value="show notes") as m:
            result = ft.fetch_transcript(url)
        m.assert_called_once_with(url)
        self.assertEqual(result, "show notes")

    def test_forensicfocus_article_url_returns_none(self):
        with patch.object(ft, "fetch_page_text") as m:
            result = ft.fetch_transcript("https://www.forensicfocus.com/articles/dfir-backlogs/")
        m.assert_not_called()
        self.assertIsNone(result)

    def test_forensicfocus_news_url_returns_none(self):
        result = ft.fetch_transcript(
            "https://www.forensicfocus.com/news/passware-decrypts-s10/"
        )
        self.assertIsNone(result)

    def test_unknown_domain_returns_none(self):
        result = ft.fetch_transcript("https://example.com/some-blog-post")
        self.assertIsNone(result)

    def test_empty_url_returns_none(self):
        result = ft.fetch_transcript("")
        self.assertIsNone(result)


class TestIsNoiseUrl(unittest.TestCase):
    def test_round_up_is_noise(self):
        self.assertTrue(
            ft.is_noise_url(
                "https://www.forensicfocus.com/news/digital-forensics-round-up-april-22-2026/"
            )
        )

    def test_digest_is_noise(self):
        self.assertTrue(
            ft.is_noise_url(
                "https://www.forensicfocus.com/news/forensic-focus-digest-may-08-2026/"
            )
        )

    def test_acquires_is_noise(self):
        self.assertTrue(
            ft.is_noise_url(
                "https://www.forensicfocus.com/news/magnet-forensics-acquires-v2-forensics/"
            )
        )

    def test_partners_with_is_noise(self):
        self.assertTrue(
            ft.is_noise_url(
                "https://www.forensicfocus.com/news/cellebrite-partners-with-acme/"
            )
        )

    def test_joins_is_noise(self):
        self.assertTrue(
            ft.is_noise_url("https://www.forensicfocus.com/news/alice-joins-belkasoft/")
        )

    def test_technical_article_is_not_noise(self):
        self.assertFalse(
            ft.is_noise_url(
                "https://www.forensicfocus.com/articles/dfir-backlogs-burnout-and-cognitive-fatigue/"
            )
        )

    def test_podcast_is_not_noise(self):
        self.assertFalse(
            ft.is_noise_url(
                "https://www.forensicfocus.com/podcast/dfir-in-2026-ai-button-pusher-forensics/"
            )
        )

    def test_tool_release_news_is_not_noise(self):
        self.assertFalse(
            ft.is_noise_url(
                "https://www.forensicfocus.com/news/passware-kit-mobile-2026-v3-decrypts-samsung/"
            )
        )

    def test_non_forensicfocus_url_is_not_noise(self):
        self.assertFalse(
            ft.is_noise_url("https://www.magnetforensics.com/blog/acquires-something/")
        )


if __name__ == "__main__":
    unittest.main()
