import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.web_crawler import _normalize, _same_host, _in_scope, _path_scope, PageParser


class TestURLNormalization(unittest.TestCase):
    def test_relative_link_resolves(self):
        self.assertEqual(
            _normalize("http://example.com/dir/", "page.html"),
            "http://example.com/dir/page.html",
        )

    def test_absolute_link_passthrough(self):
        self.assertEqual(
            _normalize("http://example.com/", "http://example.com/x"),
            "http://example.com/x",
        )

    def test_fragment_stripped(self):
        self.assertEqual(
            _normalize("http://example.com/", "page.html#section"),
            "http://example.com/page.html",
        )

    def test_javascript_and_mailto_ignored(self):
        self.assertIsNone(_normalize("http://example.com/", "javascript:void(0)"))
        self.assertIsNone(_normalize("http://example.com/", "mailto:test@example.com"))

    def test_same_host(self):
        self.assertTrue(_same_host("http://example.com/x", "example.com"))
        self.assertFalse(_same_host("http://other.com/x", "example.com"))

    def test_application_path_scope_is_preserved(self):
        base = "http://127.0.0.1:8080/WebGoat/"
        scope = _path_scope(base)
        self.assertEqual(scope, "/WebGoat/")
        self.assertTrue(_in_scope("http://127.0.0.1:8080/WebGoat/login", "127.0.0.1", scope))
        self.assertTrue(_in_scope("http://127.0.0.1:8080/WebGoat/lesson/1", "127.0.0.1", scope))
        self.assertFalse(_in_scope("http://127.0.0.1:8080/login", "127.0.0.1", scope))

    def test_origin_root_is_allowed_only_for_root_scope(self):
        self.assertTrue(_in_scope("http://example.com/login", "example.com", "/"))
        self.assertFalse(_in_scope("http://example.com/login", "example.com", "/WebGoat/"))


class TestPageParser(unittest.TestCase):
    def test_extracts_links_and_forms(self):
        html = '<a href="/a">A</a><form action="/submit" method="post">' \
               '<input name="user"></form><script src="/app.js"></script>'
        parser = PageParser()
        parser.feed(html)
        self.assertIn("/a", parser.links)
        self.assertEqual(len(parser.forms), 1)
        self.assertEqual(parser.forms[0]["action"], "/submit")
        self.assertEqual(parser.forms[0]["inputs"][0]["name"], "user")
        self.assertIn("/app.js", parser.scripts)


if __name__ == "__main__":
    unittest.main()
