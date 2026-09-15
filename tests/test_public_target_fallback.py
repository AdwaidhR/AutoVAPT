import os
import sys
import unittest
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.http_recon import fetch
from main import _record_observed_web_port


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><title>AutoVAPT fallback</title><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestPublicTargetRobustness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_http_reachable_port_is_recorded(self):
        result = {"open_ports": []}
        port = self.server.server_address[1]
        observed = _record_observed_web_port(result, f"http://127.0.0.1:{port}/")
        self.assertEqual(observed, port)
        self.assertEqual(result["open_ports"][0]["port"], port)
        self.assertEqual(result["open_ports"][0]["source"], "HTTP reconnaissance (reachable application)")

    @unittest.skipUnless(__import__("shutil").which("curl"), "curl not installed")
    def test_fetch_falls_back_to_curl_if_urllib_fails(self):
        port = self.server.server_address[1]
        with patch("modules.http_recon.urllib.request.build_opener", side_effect=OSError("simulated urllib failure")):
            result = fetch(f"http://127.0.0.1:{port}/", timeout=3)
        self.assertTrue(result.ok)
        self.assertEqual(result.status, 200)
        self.assertIn("AutoVAPT fallback", result.body)


if __name__ == "__main__":
    unittest.main()
