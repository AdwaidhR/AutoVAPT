#!/usr/bin/env python3
"""
Minimal intentionally-quirky local HTTP server for exercising AutoVAPT
safely against 127.0.0.1. Built entirely on http.server (stdlib) - no
dependencies needed to run this either.

It deliberately:
  - exposes a fake /.git/HEAD and /backup.sql (content-discovery test)
  - omits security headers (header-audit test)
  - sets a cookie without Secure/HttpOnly/SameSite (cookie test)
  - reflects a query parameter unescaped (XSS-indicator test)
  - returns a fake SQL error on a quote character (SQLi-indicator test)
  - serves a tiny HTML page with a form, a link, and a JS file
    referencing a couple of fake API endpoints (crawler/JS test)

Usage:
    python3 examples/lab_server.py [port]
    # then, in another terminal:
    python3 main.py --target http://127.0.0.1:8000 --authorized
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

PAGE = b"""<!DOCTYPE html><html><head><title>AutoVAPT Lab Target</title></head>
<body>
<h1>Intentionally Vulnerable Lab App</h1>
<a href="/about">About</a>
<a href="/admin">Admin</a>
<form action="/login" method="POST">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
<script src="/app.js"></script>
</body></html>"""

JS = b"""
const API_BASE = "/api/v1";
function login(user, pass) {
  fetch(API_BASE + "/auth/login", {method: "POST"});
}
const debugEndpoint = "/debug/status";
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        pass  # keep test output quiet

    def _send(self, status, body, content_type="text/html", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # NOTE: deliberately no CSP/HSTS/X-Frame-Options - this is the
        # lab target, not the framework - AutoVAPT should FLAG this.
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/":
            if "q" in qs:  # reflected input indicator
                reflected = qs["q"][0].encode()
                self._send(200, PAGE + b"<div>" + reflected + b"</div>")
            elif "id" in qs and "'" in qs["id"][0]:
                self._send(500, b"You have an error in your SQL syntax; check the manual")
            else:
                self._send(200, PAGE, extra_headers={
                    "Set-Cookie": "session=abc123; Path=/"  # missing Secure/HttpOnly/SameSite
                })
        elif path == "/about":
            self._send(200, b"<h1>About this lab app</h1>")
        elif path == "/admin":
            self._send(200, b"<h1>Admin Panel (should require auth in a real app)</h1>")
        elif path == "/app.js":
            self._send(200, JS, content_type="application/javascript")
        elif path == "/.git/HEAD":
            self._send(200, b"ref: refs/heads/main\n", content_type="text/plain")
        elif path == "/backup.sql":
            self._send(200, b"-- fake sql dump for testing --\n", content_type="text/plain")
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin\nDisallow: /api/\n",
                       content_type="text/plain")
        else:
            self._send(404, b"Not Found")

    def do_POST(self):
        self._send(200, b"OK")


class ReuseServer(HTTPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    server = ReuseServer(("127.0.0.1", PORT), Handler)
    print(f"AutoVAPT lab server running at http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    server.serve_forever()
