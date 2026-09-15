"""
Path-prefixed lab server for exercising application-scope handling.
------------------------------------------------------------------
Unlike examples/lab_server.py (which serves at the host root), this
target mounts a small app under /App/ and redirects /App/ -> /App/login
- deliberately mirroring how real Java web apps (WebGoat, Tomcat
context paths, etc.) are typically deployed. It also serves an
unrelated page at the host root so a scan can be checked for
accidentally mixing "unrelated local service" content into the
application's results.

Usage:
    python3 examples/path_prefixed_lab_server.py [port]
    # then:
    python3 main.py --target http://127.0.0.1:8091/App/ --authorized
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8091

LOGIN_PAGE = b"""<html><head><title>Login</title></head><body>
<form action="/App/login" method="POST">
<input name="username"><input name="password" type="password">
</form>
<a href="/App/register">Register</a>
<a href="/">Unrelated root link</a>
<script src="/App/js/app.js"></script>
</body></html>"""

APP_JS = b"const base='/App/api/v1'; fetch(base+'/session');"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype="text/html", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/App/", "/App"):
            self._send(302, b"", headers={"Location": "/App/login"})
        elif self.path == "/App/login":
            self._send(200, LOGIN_PAGE)
        elif self.path == "/App/register":
            self._send(200, b"<html><body>Register page</body></html>")
        elif self.path == "/App/js/app.js":
            self._send(200, APP_JS, ctype="application/javascript")
        elif self.path == "/":
            self._send(200, b"<html><body>Unrelated root service, not the target app</body></html>")
        else:
            self._send(404, b"Not Found")

    def do_POST(self):
        self._send(200, b"OK")


class ReuseServer(HTTPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    print(f"Path-prefixed lab server running at http://127.0.0.1:{PORT}/App/  (Ctrl+C to stop)")
    ReuseServer(("127.0.0.1", PORT), Handler).serve_forever()
