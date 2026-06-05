#!/usr/bin/env python3
"""
insecure_server.py — Module A: Plaintext HTTP Server (Insecure Baseline)
=========================================================================
SECURITY CONCEPT: Lack of Confidentiality
This server intentionally runs over plain HTTP (no encryption) to demonstrate
how credentials transmitted without TLS can be intercepted and read in plaintext.
This directly violates the CIA Triad principle of CONFIDENTIALITY.

Lab Environment: Run only on personal/lab machines or controlled virtual environments.
Test Case: TC-01
"""

import http.server
import socketserver
import urllib.parse
import sys

# ----- Configuration -------------------------------------------------------
PORT = 8000                  # Standard HTTP development port (no SSL)
HOST = "0.0.0.0"            # Listen on all interfaces so tshark/pyshark can capture

# Simple HTML login form served to the browser
LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Insecure Login (HTTP Demo)</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f0f2f5;
               display: flex; justify-content: center; align-items: center;
               height: 100vh; margin: 0; }}
        .box {{ background: white; padding: 40px; border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15); width: 320px; }}
        h2   {{ color: #cc0000; text-align: center; margin-bottom: 8px; }}
        .warn{{ color: #cc0000; font-size: 12px; text-align: center;
                margin-bottom: 20px; }}
        input{{ width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box;
                border: 1px solid #ddd; border-radius: 4px; }}
        button{{ width: 100%; padding: 12px; background: #cc0000; color: white;
                 border: none; border-radius: 4px; cursor: pointer; font-size: 15px; }}
        button:hover {{ background: #aa0000; }}
    </style>
</head>
<body>
  <div class="box">
    <h2>⚠ Insecure HTTP Login</h2>
    <p class="warn">[ No Encryption — Credentials sent in PLAINTEXT ]</p>
    <form method="POST" action="/login">
      <input type="text"     name="username" placeholder="Username" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Login (Unencrypted)</button>
    </form>
    {message}
  </div>
</body>
</html>"""


class InsecureLoginHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP request handler that processes login form submissions.
    Credentials are received and echoed back WITHOUT any encryption,
    making them trivially interceptable by a network sniffer (tshark/pyshark).
    """

    def log_message(self, format, *args):
        # Override to print clean, formatted server logs
        print(f"  [HTTP SERVER] {self.address_string()} → {format % args}")

    def do_GET(self):
        """Serve the login form on GET /"""
        if self.path == "/" or self.path == "/login":
            self._serve_login_page("")
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        """
        Handle credential submission.
        SECURITY NOTE: POST body is transmitted in cleartext over plain HTTP.
        The username and password are directly readable in the TCP stream.
        """
        if self.path == "/login":
            # Read the Content-Length header to know how many bytes to consume
            content_length = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_length).decode("utf-8")

            # URL-decode the form fields (application/x-www-form-urlencoded)
            params = urllib.parse.parse_qs(post_body)
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            # Print credentials to server console to confirm receipt
            print("\n" + "=" * 60)
            print("  [!!] PLAINTEXT CREDENTIALS RECEIVED ON SERVER SIDE")
            print(f"       Username : {username}")
            print(f"       Password : {password}")
            print("  [!!] These are IDENTICAL to what tshark captures on wire!")
            print("=" * 60 + "\n")

            # Respond with a confirmation page
            msg = f'<p style="color:green;text-align:center;">Received: <b>{username}</b> / <b>{password}</b></p>'
            self._serve_login_page(msg)
        else:
            self.send_error(404, "Not Found")

    def _serve_login_page(self, message: str):
        """Helper: send the HTML login page with an optional inline message."""
        html = LOGIN_PAGE_HTML.format(message=message)
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    print("=" * 60)
    print("  MODULE A — INSECURE HTTP SERVER (TC-01 Baseline)")
    print("=" * 60)
    print(f"  Listening on http://{HOST}:{PORT}")
    print("  ⚠  No TLS/SSL — all traffic is PLAINTEXT")
    print("  Run sniffer_agent.py in another terminal to capture creds.")
    print("  Press Ctrl+C to stop.\n")

    try:
        # Allow immediate port reuse after a restart
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer((HOST, PORT), InsecureLoginHandler) as httpd:
            httpd.serve_forever()
    except PermissionError:
        print(f"  [ERROR] Permission denied on port {PORT}. Try sudo or use port > 1024.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n  [INFO] Server stopped by user.")


if __name__ == "__main__":
    main()
