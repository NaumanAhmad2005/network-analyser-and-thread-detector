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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InstaLogin - Security Baseline Demo</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}
        body {{
            background-color: #fafafa;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            width: 100%;
            max-width: 350px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}
        .login-box {{
            background-color: #fff;
            border: 1px solid #dbdbdb;
            border-radius: 8px;
            padding: 40px 30px 25px 30px;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
        }}
        .logo {{
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 8px;
            background: linear-gradient(45deg, #f09433 0%, #e6683c 25%, #dc2743 50%, #cc2366 75%, #bc1888 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-style: italic;
            letter-spacing: -1px;
        }}
        .demo-badge {{
            display: inline-block;
            padding: 5px 12px;
            font-size: 10px;
            font-weight: 700;
            border-radius: 20px;
            margin-bottom: 24px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background-color: #ffebee;
            color: #c62828;
            border: 1px solid #ffcdd2;
        }}
        .form-group {{
            position: relative;
            margin-bottom: 8px;
        }}
        .form-group input {{
            width: 100%;
            padding: 12px 10px;
            background: #fafafa;
            border: 1px solid #dbdbdb;
            border-radius: 4px;
            font-size: 12px;
            color: #262626;
            outline: none;
            transition: border-color 0.2s ease;
        }}
        .form-group input:focus {{
            border-color: #a8a8a8;
            background: #fff;
        }}
        .login-btn {{
            width: 100%;
            background-color: #0095f6;
            color: #fff;
            border: none;
            border-radius: 4px;
            padding: 10px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 8px;
            transition: background-color 0.2s ease;
        }}
        .login-btn:hover {{
            background-color: #1877f2;
        }}
        .divider {{
            display: flex;
            align-items: center;
            margin: 20px 0;
            color: #8e8e8e;
            font-size: 12px;
            font-weight: 600;
        }}
        .divider::before, .divider::after {{
            content: "";
            flex: 1;
            height: 1px;
            background-color: #dbdbdb;
        }}
        .divider span {{
            padding: 0 10px;
        }}
        .fb-login {{
            color: #385185;
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            cursor: pointer;
            text-decoration: none;
            margin-bottom: 15px;
            margin-top: 10px;
        }}
        .fb-icon {{
            font-weight: bold;
            font-size: 16px;
        }}
        .info-box {{
            background-color: #fff;
            border: 1px solid #dbdbdb;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            font-size: 14px;
            color: #262626;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
        }}
        .info-box a {{
            color: #0095f6;
            text-decoration: none;
            font-weight: 600;
        }}
        .message-container {{
            margin-top: 15px;
            font-size: 13px;
        }}
    </style>
</head>
<body>
  <div class="container">
    <div class="login-box">
      <div class="logo">InstaLogin</div>
      <span class="demo-badge">⚠ HTTP PLAINTEXT DEMO</span>
      
      <form method="POST" action="/login">
        <div class="form-group">
          <input type="text" name="username" placeholder="Phone number, username, or email" required>
        </div>
        <div class="form-group">
          <input type="password" name="password" placeholder="Password" required>
        </div>
        <button type="submit" class="login-btn">Log In</button>
      </form>
      
      <div class="divider">
        <span>OR</span>
      </div>
      
      <a href="#" class="fb-login">
        <span class="fb-icon">f</span> Log in with Facebook
      </a>
      
      <div class="message-container">
        {message}
      </div>
    </div>
    
    <div class="info-box">
      Don't have an account? <a href="#">Sign up</a>
    </div>
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
