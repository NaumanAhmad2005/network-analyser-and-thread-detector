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
    <title>Instagram - Login Demo</title>
    <link href="https://fonts.googleapis.com/css2?family=Grand+Hotel&family=Outfit:wght@300;400;500;600&display=swap" rel="stylesheet">
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}
        body {{
            background-color: #f0f9ff;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }}
        .main-card {{
            background: #ffffff;
            border: 1px solid #dbdbdb;
            border-radius: 1px;
            width: 100%;
            max-width: 935px;
            min-height: 580px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            align-items: center;
            padding: 40px 20px 28px 20px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.02);
        }}
        .login-container {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex-grow: 1;
            width: 100%;
        }}
        .login-box {{
            background-color: #ffffff;
            border: 1px solid #dbdbdb;
            border-radius: 1px;
            width: 100%;
            max-width: 350px;
            padding: 30px 40px 25px 40px;
            display: flex;
            flex-direction: column;
            text-align: center;
        }}
        .logo-container {{
            margin: 10px auto 20px auto;
        }}
        .logo-text {{
            font-family: 'Grand Hotel', cursive;
            font-size: 52px;
            color: #262626;
            user-select: none;
        }}
        .form-container {{
            display: flex;
            flex-direction: column;
        }}
        .input-group {{
            position: relative;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
        }}
        .input-group input {{
            width: 100%;
            padding: 11px 8px 9px 8px;
            background: #fafafa;
            border: 1px solid #dbdbdb;
            border-radius: 3px;
            font-size: 12px;
            color: #262626;
            outline: none;
        }}
        .input-group input:focus {{
            border-color: #a8a8a8;
        }}
        .input-group .toggle-pass {{
            position: absolute;
            right: 8px;
            font-size: 14px;
            font-weight: 600;
            color: #262626;
            cursor: pointer;
            user-select: none;
            background: none;
            border: none;
            outline: none;
        }}
        .login-btn {{
            background-color: #0095f6;
            border: 1px solid transparent;
            border-radius: 8px;
            color: #ffffff;
            font-weight: 600;
            font-size: 14px;
            padding: 7px 16px;
            cursor: pointer;
            margin-top: 8px;
            text-align: center;
            user-select: none;
            transition: background-color 0.1s ease;
        }}
        .login-btn:hover {{
            background-color: #1877f2;
        }}
        .divider-container {{
            display: flex;
            align-items: center;
            margin: 20px 0 20px 0;
        }}
        .divider-line {{
            flex-grow: 1;
            height: 1px;
            background-color: #dbdbdb;
        }}
        .divider-text {{
            color: #8e8e8e;
            font-size: 12px;
            font-weight: 600;
            margin: 0 18px;
            text-transform: uppercase;
        }}
        .fb-login-btn {{
            background: none;
            border: none;
            color: #385185;
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            cursor: pointer;
            margin: 8px 0;
            text-decoration: none;
        }}
        .fb-icon {{
            background-color: #385185;
            color: white;
            border-radius: 4px;
            width: 16px;
            height: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: bold;
        }}
        .forgot-pass {{
            color: #00376b;
            font-size: 12px;
            text-align: center;
            text-decoration: none;
            margin-top: 12px;
        }}
        .footer-container {{
            width: 100%;
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-top: 30px;
        }}
        .footer-links {{
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 16px;
            width: 100%;
        }}
        .footer-links a {{
            color: #8e8e8e;
            font-size: 12px;
            text-decoration: none;
        }}
        .footer-links a:hover {{
            text-decoration: underline;
        }}
        .server-indicator {{
            margin-top: 24px;
            text-align: center;
        }}
        .indicator-badge {{
            display: inline-block;
            padding: 6px 14px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background-color: #ffebee;
            color: #c62828;
            border: 1px solid #ffcdd2;
        }}
        .message-box {{
            margin-top: 15px;
            font-size: 13px;
        }}
    </style>
</head>
<body>
  <div class="main-card">
    <div class="login-container">
      <div class="login-box">
        <div class="logo-container">
          <div class="logo-text">Instagram</div>
        </div>
        
        <form class="form-container" method="POST" action="/login">
          <div class="input-group">
            <input type="text" name="username" placeholder="Phone number, username, or email" required>
          </div>
          <div class="input-group">
            <input type="password" name="password" id="password-field" placeholder="Password" required>
            <button type="button" class="toggle-pass" onclick="togglePassword()">Show</button>
          </div>
          <button type="submit" class="login-btn">Log in</button>
        </form>
        
        <div class="divider-container">
          <div class="divider-line"></div>
          <div class="divider-text">or</div>
          <div class="divider-line"></div>
        </div>
        
        <a href="#" class="fb-login-btn">
          <span class="fb-icon">f</span> Log in with Facebook
        </a>
        
        <a href="#" class="forgot-pass">Forgot password?</a>
        
        <div class="message-box">
          {message}
        </div>
      </div>
    </div>
    
    <div class="footer-container">
      <div class="footer-links">
        <a href="#">Meta</a>
        <a href="#">About</a>
        <a href="#">Blog</a>
        <a href="#">Jobs</a>
        <a href="#">Help</a>
        <a href="#">API</a>
        <a href="#">Privacy</a>
        <a href="#">Cookie Settings</a>
        <a href="#">Terms</a>
        <a href="#">Locations</a>
        <a href="#">Instagram Lite</a>
        <a href="#">Threads</a>
        <a href="#">Contact Uploading & Non-Users</a>
        <a href="#">Meta Verified</a>
      </div>
      <div class="server-indicator">
        <span class="indicator-badge">HTTP (PLAINTEXT BASELINE DEMO)</span>
      </div>
    </div>
  </div>

  <script>
    function togglePassword() {{
      var x = document.getElementById("password-field");
      var btn = document.querySelector(".toggle-pass");
      if (x.type === "password") {{
        x.type = "text";
        btn.textContent = "Hide";
      }} else {{
        x.type = "password";
        btn.textContent = "Show";
      }}
    }}
  </script>
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
