from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import os
import html
from datetime import datetime

SESSIONS = {}   # session_id -> username
PASSWORDS = {}  # username -> password (intentionally weak + for demo only)
POSTS = []      # list of dicts: {user, msg, ts}

CSS_PATH = os.path.join(os.path.dirname(__file__), "http_insecure_site_style.css")


def generate_session_id():
    return os.urandom(16).hex()


def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_session(headers) -> tuple[str | None, str | None]:
    """
    Returns (session_id, username) if valid else (None, None).
    """
    cookie = headers.get("Cookie")
    if not cookie or "sessionid=" not in cookie:
        return None, None

    session_id = cookie.split("sessionid=", 1)[1].split(";", 1)[0].strip()
    username = SESSIONS.get(session_id)
    if not username:
        return None, None

    return session_id, username


def invalidate_user_sessions(username: str):
    """
    Remove all session IDs mapped to username.
    """
    to_delete = [sid for sid, u in SESSIONS.items() if u == username]
    for sid in to_delete:
        del SESSIONS[sid]


class InsecureWebApp(BaseHTTPRequestHandler):
    """
    Simple HTTP page with intentionally insecure session management, used for HTTP Session Hijacking.
    Run on Attacker VM: sudo python3 src/services/http_insecure_site.py
    """

    # GET
    def do_GET(self):
        # Serve CSS
        if self.path == "/http_insecure_site_style.css":
            try:
                with open(CSS_PATH, "rb") as f:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/css")
                    self.end_headers()
                    self.wfile.write(f.read())
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"/* CSS file not found */")
            return

        # Home
        if self.path == "/":
            self.respond(200, """
                <div class='center-screen'>
                    <div class='page-box glass'>
                        <h2>Welcome to FBI Confidential</h2>
                        <p><a href='/login'>Proceed to Login</a></p>
                    </div>
                </div>
            """)
            return

        # Login page
        if self.path == "/login":
            self.respond(200, """
                <div class='center-screen'>
                    <div class='page-box glass'>
                        <h2>Login to FBI Confidential</h2>
                        <p class='hint'>This site is intentionally insecure (training).</p>
                        <form method='POST' action='/login'>
                            <input name='username' placeholder='Username' required>
                            <input name='password' type='password' placeholder='Password' required>
                            <button type='submit'>Login</button>
                        </form>
                    </div>
                </div>
            """)
            return

        # Logout (kills only current session)
        if self.path == "/logout":
            sid, user = parse_session(self.headers)
            if sid and user:
                del SESSIONS[sid]
            # Redirect to login
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return

        # Change password page (requires valid session)
        if self.path == "/change-password":
            sid, user = parse_session(self.headers)
            if not user:
                self._forbidden_with_js_logout("No valid session. Please login again.")
                return

            self.respond(200, f"""
                <div class='profile-container'>
                    <div class='secret-card'>
                        <h3>Change Password</h3>
                        <p>Logged in as <b>@{html.escape(user)}</b></p>
                        <form method='POST' action='/change-password'>
                            <input name='new_password' type='password' placeholder='New password' required style="width:100%; padding:12px; border-radius:8px; margin-top:10px;">
                            <button type='submit' style="margin-top:12px;">Update Password</button>
                        </form>

                        <hr style="margin:18px 0; border: 1px solid #1f242c;" />

                        <h3>Security Actions</h3>
                        <p class='hint'>For demo: invalidate all sessions for this user.</p>
                        <form method='POST' action='/invalidate-sessions'>
                            <input type='hidden' name='confirm' value='YES'>
                            <button type='submit' style="background:#b42318;">Invalidate ALL Sessions</button>
                        </form>

                        <p style="margin-top:14px;"><a href='/profile'>Back to profile</a></p>
                    </div>
                </div>
            """)
            return

        # Profile page (requires valid session)
        if self.path == "/profile":
            sid, user = parse_session(self.headers)
            if not user:
                self._forbidden_with_js_logout("Your session is invalid or expired. You were logged out.")
                return

            # Render feed posts
            feed_html = ""
            for p in reversed(POSTS[-12:]):  # last 12 posts
                feed_html += f"""
                    <div class='post'>
                        <div class='author'>@{html.escape(p['user'])}</div>
                        <div class='content'>{html.escape(p['msg'])}</div>
                        <div class='hint' style="margin-top:10px;">{html.escape(p['ts'])}</div>
                    </div>
                """

            self.respond(200, f"""
                <div class='profile-container'>

                    <div class='profile-banner'></div>

                    <img class='profile-avatar' src='https://i.imgur.com/4M34hi2.png' alt='Profile Picture'>

                    <div class='profile-info'>
                        <h2>@{html.escape(user)}</h2>
                        <div class='profile-bio'>
                            Special Agent active in classified operations.<br/>
                            Monitoring encrypted channels and intelligence feeds.
                        </div>
                    </div>

                    <div class='secret-card'>
                        <h3>Classified Message</h3>
                        <p>Operation Nightwatch: <b>ACTIVE</b></p>
                        <p>Level 4 Access Granted</p>
                        <p class='hint'>Session-based access (intentionally insecure).</p>
                    </div>

                    <div class='new-post-box'>
                        <h3>Post to Secure Feed</h3>
                        <form method="POST" action="/post">
                            <textarea name="message" placeholder="Write a transmission update..." required></textarea>
                            <button type="submit">Transmit</button>
                        </form>

                        <div style="margin-top:14px;">
                            <a href="/change-password">Change password</a>
                            &nbsp;·&nbsp;
                            <a href="/logout">Logout</a>
                        </div>
                    </div>

                    {feed_html if feed_html else "<div class='post'><div class='content'>No posts yet.</div></div>"}

                </div>
            """)
            return

        # Unknown route
        self.respond(404, "<h2>404 Not Found</h2>")

    # POST
    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="ignore")
            params = parse_qs(body)

            username = params.get("username", [""])[0].strip()
            password = params.get("password", [""])[0]

            if not username:
                self.respond(400, "<h2>Bad Request</h2><p>Missing username.</p>")
                return

            # Intentionally insecure: "register on login"
            if username not in PASSWORDS:
                PASSWORDS[username] = password

            # Intentionally insecure: ignore password correctness (for demo)
            session_id = generate_session_id()
            SESSIONS[session_id] = username

            # Set cookie and redirect
            self.send_response(302)
            self.send_header("Set-Cookie", f"sessionid={session_id}; Path=/")
            self.send_header("Location", "/profile")
            self.end_headers()
            return

        if self.path == "/post":
            sid, user = parse_session(self.headers)
            if not user:
                self._forbidden_with_js_logout("Cannot post: invalid session.")
                return

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="ignore")
            params = parse_qs(body)
            msg = params.get("message", [""])[0].strip()

            if not msg:
                self.respond(400, "<h2>Bad Request</h2><p>Empty message.</p>")
                return

            POSTS.append({"user": user, "msg": msg, "ts": now_ts()})

            self.send_response(302)
            self.send_header("Location", "/profile")
            self.end_headers()
            return

        if self.path == "/change-password":
            sid, user = parse_session(self.headers)
            if not user:
                self._forbidden_with_js_logout("Cannot change password: invalid session.")
                return

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="ignore")
            params = parse_qs(body)
            new_pw = params.get("new_password", [""])[0]

            if not new_pw:
                self.respond(400, "<h2>Bad Request</h2><p>Empty password.</p>")
                return

            # Set new password
            PASSWORDS[user] = new_pw

            # Invalidate all sessions to force victim logout
            invalidate_user_sessions(user)

            # Create a fresh session for the requester (still insecure, but lets attacker continue)
            new_sid = generate_session_id()
            SESSIONS[new_sid] = user

            self.send_response(302)
            self.send_header("Set-Cookie", f"sessionid={new_sid}; Path=/")
            self.send_header("Location", "/profile")
            self.end_headers()
            return

        if self.path == "/invalidate-sessions":
            sid, user = parse_session(self.headers)
            if not user:
                self._forbidden_with_js_logout("Cannot invalidate sessions: invalid session.")
                return

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="ignore")
            params = parse_qs(body)
            confirm = params.get("confirm", [""])[0]

            if confirm != "YES":
                self.respond(400, "<h2>Bad Request</h2><p>Confirmation missing.</p>")
                return

            invalidate_user_sessions(user)

            # After invalidation, also kill current session by redirecting to login
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return

        # Unknown POST
        self.respond(404, "<h2>404 Not Found</h2>")

    # Helpers
    def respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        full_page = f"""
        <html>
            <head>
                <meta charset="utf-8"/>
                <link rel="stylesheet" href="/http_insecure_site_style.css">
                <title>FBI Confidential</title>
            </head>
            <body>
                {body}
            </body>
        </html>
        """
        self.wfile.write(full_page.encode("utf-8"))

    def _forbidden_with_js_logout(self, msg: str):
        # “victim gets logged out + message on screen” effect.
        self.respond(403, f"""
            <div class='center-screen'>
                <div class='page-box glass'>
                    <h2>Session Ended</h2>
                    <p>{html.escape(msg)}</p>
                    <button onclick="alert('You have been logged out. Please login again.'); window.location='/login';">
                        OK
                    </button>
                </div>
            </div>
        """)


def run():
    port = int(os.getenv("FBI_HTTP_PORT", "80"))
    server = HTTPServer(("0.0.0.0", port), InsecureWebApp)
    print(f"Insecure FBI Confidential Web App running on port {port}...")
    server.serve_forever()

if __name__ == "__main__":
    run()
