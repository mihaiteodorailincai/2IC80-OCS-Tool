from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import os

SESSIONS = {}  # session_id -> username

def generate_session_id():
    return os.urandom(16).hex()

# pointer to CSS file living in same folder
CSS_PATH = os.path.join(os.path.dirname(__file__), "http_insecure_site_style.css")



# Simple HTTP page with insecure session management, used for HTTP Session Hijacking
# Run in terminal inside src/services: python http_insecure_site.py
class InsecureWebApp(BaseHTTPRequestHandler):

    def do_GET(self):

        # Serve CSS styling required for the UI
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

        # Home page
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

        # Login form: centralized and styled
        if self.path == "/login":
            self.respond(200, """
                <div class='center-screen'>
                    <div class='page-box glass'>
                        <h2>Login to FBI Confidential</h2>

                        <form method='POST' action='/login'>
                            <input name='username' placeholder='Username'>
                            <input name='password' type='password' placeholder='Password'>
                            <button type='submit'>Login</button>
                        </form>
                    </div>
                </div>
            """)
            return

        # Profile page (main target for attack & session hijacking)
        if self.path == "/profile":

            # check that session cookie is present
            cookie = self.headers.get("Cookie")
            if not cookie or "sessionid=" not in cookie:
                self.respond(403, """
                    <div class='center-screen'>
                        <div class='page-box glass'>
                            <h2>Forbidden</h2>
                            <p>No valid session.</p>
                        </div>
                    </div>
                """)
                return
            
            # extract session token
            session_id = cookie.split("sessionid=")[1]
            username = SESSIONS.get(session_id)

            # verify that session exists
            if not username:
                self.respond(403, """
                    <div class='center-screen'>
                        <div class='page-box glass'>
                            <h2>Forbidden</h2>
                            <p>Invalid session.</p>
                        </div>
                    </div>
                """)
                return

            # Construct a full styled profile dashboard
            self.respond(200, f"""
                <div class='profile-container'>

                    <!-- Banner -->
                    <div class='profile-banner'></div>

                    <!-- Avatar + Username -->
                    <img class='profile-avatar' src='https://imgur.com/gallery/takedown-MJk3zwJ' alt='Profile Picture'>

                    <div class='profile-info'>
                        <h2>@{username}</h2>
                        <div class='profile-bio'>
                            Special Agent active in classified operations.
                            Monitoring encrypted channels and intelligence feeds.
                        </div>
                    </div>

                    <!-- Secret classified message  -->
                    <div class='secret-card'>
                        <h3>Classified Message</h3>
                        <p>Operation Nightwatch: <b>ACTIVE</b></p>
                        <p>Level 4 Access Granted</p>
                    </div>

                    <!-- Post to feed area -->
                    <div class='new-post-box'>
                        <h3>Post to Secure Feed</h3>
                        <textarea placeholder='Write a transmission update...'></textarea>
                        <button>Transmit</button>
                    </div>

                    <!-- Example feed posts -->
                    <div class='post'>
                        <div class='author'>@{username}</div>
                        <div class='content'>
                            Perimeter sweep completed. No hostile signals detected.
                        </div>
                    </div>

                    <div class='post'>
                        <div class='author'>CentralCommand</div>
                        <div class='content'>
                            Reminder: Maintain secure communications protocol at all times.
                        </div>
                    </div>

                </div>
            """)
            return

        # Unknown route flag for any other location
        self.respond(404, "<h2>404 Not Found</h2>")



    def do_POST(self):
        # Login logic (session is created and stored in SESSIONS)
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            params = parse_qs(body)

            username = params.get("username", [""])[0]
            # password is ignored—this is insecure on purpose

            # Create session ID and attach to username
            session_id = generate_session_id()
            SESSIONS[session_id] = username

            # Set cookie for session
            self.send_response(302)
            self.send_header("Set-Cookie", f"sessionid={session_id}; Path=/")
            self.send_header("Location", "/profile")
            self.end_headers()
            return

        # Unknown POST route
        self.respond(404, "<h2>404 Not Found</h2>")



    # Utility function: wraps HTML into full page with CSS link
    def respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        full_page = f"""
        <html>
            <head>
                <link rel="stylesheet" href="/http_insecure_site_style.css">
            </head>
            <body>
                {body}
            </body>
        </html>
        """

        self.wfile.write(full_page.encode())



def run():
    server = HTTPServer(("0.0.0.0", 80), InsecureWebApp)
    print("Insecure FBI Confidential Web App running on port 80...")
    server.serve_forever()


if __name__ == "__main__":
    run()
