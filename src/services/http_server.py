# # src/services/https_server.py
# import http.server
# import ssl

# def run_https_server():
#     """Run the HTTPS server for fbi.confidential."""
#     handler = http.server.SimpleHTTPRequestHandler
#     server = http.server.HTTPServer(('0.0.0.0', 443), handler)
    
#     # Wrap the server with SSL
#     server.socket = ssl.wrap_socket(server.socket, keyfile="fbi.key", certfile="fbi.crt", server_side=True)
#     print("HTTPS server running on https://fbi.confidential")
#     server.serve_forever()

# if __name__ == "__main__":
#     run_https_server()


# src/services/https_server.py
import http.server
import ssl
from urllib.parse import parse_qs
import os

SESSION_TOKEN = "secret-token"

class Handler(http.server.SimpleHTTPRequestHandler):

    #check if already logged in (token in cookies), else login
    def do_GET(self):
        if self.path == "/":
            self.serve_file("static/login.html")
        elif self.path == "/main":
            # Check fake session token
            cookies = self.headers.get("Cookie", "")
            if "session=" + SESSION_TOKEN in cookies:
                self.serve_file("static/main.html")
            else:
                self.redirect("/")
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers.get("Content-Length"))
            body = self.rfile.read(length).decode()
            data = parse_qs(body)

            username = data.get("username", [""])[0]
            password = data.get("password", [""])[0]

            if username == "admin" and password == "password":
                self.send_response(302)
                self.send_header("Set-Cookie", f"session={SESSION_TOKEN}")
                self.send_header("Location", "/main")
                self.end_headers()
            else:
                self.redirect("/")
        else:
            self.send_error(404)

    def serve_file(self, path):
        if not os.path.exists(path):
            self.send_error(404)
            return

        with open(path, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()


def run():
    server = http.server.HTTPServer(("0.0.0.0", 80), Handler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    #TODO: change, local host for now
    print("HTTP server running at http://localhost/")
    server.serve_forever()

if __name__ == "__main__":
    run()
