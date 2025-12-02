from src.attacks.arp_spoofing import start_arp_spoof
from src.attacks.dns_spoofing import DnsSpoofingAttack
from src.attacks.ssl_strip import start_sslstrip

from .config import load_config
from .network import check_lab_reachability, ping

""" src/core/mitm_pipeline.py: Module for managing MITM attack pipelines.
    Provides functions to set up, monitor, and tear down MITM attack pipelines. """

def start_arp_mitm(target_ip: str, gateway_ip: str):
    # Placeholder for starting ARP MITM attack
    # Import from attacks.arp_spoof
    
    # Call the ARP spoofing attack (non existing for now)
    start_arp_spoof(target_ip, gateway_ip)

    # Test connectivity after attack
    if ping(target_ip):
        print(f"[INFO] Victim {target_ip} is reachable after ARP spoof.")
    else:
        print(f"[ERROR] Victim {target_ip} is NOT reachable after ARP spoof.")

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

def run(mode: str):
    """ Run the MITM pipeline based on the specified mode. """
    reachability = check_lab_reachability()
    if not all(reachability.values()):
        print("One or more lab components are unreachable:")
        for role, reachable in reachability.items():
            if not reachable:
                print(f" - {role} is unreachable")
        return

    if mode == "arp":
        start_arp_mitm()
    elif mode == "dns":
        dns_spoof()
    elif mode == "ssl":
        start_ssl_strip()
    else:
        print(f"Unknown mode: {mode}")
