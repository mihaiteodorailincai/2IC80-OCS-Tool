<<<<<<< HEAD
from src.attacks.arp_spoofing import start_arp_spoof
from src.attacks.dns_spoofing import start_dns_spoof
from src.attacks.ssl_strip import start_sslstrip

from .config import load_config
from .network import check_lab_reachability, ping
=======
from .config import load_config
from .network import check_lab_reachability
>>>>>>> c07821dcd0f9f7e0c6dc9cf061b1c0b9309775a6

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

def start_dns_spoof(domain: str, fake_ip: str):
    # Placeholder for starting DNS spoofing attack
    # Import from attacks.dns_spoof
    print(f"[INFO] Starting DNS spoof for {domain} to {fake_ip}...")
    
    # Call the DNS spoofing attack (stubbed function for now)
    start_dns_spoof(domain, fake_ip)

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
        start_dns_spoof()
    elif mode == "ssl":
        start_ssl_strip()
    else:
        print(f"Unknown mode: {mode}")
