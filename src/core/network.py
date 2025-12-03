import subprocess
import os
from .config import load_config
from scapy.all import srp, Ether, ARP




""" src/core/network.py: Module for network-related operations.
    Provides basic utilities (functions) everyone can reuse: ping, interface info, etc."""

def ping(ip: str, count: int = 1) -> bool:
    result = subprocess.run(
        ["ping", "-c", str(count), ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0

# Check that the virtual network is reachable by the attacking tool
# Attack module assume victim VM, gateway VM, and DNS seever VM are reachable
# If one is dead/misconfigured, the attack will fail.
def check_lab_reachability():
    config = load_config()
    reachable_hosts = {}

    for role in ("victim", "gateway", "dns"):
        ip = config[role]["ip"]
        reachable_hosts[role] = ping(ip)
    return reachable_hosts

def enable_ip_forwarding() -> bool:
    """Enables IP forwarding on the system. Returns True on success."""
    if os.name != 'posix':
        print("[WARNING] IP forwarding setup is only supported on POSIX systems.")
        return False
        
    print("[INFO] Enabling IP forwarding...")
    try: 
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
        print("[INFO] IP forwarding enabled.")
        return True
    except Exception as e:
        print(f"[ERROR] Could not enable IP forwarding: {e}")
        return False
    
def get_mac_for_ip(ip_address: str, interface: str = None) -> str | None:
    """Uses Scapy to dynamically resolve the MAC address for a given IP."""
    try:
        arp_request = ARP(pdst=ip_address)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")/arp_request
        answered, _ = srp(ether_frame, timeout=1, verbose=False, iface=interface)
        
        if answered:
            return answered[0][1].hwsrc
        else:
            print(f"[WARNING] Could not resolve MAC for IP: {ip_address}")
            return None

    except Exception as e:
        print(f"[ERROR] MAC resolution failed for {ip_address}. Is Scapy installed and running as root/sudo?: {e}")
        return None

    