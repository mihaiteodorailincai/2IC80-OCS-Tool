import subprocess
from .config import load_config


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
    reachable_hosts = []

    for role in ("victim", "gateway", "dns"):
        ip = config[role]["ip"]
        reachable_hosts[role] = ping(ip)
    return reachable_hosts