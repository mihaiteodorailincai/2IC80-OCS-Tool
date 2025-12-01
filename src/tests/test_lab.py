# src/tests/test_lab.py
from src.core.network import ping

def test_vms():
    assert ping("10.0.0.10") == True  # Test Victim
    assert ping("10.0.0.1") == True   # Test Gateway
    assert ping("10.0.0.53") == True  # Test DNS
    assert ping("10.0.0.50") == True  # Test Attacker
    print("[INFO] All VMs are reachable.")
