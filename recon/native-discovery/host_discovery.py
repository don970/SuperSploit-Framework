"""
Native Host Discovery Engine
Replaces Nmap's `-sn` functionality using raw sockets via Scapy.
Implements Layer 2 (ARP) for local subnets and Layer 3 (ICMP) for remote networks.
"""

import json
import logging
import uuid
import os
import ipaddress
from scapy.all import IP, ICMP, Ether, ARP, srp, sr, conf
from scapy.error import Scapy_Exception

install_location = f'{os.getenv("HOME")}/.SuperSploit'
path_to_database = f"{install_location}/.data/.config/data.json"
path_to_targets_db = f"{install_location}/.data/.config/targets.json"

# Load database directly
try:
    with open(path_to_database) as f:
        db = json.load(f)
except FileNotFoundError:
    db = {}

# Suppress Scapy's default routing warnings for cleaner console output
conf.verb = 0

class HostDiscoveryEngine:
    """
    A modular host discovery engine designed for SuperSploit.
    Utilizes raw sockets to fire off concurrent ARP and ICMP packets across CIDR ranges.
    """
    def __init__(self, session_id: str | None = None, debug_mode: bool = False):
        self.session_id = session_id or str(uuid.uuid4())
        self.logger = self._setup_logger(debug_mode)

    def _setup_logger(self, debug_mode: bool) -> logging.Logger:
        """Initializes a framework-compliant logging system with session tracking."""
        logger = logging.getLogger(f"DiscoveryEngine_{self.session_id}")
        logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                f'%(asctime)s - [Session: {self.session_id}] - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger

    def arp_sweep(self, target_cidr: str) -> list[dict]:
        """
        Layer 2 Host Discovery.
        Extremely fast and bypasses local OS firewalls. Only works on the local subnet.
        """
        self.logger.info(f"Initiating Layer 2 (ARP) sweep against {target_cidr}...")
        live_hosts = []
        try:
            # Craft Ethernet broadcast + ARP request for the entire CIDR
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_cidr)
            
            # srp (send and receive at Layer 2)
            ans, unans = srp(packet, timeout=2, retry=1)
            
            for snd, rcv in ans:
                live_hosts.append({
                    "ip": rcv.psrc,
                    "mac": rcv.hwsrc,
                    "protocol": "ARP"
                })
                self.logger.debug(f"Host up (ARP): {rcv.psrc} - {rcv.hwsrc}")
                
        except (PermissionError, Scapy_Exception):
            self.logger.error("Permission denied: Raw socket (L2) access requires root privileges. Run with sudo.")
        except Exception as e:
            self.logger.error(f"ARP sweep error: {e}")
            
        return live_hosts

    def icmp_sweep(self, target_cidr: str) -> list[dict]:
        """
        Layer 3 Host Discovery.
        Standard 'ping' sweep. Required if scanning routable IPs outside the local subnet.
        """
        self.logger.info(f"Initiating Layer 3 (ICMP) sweep against {target_cidr}...")
        live_hosts = []
        try:
            # IP layer automatically parses CIDR strings in Scapy
            packet = IP(dst=target_cidr) / ICMP()
            
            # sr (send and receive at Layer 3)
            ans, unans = sr(packet, timeout=2, retry=1)
            
            for snd, rcv in ans:
                live_hosts.append({
                    "ip": rcv.src,
                    "mac": "Unknown (Routed)",
                    "protocol": "ICMP"
                })
                self.logger.debug(f"Host up (ICMP): {rcv.src}")
                
        except (PermissionError, Scapy_Exception):
            self.logger.error("Permission denied: Raw socket (L3) access requires root privileges. Run with sudo.")
        except Exception as e:
            self.logger.error(f"ICMP sweep error: {e}")
            
        return live_hosts


class Start:
    def __init__(self):
        # Fetch the target from the database (e.g., 192.168.1.0/24)
        target_cidr = str(db.get("R_HOST", ""))
        
        if not target_cidr:
            print("[-] No valid R_HOST set. Please set R_HOST to a valid IP or CIDR (e.g., 192.168.1.0/24).")
            return

        engine = HostDiscoveryEngine(debug_mode=True)
        print(f"[*] Starting Native Host Discovery on {target_cidr}")

        # Execute Both Sweeps
        # ARP will catch local machines even if they block ICMP (like Windows Defender)
        # ICMP will catch everything else across routers
        arp_results = engine.arp_sweep(target_cidr)
        icmp_results = engine.icmp_sweep(target_cidr)

        # Merge results, prioritizing ARP data (since it contains MAC addresses)
        discovered = {host['ip']: host for host in arp_results}
        for host in icmp_results:
            if host['ip'] not in discovered:
                discovered[host['ip']] = host

        print(f"\n[+] Discovery Complete. Found {len(discovered)} active hosts.")
        
        target_updates = {}
        for ip, data in sorted(discovered.items(), key=lambda x: ipaddress.IPv4Address(x[0])):
            mac_str = f" [{data['mac']}]" if data['mac'] != "Unknown (Routed)" else ""
            print(f"    - {ip}{mac_str} (via {data['protocol']})")
            target_updates[ip] = "N/A"

        # Save discovered hosts to the central database
        if target_updates:
            print(f"[*] Saving {len(target_updates)} hosts to the targets database...")
            try:
                current_db = {"TARGETS": {}}
                # Load existing targets DB or create new
                if os.path.exists(path_to_targets_db):
                    with open(path_to_targets_db, "r") as f:
                        try:
                            current_db = json.load(f)
                        except json.JSONDecodeError:
                            pass
                    
                existing_targets = current_db.get("TARGETS", {})
                existing_targets.update(target_updates)
                current_db["TARGETS"] = existing_targets
                
                with open(path_to_targets_db, "w") as f:
                    json.dump(current_db, f, sort_keys=True, indent=4)
                print("[+] Database updated successfully.")
            except Exception as e:
                print(f"[-] Failed to update database: {e}")

#!#!#!
name: "Native Network Discovery"
category: "Discovery"
desc: """Performs blazing fast host discovery utilizing raw sockets. 
Fires asynchronous Layer 2 (ARP) and Layer 3 (ICMP) ping sweeps across a CIDR block, 
completely eliminating the need for Nmap -sn."""
author: "Donald Ford"
#!#!#!