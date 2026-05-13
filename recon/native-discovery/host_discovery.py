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

# Suppress Scapy's default routing warnings for cleaner console output
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class HostDiscoveryEngine:
    """
    A modular host discovery engine designed for SuperSploit.
    Utilizes raw sockets to craft and fire off custom ARP and ICMP packets across CIDR ranges.
    
    By operating at the raw socket level with Scapy, this engine completely bypasses the 
    need for external binaries like Nmap, while simultaneously dodging standard OS-level 
    socket restrictions to allow for high-speed packet injection.
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
        Operates directly on the Data Link Layer (OSI Layer 2) using the Address Resolution Protocol.
        
        Why ARP?
        ARP requests ask "Who has this IP?" by broadcasting a frame to the FF:FF:FF:FF:FF:FF MAC address.
        Because this happens below the IP routing layer (Layer 3), local host firewalls (like Windows Defender) 
        typically do not block it. It is extremely fast and accurate, but it ONLY works on the local subnet.
        """
        self.logger.info(f"Initiating Layer 2 (ARP) sweep against {target_cidr}...")
        live_hosts = []
        try:
            # Craft the packet: Ethernet broadcast destination + ARP request.
            # Scapy automatically expands the target_cidr (e.g. 192.168.1.0/24) into individual IP addresses.
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_cidr)
            
            # srp (Send and Receive at Layer 2). 
            # Timeout dictates how long we wait for straggling responses after all packets are fired.
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
        Operates on the Network Layer (OSI Layer 3) using Internet Control Message Protocol (ICMP).
        
        This is essentially a standard 'ping' sweep. While it is highly likely to be dropped by 
        modern host-based firewalls, it is strictly necessary if we are scanning routable IPs 
        outside of our local subnet (since ARP cannot cross routers).
        """
        self.logger.info(f"Initiating Layer 3 (ICMP) sweep against {target_cidr}...")
        live_hosts = []
        try:
            # Craft the packet: The IP layer encapsulates an empty ICMP Echo Request.
            packet = IP(dst=target_cidr) / ICMP()
            
            # sr (Send and Receive at Layer 3). Notice we don't need the Ethernet layer here.
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
        # Load database dynamically upon execution to avoid stale memory cache
        try:
            with open(path_to_database) as f:
                db = json.load(f)
        except FileNotFoundError:
            db = {}
            
        # Fetch the target IP or Subnet from the SuperSploit database.
        # This value was previously set by the user (e.g., `set R_HOST 192.168.1.0/24`).
        target_cidr = str(db.get("R_HOST", ""))
        
        if not target_cidr:
            print("[-] No valid R_HOST set. Please set R_HOST to a valid IP or CIDR (e.g., 192.168.1.0/24).")
            return

        engine = HostDiscoveryEngine(debug_mode=True)
        print(f"[*] Starting Native Host Discovery on {target_cidr}")

        # Execute Both Sweeps Sequentially
        # 1. ARP catches completely stealthy local machines that drop ICMP.
        # 2. ICMP catches segmented/routed machines outside of the local switch.
        arp_results = engine.arp_sweep(target_cidr)
        icmp_results = engine.icmp_sweep(target_cidr)

        # Merge results into a deduplicated dictionary.
        # We prioritize ARP data over ICMP because ARP physically provides the remote host's MAC address.
        discovered = {host['ip']: host for host in arp_results}
        for host in icmp_results:
            if host['ip'] not in discovered:
                discovered[host['ip']] = host

        print(f"\n[+] Discovery Complete. Found {len(discovered)} active hosts.")
        
        target_updates = {}
        for ip, data in sorted(discovered.items(), key=lambda x: ipaddress.IPv4Address(x[0])):
            mac_str = f" [{data['mac']}]" if data['mac'] != "Unknown (Routed)" else ""
            print(f"    - {ip}{mac_str} (via {data['protocol']})")
            target_updates[ip] = {"mac": data["mac"], "status": "up"}

        # Target Database Persistence
        # Automatically saves newly discovered live hosts to targets.json.
        # This allows the user to immediately run `use target <index>` to begin exploiting them.
        if target_updates:
            print(f"[*] Saving {len(target_updates)} hosts to the targets database...")
            try:
                # Attempt to use the in-memory state manager if running within SuperSploit
                try:
                    print("[*] Using the in-memory state manager to find dictionary")
                    import sys
                    # Dynamically resolve the source directory relative to this script's location
                    current_dir = os.path.dirname(os.path.abspath(__file__))
                    source_dir = os.path.abspath(os.path.join(current_dir, "..", "..", "source"))
                    if source_dir not in sys.path:
                        sys.path.append(source_dir)
                    from core.database import DatabaseManagment
                    has_db_manager = True
                except ImportError:
                    print("[!] Are you running this as a standalone no database found.")
                    has_db_manager = False

                if has_db_manager:
                    existing_targets = DatabaseManagment.getTargets()
                else:
                    existing_targets = {}
                    if os.path.exists(path_to_targets_db):
                        with open(path_to_targets_db, "r") as f:
                            try:
                                existing_targets = json.load(f).get("TARGETS", {})
                            except json.JSONDecodeError:
                                pass

                # Safely merge discovered hosts without overwriting existing data (like open ports)
                for ip, info in target_updates.items():
                    if ip not in existing_targets or not isinstance(existing_targets[ip], dict):
                        existing_targets[ip] = info
                    else:
                        existing_targets[ip].update(info)
                
                if has_db_manager:
                    DatabaseManagment.updateTargets(existing_targets)
                    DatabaseManagment.sync_targets_to_disk()
                else:
                    with open(path_to_targets_db, "w") as f:
                        json.dump({"TARGETS": existing_targets}, f, sort_keys=True, indent=4)
                print("[+] Database updated successfully.")
            except Exception as e:
                print(f"[-] Failed to update database: {e}")

if __name__ == "__main__":
    Start()

#!#!#!
root: "true"
name: "Native Network Discovery"
category: "Discovery"
desc: """Performs blazing fast host discovery utilizing raw sockets. 
Fires asynchronous Layer 2 (ARP) and Layer 3 (ICMP) ping sweeps across a CIDR block, 
completely eliminating the need for Nmap -sn."""
author: "Donald Ford"
#!#!#!