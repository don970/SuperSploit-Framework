"""
This is a modular engine designed for integration into SuperSploit's
reconnaissance Framework. It performs active OS fingerprinting by sending 
crafted TCP probes to target hosts analyzing TCP SYN/ACK responses against 
a centralized online signature database. It includes session tracking, detailed 
logging, and a heuristic matching algorithm for accurate OS identification. 


It still need to be able to read targets from the cached database and run 
against them, and also needs to be able to update the database with new 
signatures. along with fuzzy searching and weightings for more accurate 
matching. also this is the para link for nmaps os db 
https://github.com/nmap/nmap/blob/4085d78e3dddf96719b4b7569a450a14c894e93a/nmap-os-db
"""


import json
import logging
import requests
import uuid
import os
from urllib.parse import urlparse
from scapy.all import IP, TCP, sr1, conf
from scapy.error import Scapy_Exception

install_location = f'{os.getenv("HOME")}/.SuperSploit'
# Absolute path to the main configuration/session JSON database
path_to_database = f"{install_location}/.data/.config/data.json"

# Suppress Scapy's default routing warnings for cleaner console output
conf.verb = 0

class NmapProbeCrafter:
    def __init__(self, target_ip, open_port, closed_port):
        self.target_ip = target_ip
        self.open_port = open_port
        self.closed_port = closed_port

    def probe_t1(self):
        """
        T1: Sends a SYN packet with a specific window size and a full
        suite of TCP options to an OPEN port.
        """
        pkt = IP(dst=self.target_ip) / TCP(
            dport=self.open_port,
            flags="S",
            window=32768,
            options=[
                ('WScale', 10),
                ('NOP', None),
                ('MSS', 1460),
                ('Timestamp', (0xFFFFFFFF, 0)),
                ('SAckOK', '')
            ]
        )
        return sr1(pkt, timeout=2, verbose=0)

    def probe_t2(self):
        """
        T2: Sends a NULL packet (no flags) with the Don't Fragment (DF)
        bit set to an OPEN port.
        """
        pkt = IP(dst=self.target_ip, flags="DF") / TCP(
            dport=self.open_port,
            flags="",  # NULL
            window=128
        )
        return sr1(pkt, timeout=2, verbose=0)

    def probe_t5(self):
        """
        T5: Sends a SYN packet to a CLOSED port to analyze the RST response.
        """
        pkt = IP(dst=self.target_ip) / TCP(
            dport=self.closed_port,
            flags="S",
            window=31337
        )
        return sr1(pkt, timeout=2, verbose=0)


def parse_nmap_options(tcp_layer):
    """
    Translates Scapy's TCP options list into Nmap's 'O' string format.
    Example output: 'M5B4NW0NNT11S'
    """
    if not tcp_layer.options:
        return ""

    nmap_opt_string = ""

    for opt in tcp_layer.options:
        name = opt[0]
        val = opt[1] if len(opt) > 1 else None

        if name == 'MSS':
            # Nmap expects 'M' followed by the MSS value in Hex
            nmap_opt_string += f"M{val:X}"
        elif name == 'WScale':
            # Nmap expects 'W' followed by the scale value
            nmap_opt_string += f"W{val}"
        elif name == 'NOP':
            # Nmap expects 'N'
            nmap_opt_string += "N"
        elif name == 'SAckOK':
            # Nmap expects 'S'
            nmap_opt_string += "S"
        elif name == 'Timestamp':
            # Nmap expects 'T' followed by 0 or 1 for the two timestamp values
            ts_val, ts_ecr = val
            v1 = "1" if ts_val != 0 else "0"
            v2 = "1" if ts_ecr != 0 else "0"
            nmap_opt_string += f"T{v1}{v2}"

    return nmap_opt_string


# --- Example Usage ---
# response = crafter.probe_t1()
# if response and response.haslayer(TCP):
#     nmap_o_string = parse_nmap_options(response.getlayer(TCP))
#     print(f"TCP Options formatted for Nmap DB: {nmap_o_string}")

class OSFingerprintEngine:
    """
    A modular OS fingerprinting engine designed for integration into security frameworks.
    Analyzes TCP SYN/ACK responses against a centralized online signature database.
    """
    def __init__(self, db_endpoint: str, session_id: str | None = None, debug_mode: bool = False):
        self.db_endpoint = db_endpoint
        self.session_id = session_id or str(uuid.uuid4())
        self.logger = self._setup_logger(debug_mode)
        self.signatures = self._fetch_online_signatures()

    def _setup_logger(self, debug_mode: bool) -> logging.Logger:
        """Initializes a framework-compliant logging system with session tracking."""
        logger = logging.getLogger(f"FPEngine_{self.session_id}")
        logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
        
        # Prevent duplicate handlers if the engine is re-instantiated
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                f'%(asctime)s - [Session: {self.session_id}] - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger

    def _fetch_online_signatures(self) -> dict:
        """Fetches the latest OS fingerprint definitions from a remote API."""
        self.logger.info(f"Fetching OS signature database from: {self.db_endpoint}")
        try:
            # In a production environment, this queries your centralized API:
            #response = requests.get(self.db_endpoint, timeout=10)
            #response.raise_for_status()
            #input(response.json())
            #return response.json()
            #Simulated JSON response for demonstration purposes
            return {
                "Linux 3.x/4.x": {"base_ttl": 64, "window": 5840, "mss": 1460},
                "Windows 10/11": {"base_ttl": 128, "window": 8192, "mss": 1460},
                "FreeBSD 12.x": {"base_ttl": 64, "window": 65535, "mss": 1460},
                "Cisco IOS": {"base_ttl": 255, "window": 4128, "mss": 536},
                "linux_router/gateway": {'received_ttl': 64, 'base_ttl': 64, 'window': 64240, 'mss': 1460}
            }
        except requests.RequestException as e:
            self.logger.error(f"Failed to retrieve online database: {e}")
            return {}

    def _guess_base_ttl(self, received_ttl: int) -> int:
        """
        Estimates the initial TTL before network hops decremented it.
        Common starting TTLs are 64 (Linux), 128 (Windows), and 255 (Cisco/Solaris).
        """   
        for base in [64, 128, 255]:
            if received_ttl <= base:
                return base
        return received_ttl

    def execute_probe(self, target_ip: str, port: int) -> dict | None:
        """Sends a crafted TCP SYN packet and records the response characteristics."""
        self.logger.info(f"Initiating active probe against {target_ip}:{port}")
        
        try:
            # Craft a TCP SYN packet
            probe_pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
             
            # Send and wait for a single response
            resp = sr1(probe_pkt, timeout=3)
        except (PermissionError, Scapy_Exception):
            self.logger.error("Permission denied: Raw socket access requires root privileges. Please run SuperSploit with sudo.")
            return None
        except Exception as e:
            self.logger.error(f"Network error during probe execution: {e}")
            return None

        if resp is None:
            self.logger.warning(f"Timeout: No response from {target_ip}:{port}")
            return None

        # Check if the response is a TCP SYN/ACK (0x12)
        if resp.haslayer(TCP) and resp.getlayer(TCP).flags & 0x12: 
            ip_layer = resp.getlayer(IP)
            tcp_layer = resp.getlayer(TCP)
            
            # Parse all TCP options dynamically
            tcp_options_dict = {}
            tcp_options_order = []
            for opt in tcp_layer.options:
                opt_name = opt[0]
                opt_val = opt[1] if len(opt) > 1 else None
                
                tcp_options_order.append(opt_name)
                
                # Handle options with no specific value (like SAckOK)
                if opt_val == '' or opt_val is None:
                    tcp_options_dict[opt_name] = True
                else:
                    tcp_options_dict[opt_name] = opt_val

            fingerprint = {
                # Standard Core Fields
                "received_ttl": ip_layer.ttl,
                "base_ttl": self._guess_base_ttl(ip_layer.ttl),
                "window": tcp_layer.window,
                "mss": tcp_options_dict.get('MSS', None),
                
                # Extended IP Characteristics
                "ip_layer": {
                    "version": ip_layer.version,
                    "ihl": ip_layer.ihl,            # Internet Header Length
                    "tos": ip_layer.tos,            # Type of Service
                    "len": ip_layer.len,            # Total Length
                    "id": ip_layer.id,              # Identification
                    "flags": str(ip_layer.flags),   # e.g., 'DF' (Don't Fragment)
                    "frag": ip_layer.frag,          # Fragment Offset
                    "chksum": ip_layer.chksum,      # IP Checksum
                },
                
                # Extended TCP Characteristics
                "tcp_layer": {
                    "seq": tcp_layer.seq,           # Sequence Number
                    "ack": tcp_layer.ack,           # Acknowledgment Number
                    "dataofs": tcp_layer.dataofs,   # Data Offset
                    "reserved": tcp_layer.reserved, # Reserved bits
                    "flags": str(tcp_layer.flags),  # e.g., 'SA' (SYN/ACK)
                    "urgptr": tcp_layer.urgptr,     # Urgent Pointer
                    "chksum": tcp_layer.chksum,     # TCP Checksum
                    "options_order": tcp_options_order, # Order of options is a key OS identifier
                    "options_parsed": tcp_options_dict
                }
            }
            
            self.logger.debug(f"Captured network fingerprint: {fingerprint}")
            return fingerprint
            
        self.logger.warning("Target responded, but not with a TCP SYN/ACK.")
        return None

    def identify_os(self, target_ip: str, port: int = 80) -> str:
        """Matches the target's network response against the online database."""
        if not self.signatures:
            return "Engine error: Signature database is empty or unreachable."

        fp = self.execute_probe(target_ip, port)
        if not fp:
            return "Identification failed: No valid fingerprint extracted."

        self.logger.info("Analyzing fingerprint against signature database...")
        
        # Heuristic matching logic
        # A highly accurate engine would use fuzzy logic and weightings here
        for os_name, sig in self.signatures.items():
            if sig["base_ttl"] == fp["base_ttl"] and sig["window"] == fp["window"]:
                return f"Match Found: {os_name}"
        
        return f"Unknown OS (Unmatched Fingerprint: TTL={fp['base_ttl']}, Win={fp['window']})"



class Start:

    def __init__(self):
        # Example Framework Execution Workflow
        ENGINE_API_URL = "https://api.threat-intelligence.local/v1/os-signatures"
        
        try:
            import sys
            current_dir = os.path.dirname(os.path.abspath(__file__))
            source_dir = os.path.abspath(os.path.join(current_dir, "..", "..", "source"))
            if source_dir not in sys.path:
                sys.path.append(source_dir)
            from core.database import DatabaseManagment
            db = DatabaseManagment.get()
        except ImportError:
            db = {}
            
        # Clean up the target IP in case it was stored as a URL or includes a port
        raw_target = str(db.get("R_HOST", ""))
        if "://" in raw_target:
            TARGET_IP = urlparse(raw_target).hostname
        else:
            TARGET_IP = raw_target.split(":")[0]
            
        if not TARGET_IP:
            print("[-] No valid R_HOST set in the database.")
            return

        raw_port = db.get("R_PORT", "80")
        try:
            target_port = int(raw_port)
        except ValueError:
            print(f"[-] Invalid R_PORT '{raw_port}', defaulting to 80.")
            target_port = 80

        # Initialize the engine handler with debugging toggled on
        os_engine = OSFingerprintEngine(
            db_endpoint=ENGINE_API_URL,
            debug_mode=True
        )

        # Execute the module
        result = os_engine.identify_os(TARGET_IP, port=target_port)
        print(f"\n[+] Final Result: {result}")


#!#!#!
name: "Native python OS fingerprint service"
category: "FingerPrinter"
desc: """This is a modular engine designed for integration into SuperSploit's 
reconnaissance Framework. It performs active OS fingerprinting by sending 
crafted TCP probes to target hosts analyzing TCP SYN/ACK responses against 
a centralized online signature database. It includes session tracking, detailed 
logging, and a heuristic matching algorithm for accurate OS identification. 
"""
author: "Donald Ford"
#!#!#!
