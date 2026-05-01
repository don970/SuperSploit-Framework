"""This is a modular engine designed for integration into SuperSploit's 
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

import logging
import requests
import uuid
from scapy.all import IP, TCP, sr1, conf

# Suppress Scapy's default routing warnings for cleaner console output
conf.verb = 0 

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
            # response = requests.get(self.db_endpoint, timeout=10)
            # response.raise_for_status()
            # return response.json()
            # Simulated JSON response for demonstration purposes
            return {
                "Linux 3.x/4.x": {"base_ttl": 64, "window": 5840, "mss": 1460},
                "Windows 10/11": {"base_ttl": 128, "window": 8192, "mss": 1460},
                "FreeBSD 12.x": {"base_ttl": 64, "window": 65535, "mss": 1460},
                "Cisco IOS": {"base_ttl": 255, "window": 4128, "mss": 536}
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
        
        # Craft a TCP SYN packet
        probe_pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
         
        # Send and wait for a single response
        resp = sr1(probe_pkt, timeout=3)

        if resp is None:
            self.logger.warning(f"Timeout: No response from {target_ip}:{port}")
            return None

        # Check if the response is a TCP SYN/ACK (0x12)
        if resp.haslayer(TCP) and resp.getlayer(TCP).flags & 0x12: 
            ip_layer = resp.getlayer(IP)
            tcp_layer = resp.getlayer(TCP)
            
            # Extract Maximum Segment Size (MSS) from TCP options
            mss = None
            for opt in tcp_layer.options:
                if opt[0] == 'MSS':
                    mss = opt[1]

            fingerprint = {
                "received_ttl": ip_layer.ttl,
                "base_ttl": self._guess_base_ttl(ip_layer.ttl),
                "window": tcp_layer.window,
                "mss": mss
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

if __name__ == "__main__":
    # Example Framework Execution Workflow
    ENGINE_API_URL = "https://api.threat-intelligence.local/v1/os-signatures"
    TARGET_IP = "192.168.1.1" # Replace with a valid target
    
    # Initialize the engine handler with debugging toggled on
    os_engine = OSFingerprintEngine(
        db_endpoint=ENGINE_API_URL, 
        debug_mode=True
    )
    
    # Execute the module
    result = os_engine.identify_os(TARGET_IP, port=80)
    print(f"\n[+] Final Result: {result}")