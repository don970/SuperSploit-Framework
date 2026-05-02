"""
Native TCP Port Scanner Module
Provides fast, concurrent port scanning without external dependencies.
"""

import socket
import concurrent.futures
from typing import List, Tuple
import json
import os


class PortScanner:
    """
    A fast, native Python TCP port scanner utilizing ThreadPoolExecutor.
    Ideal for replacing external dependencies like Nmap for basic reconnaissance.
    """

    # A predefined list of common ports for rapid scanning
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    ]

    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        """
        Initializes the PortScanner.
        
        :param timeout: Time in seconds before giving up on a connection.
        :param max_workers: Maximum number of concurrent threads to use.
        """
        self.timeout = timeout
        self.max_workers = max_workers

    def _scan_single_port(self, ip: str, port: int) -> Tuple[int, bool]:
        """
        Attempts to connect to a specific TCP port on the target IP.
        
        :param ip: Target IP address.
        :param port: Target port number.
        :return: A tuple containing the port number and a boolean indicating if it's open.
        """
        try:
            # Use IPv4 (AF_INET) and TCP (SOCK_STREAM)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                # connect_ex returns 0 if the connection was successful
                result = sock.connect_ex((ip, port))
                return port, (result == 0)
        except Exception:
            # Catching general exceptions (e.g., socket creation errors, routing issues)
            return port, False

    def scan_target(self, ip: str, ports: List[int] = None) -> List[int]:
        """
        Scans a list of ports concurrently on the specified IP.
        
        :param ip: Target IP address to scan.
        :param ports: List of ports to scan. Defaults to COMMON_PORTS if None.
        :return: A sorted list of open ports.
        """
        if ports is None:
            ports = self.COMMON_PORTS
            
        open_ports = []
        
        # ThreadPoolExecutor manages a pool of threads for concurrent execution
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Map the target IP and ports to the thread pool
            future_to_port = {
                executor.submit(self._scan_single_port, ip, port): port 
                for port in ports
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    
        return sorted(open_ports)


class Start:
    def __init__(self):
        install_location = f'{os.getenv("HOME")}/.SuperSploit'
        # Absolute path to the main configuration/session JSON database
        path_to_database = f"{install_location}/.data/.config/data.json"

        # load database directly
        with open(path_to_database) as f:
            db = json.load(f)

        # Example Usage / CLI Runner
        target_ip = db["R_HOST"]
        scanner = PortScanner(timeout=0.5, max_workers=50)

        print(f"[*] Starting native scan on {target_ip}...")
        results = scanner.scan_target(target_ip)

        print(f"[*] Scan complete.")
        if results:
            print(f"[+] Open ports found: {results}")
        else:
            print("[-] No open ports found.")