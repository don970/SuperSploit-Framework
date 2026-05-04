"""
Native Async Port Scanner Engine
Replaces threaded scanning with asyncio for non-blocking, high-speed 
network mapping and banner grabbing.
"""

import asyncio
import json
import os
from urllib.parse import urlparse

install_location = f'{os.getenv("HOME")}/.SuperSploit'
path_to_database = f"{install_location}/.data/.config/data.json"
path_to_targets_db = f"{install_location}/.data/.config/targets.json"

class ServiceDetector:
    """
    Analyzes grabbed banners and port numbers to heuristically determine 
    the underlying network service running on an open port.
    """
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
        135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8000: "HTTP-ALT", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
    }

    @classmethod
    def detect(cls, port: int, banner: str) -> str:
        banner_upper = banner.upper()
        
        # 1. Signature-based detection (highest confidence)
        if "SSH-" in banner_upper:
            return "SSH"
        elif "HTTP/" in banner_upper or "HTML" in banner_upper:
            return "HTTP"
        elif "FTP" in banner_upper:
            return "FTP"
        elif "SMTP" in banner_upper or "POSTFIX" in banner_upper or "SENDMAIL" in banner_upper:
            return "SMTP"
        elif "MYSQL" in banner_upper or "MARIADB" in banner_upper:
            return "MySQL"
            
        # 2. Fallback to standard port mappings
        return cls.COMMON_PORTS.get(port, "Unknown")

class AsyncPortScanner:
    """
    Asynchronous port scanner utilizing Python's asyncio event loop.    
    Unlike traditional threaded scanners which suffer from high context-switching overhead, 
    this scanner leverages asynchronous I/O to handle thousands of concurrent TCP handshakes 
    in a single thread. This results in hyper-fast network mapping and banner grabbing.
    """
    def __init__(self, target: str, ports: list, timeout: float = 1.5, max_concurrency: int = 500):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        
        # asyncio.Semaphore acts as a concurrency throttle.
        # Operating Systems have strict limits on how many file descriptors (sockets) can be open at once (usually ~1024).
        # If we exceed this, the OS will violently terminate the script with a "Too many open files" error.
        # The Semaphore ensures we never have more than `max_concurrency` sockets open simultaneously.
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.open_ports = []

    async def grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> str:
        """
        Attempts to read the service banner data immediately after the TCP handshake.
        Some protocols (like SSH or FTP) passively send a welcome banner upon connection.
        Other protocols (like HTTP) wait for the client to send data first.
        """
        banner = ""
        try:
            # Active Probing: If the port is a standard web port, the server is waiting for an HTTP request.
            # We send a bare-minimum HTTP/1.0 HEAD request to violently provoke a response (e.g., "HTTP/1.1 200 OK...").
            if port in [80, 443, 8080, 8443]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
            
            # Passive Listening: Wait up to `self.timeout` seconds for data to arrive on the socket's read buffer.
            data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            if data:
                # Safely decode the payload, explicitly ignoring strict Unicode errors 
                # because some proprietary services (like SMB or RDP) send raw binary bytes.
                banner = data.decode('utf-8', errors='ignore').strip()
                # Clean up newlines for a cleaner console output
                banner = banner.replace('\r', '').replace('\n', ' ')
        except Exception:
            pass
        finally:
            # Socket Cleanup: Always close the writer and await its termination to free up the OS file descriptor.
            writer.close()
            await writer.wait_closed()
            
        return banner

    async def scan_port(self, port: int):
        """
        Attempts an asynchronous connection to a specific target port.
        If the TCP 3-way handshake succeeds, it immediately attempts to grab the service banner.
        """
        async with self.semaphore:
            try:
                # Attempt a non-blocking TCP connection.
                # Under the hood, this handles the SYN -> SYN-ACK -> ACK handshake.
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port), 
                    timeout=self.timeout
                )
                
                # If no exception was thrown by wait_for, the TCP handshake succeeded and the port is OPEN.
                banner = await self.grab_banner(reader, writer, port)
                service = ServiceDetector.detect(port, banner)
                
                self.open_ports.append({"port": port, "service": service, "banner": banner})
                
                # Print results to the console dynamically as they are found
                banner_disp = f" | Banner: {banner[:50]}..." if banner else ""
                print(f"[+] Port {port:<5} | {service:<10} | OPEN{banner_disp}")
                
            except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError, OSError):
                # Port is either closed (ConnectionRefusedError via RST packet), 
                # filtered by a firewall (TimeoutError via dropped packet), 
                # or fundamentally unreachable (OSError).
                # ConnectionResetError is added to gracefully handle TCP RSTs sent mid-connection.
                pass

    async def run_scan(self):
        """Constructs the event loop tasks and executes all port scanning coroutines concurrently."""
        print(f"[*] Starting Async Port Scan on {self.target} ({len(self.ports)} ports)")
        print("[*] Concurrency Limit: 500 tasks | Timeout: 1.5s\n")
        
        # Create an un-executed coroutine object for every port in our target list.
        tasks = [self.scan_port(port) for port in self.ports]
        
        # Inject all tasks into the event loop. asyncio.gather() will run them concurrently,
        # constrained only by our Semaphore limits.
        await asyncio.gather(*tasks)
        
        return sorted(self.open_ports, key=lambda x: x["port"])

class Start:
    def __init__(self, args=None):
        # Load the database dynamically upon execution.
        # This ensures we are always reading the latest user-set variables, avoiding stale memory cache bugs.
        try:
            with open(path_to_database) as f:
                db = json.load(f)
        except FileNotFoundError:
            db = {}
            
        # Target Sanitization:
        # Safely parse the database target, stripping out URI schemes (http://) and trailing ports.
        raw_target = str(db.get("R_HOST", ""))
        if "://" in raw_target:
            target_ip = urlparse(raw_target).hostname
        else:
            target_ip = raw_target.split(":")[0]
            
        if not target_ip:
            print("[-] No valid R_HOST set in the database.")
            return

        # Generate the target scope: Allow users to specify custom ports via the 'PORTS' variable.
        # Supports comma-separated lists and ranges (e.g., 80,443,8000-8080).
        raw_ports = str(db.get("PORTS", ""))
        ports_to_scan = []
        
        if raw_ports:
            for part in raw_ports.split(','):
                part = part.strip()
                if '-' in part:
                    try:
                        start, end = part.split('-', 1)
                        ports_to_scan.extend(range(int(start), int(end) + 1))
                    except ValueError:
                        continue
                elif part.isdigit():
                    ports_to_scan.append(int(part))
            ports_to_scan = sorted(list(set(ports_to_scan)))
        else:
            # Fallback to the standard, privileged well-known ports (1-1024) if no custom ports are defined.
            ports_to_scan = list(range(1, 1025))
        
        scanner = AsyncPortScanner(target_ip, ports_to_scan)
        
        # Start the asyncio event loop and block until all port scanning tasks are finalized.
        results = asyncio.run(scanner.run_scan())
        
        print(f"\n[+] Scan Complete. Found {len(results)} open ports.")
        
        # Target Database Persistence
        # If we found open ports, save the structured data to the global targets.json database.
        if results:
            print(f"[*] Saving port data for {target_ip} to the targets database...")
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
                
                # Fetch existing target data or initialize a new dictionary
                target_entry = existing_targets.get(target_ip, {})
                if not isinstance(target_entry, dict):
                    # Convert legacy string entries (like "N/A" from host discovery) into a structured dict
                    target_entry = {"status": target_entry}
                
                # Store the discovered ports and update the database
                target_entry["ports"] = results
                existing_targets[target_ip] = target_entry
                current_db["TARGETS"] = existing_targets
                
                with open(path_to_targets_db, "w") as f:
                    json.dump(current_db, f, sort_keys=True, indent=4)
                print("[+] Database updated successfully.")
            except Exception as e:
                print(f"[-] Failed to update database: {e}")

#!#!#!
name: "Async Port Scanner"
category: "Scanner"
desc: """Performs hyper-fast concurrent network mapping and banner grabbing.
Utilizes Python's asyncio event loop to bypass threading limits and scan hundreds 
of ports simultaneously."""
author: "Donald Ford"
#!#!#!