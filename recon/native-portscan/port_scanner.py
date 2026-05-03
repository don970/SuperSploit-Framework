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

# Load database directly
try:
    with open(path_to_database) as f:
        db = json.load(f)
except FileNotFoundError:
    db = {}

class AsyncPortScanner:
    """
    Asynchronous port scanner utilizing Python's asyncio event loop.
    Handles concurrent connections and passive/active banner grabbing.
    """
    def __init__(self, target: str, ports: list, timeout: float = 1.5, max_concurrency: int = 500):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        # Semaphore prevents "Too many open files" OS-level crashes
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.open_ports = []

    async def grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> str:
        """Attempts to read the service banner. Sends a probe for HTTP services."""
        banner = ""
        try:
            # Send a generic probe for web ports to trigger an immediate response
            if port in [80, 443, 8080, 8443]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
            
            # Wait for data to arrive on the socket
            data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            if data:
                # Decode, ignoring strict errors since some services send raw bytes
                banner = data.decode('utf-8', errors='ignore').strip()
                # Clean up newlines for a cleaner console output
                banner = banner.replace('\r', '').replace('\n', ' ')
        except Exception:
            pass
        finally:
            # Always cleanly close the socket
            writer.close()
            await writer.wait_closed()
            
        return banner

    async def scan_port(self, port: int):
        """Attempts an async connection to the port. If successful, initiates banner grab."""
        async with self.semaphore:
            try:
                # Attempt non-blocking connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port), 
                    timeout=self.timeout
                )
                
                # If we get here, the TCP handshake succeeded (Port is OPEN)
                banner = await self.grab_banner(reader, writer, port)
                
                self.open_ports.append({"port": port, "banner": banner})
                
                # Print results to the console dynamically as they are found
                banner_disp = f" | Banner: {banner[:50]}..." if banner else ""
                print(f"[+] Port {port:<5} is OPEN{banner_disp}")
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # Port is closed, filtered, or unreachable
                pass

    async def run_scan(self):
        """Gathers and executes all port scanning tasks concurrently."""
        print(f"[*] Starting Async Port Scan on {self.target} ({len(self.ports)} ports)")
        print("[*] Concurrency Limit: 500 tasks | Timeout: 1.5s\n")
        
        # Create a task for every port
        tasks = [self.scan_port(port) for port in self.ports]
        
        # Execute all tasks concurrently on the event loop
        await asyncio.gather(*tasks)
        
        return sorted(self.open_ports, key=lambda x: x["port"])

class Start:
    def __init__(self, args=None):
        raw_target = str(db.get("R_HOST", ""))
        if "://" in raw_target:
            target_ip = urlparse(raw_target).hostname
        else:
            target_ip = raw_target.split(":")[0]
            
        if not target_ip:
            print("[-] No valid R_HOST set in the database.")
            return

        # Scan the standard well-known ports (1-1024)
        ports_to_scan = list(range(1, 1025))
        
        scanner = AsyncPortScanner(target_ip, ports_to_scan)
        
        # Enter the asyncio event loop
        results = asyncio.run(scanner.run_scan())
        
        print(f"\n[+] Scan Complete. Found {len(results)} open ports.")

#!#!#!
name: "Async Port Scanner"
category: "Scanner"
desc: """Performs hyper-fast concurrent network mapping and banner grabbing.
Utilizes Python's asyncio event loop to bypass threading limits and scan hundreds 
of ports simultaneously."""
author: "Donald Ford"
#!#!#!