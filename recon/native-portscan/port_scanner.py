"""
Native Async Port Scanner Engine
Replaces threaded scanning with asyncio for non-blocking, high-speed 
network mapping and banner grabbing.
"""

import asyncio
import json
import os
import platform
from urllib.parse import urlparse

# DEBUG TIP: Ensure 'HOME' is properly set in the environment. If running as a different user 
# (e.g., sudo without -E), os.getenv("HOME") might resolve to /root instead of the user's home.
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
            
        # DEBUG TIP: If a service isn't being identified accurately, it likely doesn't send a 
        # recognizable banner. It falls back to COMMON_PORTS mapping here.
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
        
        # Dynamically adjust max_concurrency based on OS limits
        actual_limit = max_concurrency
        if platform.system() != "Windows":
            import resource
            # Fetch the soft limit for maximum open file descriptors
            soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
            
            # Provide a safety buffer of 50 descriptors for the framework itself
            safe_limit = max(10, soft_limit - 50)
            actual_limit = min(max_concurrency, safe_limit)
            if actual_limit < max_concurrency:
                print(f"[*] OS File Descriptor limit detected. Scaling concurrency down to {actual_limit} tasks.")

        # asyncio.Semaphore acts as a concurrency throttle.
        # Operating Systems have strict limits on how many file descriptors (sockets) can be open at once (usually ~1024).
        # If we exceed this, the OS will violently terminate the script with a "Too many open files" error.
        # The Semaphore ensures we never have more than `max_concurrency` sockets open simultaneously.
        self.semaphore = asyncio.Semaphore(actual_limit)
        self.open_ports = []

    async def grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> str:
        """
        Attempts to read the service banner data immediately after the TCP handshake.
        Some protocols (like SSH or FTP) passively send a welcome banner upon connection.
        Other protocols (like HTTP) wait for the client to send data first.
        """
        banner = ""
        try:
            # DEBUG TIP: If web servers are returning blank banners, check if this HEAD request 
            # is being rejected because the server strictly requires HTTP/1.1 with a valid 'Host' header.
            # Active Probing: If the port is a standard web port, the server is waiting for an HTTP request.
            # We send a bare-minimum HTTP/1.0 HEAD request to violently provoke a response (e.g., "HTTP/1.1 200 OK...").
            if port in [80, 443, 8080, 8443]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
            
            # Passive Listening: Wait up to `self.timeout` seconds for data to arrive on the socket's read buffer.
            # DEBUG TIP: If banners are truncating or timing out consistently on slow networks, 
            # consider increasing `self.timeout`. `reader.read(1024)` pulls the first 1KB of data.
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
            # DEBUG TIP: Failure to close the writer results in File Descriptor leaks. 
            # If you hit an "OSError: [Errno 24] Too many open files" crash, check this block.
            # Socket Cleanup: Always close the writer and await its termination to free up the OS file descriptor.
            writer.close()
            await writer.wait_closed()
            
        return banner

    async def scan_port(self, port: int):
        """
        Attempts an asynchronous connection to a specific target port.
        If the TCP 3-way handshake succeeds, it immediately attempts to grab the service banner.
        """
        # async with self.semaphore: Acquires a lock. If `max_concurrency` (e.g., 500) tasks 
        # are already running, this execution pauses right here until a slot opens up.
        async with self.semaphore:
            try:
                # Attempt a non-blocking TCP connection.
                # Under the hood, this handles the SYN -> SYN-ACK -> ACK handshake.
                # DEBUG TIP: If `asyncio.open_connection` hangs indefinitely, ensure `self.timeout`
                # is correctly wrapping it via `asyncio.wait_for`.
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
                # DEBUG TIP: Diagnosing connection failures:
                # TimeoutError = The port is likely FILTERED by a firewall (packets silently dropped).
                # ConnectionRefusedError = The port is CLOSED (server sent a TCP RST packet in response).
                # ConnectionResetError = Connection started but was aborted mid-flight (often IPS/IDS interference).
                # OSError = Usually "No route to host" or local OS limits exhausted.
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
        # DEBUG TIP: If the scan crashes right at launch, the semaphore might be set too high 
        # for the local machine's `ulimit -n` configuration.
        # constrained only by our Semaphore limits.
        await asyncio.gather(*tasks)
        
        return sorted(self.open_ports, key=lambda x: x["port"])

class Start:
    def __init__(self, args=None):
        # Load the database dynamically upon execution.
        # This ensures we are always reading the latest user-set variables, avoiding stale memory cache bugs.
        # DEBUG TIP: If variables aren't updating when set in the CLI, verify that `path_to_database`
        # points to the exact same file the CLI is writing to.
        try:
            with open(path_to_database) as f:
                db = json.load(f)
        except FileNotFoundError:
            db = {}
            
        # Target Sanitization:
        # Safely parse the database target, stripping out URI schemes (http://) and trailing ports.
        # DEBUG TIP: If target parsing fails, verify that R_HOST doesn't contain multiple IPs 
        # or malformed URI structures (e.g., missing slashes).
        raw_target = str(db.get("R_HOST", ""))
        if "://" in raw_target:
            target_ip = urlparse(raw_target).hostname
        else:
            target_ip = raw_target.split(":")[0]
            
        if not target_ip:
            print("[-] No valid R_HOST set in the database.")
            return

        # Generate the target scope: Allow users to specify custom ports via the 'PORTS' variable.
        # Supports comma-separated lists and ranges (e.g., 80,443,8000-8080) and the PORT_RANGE flag.
        raw_ports = str(db.get("PORTS", ""))
        raw_port_range = str(db.get("PORT_RANGE", ""))

        # Combine both variables to allow maximum flexibility
        # DEBUG TIP: If port ranges seem to duplicate or fail to parse, ensure no invisible whitespace 
        # is breaking the split(',') logic below. `.strip(',')` removes trailing/leading commas.
        combined_ports_raw = f"{raw_ports},{raw_port_range}".strip(',')
        ports_to_scan = []
        
        if combined_ports_raw:
            for part in combined_ports_raw.split(','):
                part = part.strip()
                if '-' in part:
                    try:
                        start, end = part.split('-', 1)
                        # Boundary Check: Caps the ranges between 0 and 65535 to prevent 
                        # feeding invalid sockets to the asyncio layer which would cause fatal crashes.
                        start_port = max(0, int(start))
                        end_port = min(65535, int(end))
                        ports_to_scan.extend(range(start_port, end_port + 1))
                    except ValueError:
                        continue
                elif part.isdigit():
                    port_val = int(part)
                    if 0 <= port_val <= 65535:
                        ports_to_scan.append(port_val)
            ports_to_scan = sorted(list(set(ports_to_scan)))

        if not ports_to_scan:
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
                # Attempt to use the in-memory state manager if running within SuperSploit
                try:
                    from core.database import DatabaseManagment
                    has_db_manager = True
                except ImportError:
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

                if not isinstance(existing_targets, dict):
                    existing_targets = {}

                target_entry = existing_targets.setdefault(target_ip, {})
                
                # Legacy migration: If an older version of the framework stored a basic string (like "N/A") 
                # for this IP, convert it into a dictionary dynamically so we don't throw a KeyError.
                if not isinstance(target_entry, dict):
                    target_entry = existing_targets[target_ip] = {"status": target_entry}

                # Save the new port array into the target's dictionary space.
                target_entry["ports"] = results
                
                if has_db_manager:
                    DatabaseManagment.updateTargets(existing_targets)
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
name: "Async Port Scanner"
category: "Scanner"
desc: """Performs hyper-fast concurrent network mapping and banner grabbing.
Utilizes Python's asyncio event loop to bypass threading limits and scan hundreds 
of ports simultaneously."""
author: "Donald Ford"
#!#!#!