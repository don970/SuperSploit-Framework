import sys
import asyncio
import re
import time
import traceback

# Try to import framework modules if running inside SuperSploit
try:
    from core.database import DatabaseManagment
    from core.logger import Logger
except ImportError:
    DatabaseManagment = None
    Logger = None

#!#!#!
# name: Async Port Scanner
# description: High-speed asynchronous port scanner with active heuristic service detection.
# target: Remote Host IP
# root: False
#!#!#!

class ServiceDetector:
    """
    Asynchronous Heuristic Service and Protocol Detector.
    Performs active protocol signature matching and fallback heuristic detection directly over raw sockets.
    """
    
    # Heuristic fallbacks for well-known ports if active probing fails to identify the banner
    COMMON_PORTS = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Proxy"
    }

    # Active protocol signatures (Regex mapped against raw byte responses)
    SIGNATURES = {
        b"^SSH-\d\.\d": "SSH",
        b"^HTTP/1\.[01] \d\d\d": "HTTP",
        b"^220.*FTP": "FTP",
        b"^220.*SMTP": "SMTP",
        b"^220.*ESMTP": "SMTP",
        b"^\+OK": "POP3",
        b"^\* OK.*IMAP": "IMAP",
        b"mysql_native_password": "MySQL",
        b"RFB \d{3}\.\d{3}": "VNC",
        b"^\x15\x03": "TLS/SSL",
        b"Server: Werkzeug": "Werkzeug (Python HTTP)",
        b"Server: Apache": "Apache HTTP",
        b"Server: nginx": "Nginx HTTP"
    }

    @classmethod
    async def detect(cls, ip: str, port: int, timeout: float = 1.5):
        """
        Attempts to connect to a port, grab the banner, and detect the service.
        Uses a dual-probe approach (Passive listening -> Active HTTP/Generic payload).
        """
        service = "Unknown"
        banner_display = ""

        try:
            # DEBUG TIP: asyncio.wait_for wraps the TCP handshake to ensure dead IPs 
            # don't cause the asynchronous event loop to hang indefinitely.
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), 
                timeout=timeout
            )
            
            # 1. PASSIVE PROBE (Wait for the service to speak first, e.g., SSH or FTP)
            raw_banner = b""
            try:
                raw_banner = await asyncio.wait_for(reader.read(2048), timeout=timeout/3)
            except asyncio.TimeoutError:
                pass
            
            # 2. ACTIVE PROBE (If passive yields nothing, actively poke it)
            if not raw_banner:
                # Generic HTTP payload elicits responses from most HTTP/REST/Proxy servers
                probe = f"GET / HTTP/1.1\r\nHost: {ip}\r\nAccept: */*\r\n\r\n".encode()
                writer.write(probe)
                await writer.drain()
                
                try:
                    raw_banner = await asyncio.wait_for(reader.read(2048), timeout=timeout/3)
                except asyncio.TimeoutError:
                    pass
            
            # Clean up the socket
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            
            # 3. SIGNATURE MATCHING
            if raw_banner:
                # Clean up the banner string to be terminal-friendly
                decoded_banner = raw_banner.decode('utf-8', errors='ignore').strip()
                banner_display = decoded_banner.split('\r\n')[0].split('\n')[0][:80]
                
                for sig, srv in cls.SIGNATURES.items():
                    if re.search(sig, raw_banner, re.IGNORECASE):
                        service = srv
                        break
                        
            # 4. HEURISTIC FALLBACK
            if service == "Unknown" and port in cls.COMMON_PORTS:
                service = cls.COMMON_PORTS[port]
                
            # Quick TLS identification fallback if no banner was extracted
            if not banner_display and port in [443, 8443]:
                service = "HTTPS"
                
            return "OPEN", service, banner_display

        except (ConnectionRefusedError, OSError):
            # Port is definitively closed or unreachable
            return "CLOSED", "", ""
        except asyncio.TimeoutError:
            # TCP handshake timed out (Filtered / Dropped by Firewall)
            return "FILTERED", "", ""
        except Exception:
            return "CLOSED", "", ""


async def scan_port(ip, port, timeout, semaphore, open_ports):
    """Worker function constrained by an asyncio Semaphore to limit concurrent file descriptors."""
    async with semaphore:
        status, service, banner = await ServiceDetector.detect(ip, port, timeout)
        
        if status == "OPEN":
            open_ports.append({"port": port, "service": service, "banner": banner})
            banner_str = f" | Banner: {banner}" if banner else ""
            print(f"[+] Port {port:<5} | {service:<10} | OPEN {banner_str}")


async def scan_host(ip, ports, concurrency, timeout):
    print(f"[*] Starting Async Port Scan on {ip} ({len(ports)} ports)")
    print(f"[*] Concurrency Limit: {concurrency} tasks | Timeout: {timeout}s\n")
    
    semaphore = asyncio.Semaphore(concurrency)
    open_ports = []
    
    tasks = [scan_port(ip, port, timeout, semaphore, open_ports) for port in ports]
    await asyncio.gather(*tasks)
    
    return open_ports


def Start(args=None):
    # Dynamically pull scope configurations from the framework database
    if DatabaseManagment:
        db = DatabaseManagment.get()
        target_ip = db.get("R_HOST", db.get("TARGET", "127.0.0.1"))
        port_scope = str(db.get("PORT_RANGE", "1-65535"))
    else:
        target_ip = args[0] if args else "127.0.0.1"
        port_scope = "1-65535"

    try:
        start, end = map(int, port_scope.split("-"))
        ports_list = list(range(start, end + 1))
    except ValueError:
        print(f"[!] Invalid PORT_RANGE '{port_scope}'. Defaulting to 1-1024.")
        ports_list = list(range(1, 1025))
        
    start_time = time.time()
    open_ports = asyncio.run(scan_host(target_ip, ports_list, concurrency=500, timeout=1.5))
    
    print(f"\n[+] Scan Complete. Found {len(open_ports)} open ports.")
    
    # Log discovery seamlessly to the Target Database cache
    if DatabaseManagment:
        print(f"[*] Saving port data for {target_ip} to the targets database...")
        targets_db = DatabaseManagment.getTargets()
        
        target_entry = targets_db.setdefault(target_ip, {})
        target_entry["open_ports"] = open_ports
        
        DatabaseManagment.updateTargets(targets_db)
        print("[+] Database updated successfully.")