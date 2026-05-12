import sys
import os
import asyncio
import re
import time
import pickle
import traceback
import ipaddress

# Dynamically append the framework's source directory to sys.path
# so isolated sudo subprocesses can import the core database modules
_scanner_dir = os.path.dirname(os.path.abspath(__file__))
_framework_root = os.path.abspath(os.path.join(_scanner_dir, "..", ".."))
_source_dir = os.path.join(_framework_root, "source")
if _source_dir not in sys.path:
    sys.path.append(_source_dir)

# Try to import framework modules if running inside SuperSploit
try:
    from core.database import DatabaseManagment
    from core.logger import Logger
except ImportError as e:
    print(f"[*] Note: Framework core modules unavailable in sudo environment ({e}). Using native file I/O.")
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
        rb"^SSH-\d\.\d": "SSH",
        rb"^HTTP/1\.[01] \d\d\d": "HTTP",
        b"^220.*FTP": "FTP",
        b"^220.*SMTP": "SMTP",
        b"^220.*ESMTP": "SMTP",
        rb"^\+OK": "POP3",
        rb"^\* OK.*IMAP": "IMAP",
        b"mysql_native_password": "MySQL",
        rb"RFB \d{3}\.\d{3}": "VNC",
        b"^\x15\x03": "TLS/SSL",
        b"Server: Werkzeug": "Werkzeug (Python HTTP)",
        b"Server: Apache": "Apache HTTP",
        b"Server: nginx": "Nginx HTTP"
    }

    NMAP_COMPILED_SIGS = []
    _nmap_loaded = False

    @classmethod
    def load_nmap_db(cls):
        """Dynamically loads and compiles the Nmap service probes database."""
        if cls._nmap_loaded:
            return
            
        # Check if the database was already compiled and cached in the global sys module.
        # This prevents re-parsing the huge file if the framework reloads this module dynamically.
        if hasattr(sys, '_supersploit_nmap_cache'):
            cls.NMAP_COMPILED_SIGS = sys._supersploit_nmap_cache
            cls._nmap_loaded = True
            return
            
        # Check for a pickled version on disk for ultra-fast subprocess loading
        cache_path = os.path.expanduser("~/.SuperSploit/.data/.config/nmap-compiled.pkl")
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'rb') as f:
                    cls.NMAP_COMPILED_SIGS = pickle.load(f)
                cls._nmap_loaded = True
                sys._supersploit_nmap_cache = cls.NMAP_COMPILED_SIGS
                return
            except Exception:
                pass # Fallback to parsing the text file if pickle is corrupted

        cls._nmap_loaded = True
        
        # Try to resolve the database path regardless of where the script is executed from
        paths = [
            os.path.expanduser("~/.SuperSploit/.data/.config/nmap-service-probes.txt"),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.data/.config/nmap-service-probes.txt")),
            ".data/.config/nmap-service-probes.txt"
        ]
        
        for db_path in paths:
            if os.path.exists(db_path):
                try:
                    with open(db_path, 'r', encoding='latin-1') as f:
                        for line in f:
                            if line.startswith("match ") or line.startswith("softmatch "):
                                parts = line.strip().split(' ', 2)
                                if len(parts) >= 3 and parts[2].startswith('m'):
                                    delim = parts[2][1] # Usually a '|' or '=' character
                                    try:
                                        regex_str = parts[2].split(delim)[1].replace('\\0', '\\x00')
                                        compiled = re.compile(regex_str.encode('latin-1'), re.IGNORECASE)
                                        cls.NMAP_COMPILED_SIGS.append((compiled, parts[1]))
                                    except Exception:
                                        continue # Skip PCRE syntaxes that Python's 're' module doesn't support
                except Exception:
                    pass
                break
                
        # Save the compiled database to the global interpreter memory for instant future scans
        sys._supersploit_nmap_cache = cls.NMAP_COMPILED_SIGS
        
        # Save the fully compiled byte-objects to disk to persist across subprocess executions
        try:
            with open(cache_path, 'wb') as f:
                pickle.dump(cls.NMAP_COMPILED_SIGS, f)
        except Exception:
            pass

    @classmethod
    async def detect(cls, ip: str, port: int, timeout: float = 1.5):
        """
        Attempts to connect to a port, grab the banner, and detect the service.
        Uses a dual-probe approach (Passive listening -> Active HTTP/Generic payload).
        """
        service = "Unknown"
        banner_display = ""

        if not cls._nmap_loaded:
            cls.load_nmap_db()

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
                        
                # Fallback to the massive Nmap database if our hardcoded signatures fail
                if service == "Unknown" and cls.NMAP_COMPILED_SIGS:
                    for sig_regex, srv in cls.NMAP_COMPILED_SIGS:
                        if sig_regex.search(raw_banner):
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
        target_ip = db.get("R_HOST")
        if not target_ip:
            target_ip = "127.0.0.1"
        port_scope = str(db.get("PORT_RANGE", "1-65535"))
    else:
        # Fallback to direct file read if the core framework fails to import under sudo
        try:
            import json
            db_path = os.path.join(_framework_root, ".data", ".config", "data.json")
            with open(db_path, "r", encoding="utf-8") as f:
                db = json.load(f)
            target_ip = db.get("R_HOST", "127.0.0.1")
            port_scope = str(db.get("PORT_RANGE", "1-65535"))
        except Exception:
            target_ip = args[0] if args else "127.0.0.1"
            port_scope = "1-65535"

    try:
        start, end = map(int, port_scope.split("-"))
        ports_list = list(range(start, end + 1))
    except ValueError:
        print(f"[!] Invalid PORT_RANGE '{port_scope}'. Defaulting to 1-1024.")
        ports_list = list(range(1, 1025))
        
    # Convert the target into a list of IPs to natively support CIDR (e.g. 192.168.0.1/24)
    try:
        network = ipaddress.ip_network(target_ip, strict=False)
        hosts = [str(ip) for ip in network.hosts()] if network.num_addresses > 1 else [str(network.network_address)]
    except ValueError:
        # Fallback for standard domain names like example.com
        hosts = [target_ip]

    for host in hosts:
        open_ports = asyncio.run(scan_host(host, ports_list, concurrency=500, timeout=1.5))
        
        print(f"\n[+] Scan Complete. Found {len(open_ports)} open ports for {host}.")
        
        # Log discovery seamlessly to the Target Database cache
        if open_ports:
            if DatabaseManagment:
                print(f"[*] Saving port data for {host} to the targets database...")
                targets_db = DatabaseManagment.getTargets()

                target_entry = targets_db.setdefault(host, {})
                # Ensure target_entry is a dictionary (fixes crashes on corrupt/legacy data)
                if not isinstance(target_entry, dict):
                    target_entry = {}
                    targets_db[host] = target_entry
                target_entry["open_ports"] = open_ports

                DatabaseManagment.updateTargets(targets_db)
                DatabaseManagment.sync_targets_to_disk()
                print("[+] Database updated successfully.")
            else:
                # Native JSON fallback for sudo isolation
                try:
                    import json
                    targets_path = os.path.join(_framework_root, ".data", ".config", "targets.json")
                    print(f"[*] Saving port data for {host} directly to {targets_path}...")
                    try:
                        with open(targets_path, "r", encoding="utf-8") as f:
                            targets_data = json.load(f)
                    except Exception:
                        targets_data = {"TARGETS": {}}

                    target_entry = targets_data.setdefault("TARGETS", {}).setdefault(host, {})
                    # Ensure target_entry is a dictionary for the native fallback as well
                    if not isinstance(target_entry, dict):
                        target_entry = {}
                        targets_data["TARGETS"][host] = target_entry
                    target_entry["open_ports"] = open_ports
                    with open(targets_path, "w", encoding="utf-8") as f:
                        json.dump(targets_data, f, indent=4, sort_keys=True)
                    print("[+] Database updated successfully.")
                except Exception as e:
                    print(f"[-] Failed to update targets natively: {e}")


if __name__ == "__main__":
    Start(sys.argv[1:])