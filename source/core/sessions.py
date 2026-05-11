import shlex
from .listener import Listener
from .ToStdOut import ToStdout

write = ToStdout.write

class Sessions:
    @staticmethod
    def manage(args):
        parts = shlex.split(args) if args else []
        
        # Show list of active sessions (e.g., "sessions" or "sessions -l")
        if not parts or len(parts) == 1 or (len(parts) == 2 and parts[1] == "-l"):
            sessions = Listener.active_sessions
            if not sessions:
                write("[-] No active sessions.")
                return
            
            write("\nActive Sessions")
            write("===============")
            write(f"{'ID':<4} | {'Target IP:Port':<22} | {'Status'}")
            write("-" * 42)
            for sid, info in sessions.items():
                addr = f"{info['addr'][0]}:{info['addr'][1]}"
                write(f"{sid:<4} | {addr:<22} | Active")
            write("\n[*] Type 'sessions -i <ID>' to interact with a target.")
            return
            
        # Interact with a specific session (e.g., "sessions -i 1")
        if len(parts) >= 3 and parts[1] == "-i":
            try:
                sid = int(parts[2])
                Listener.interact(sid)
            except ValueError:
                write("[-] Invalid session ID. Usage: sessions -i <id>")
            return
            
        write("Usage: sessions [-l] | [-i <id>]")