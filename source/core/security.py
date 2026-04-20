import hashlib
import subprocess
import os
import json

install_location = f'{os.getenv("HOME")}/.SuperSploit'
CHECKSUMS_FILE = f"{install_location}/.data/.security/checksums.json"

class SecurityValidator:
    def __init__(self):
        self.checksums = self._load_checksums()

    def _load_checksums(self):
        if not os.path.exists(CHECKSUMS_FILE):
            return {}
        try:
            with open(CHECKSUMS_FILE, "r") as file:
                return json.load(file)
        except Exception:
            return {}

    @staticmethod
    def verify_system_package(package_name: str) -> bool:
        """
        Verifies integrity of system packages installed via apt/dpkg.
        Returns True if the package is unmodified, False if tampered or missing.
        """
        try:
            # dpkg -V returns 0 if all files in the package pass integrity checks
            result = subprocess.run(
                ["dpkg", "-V", package_name], 
                capture_output=True, 
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            # Fallback if dpkg is not available on the OS
            return False

    @staticmethod
    def get_sha256(file_path: str) -> str:
        """Securely generates a SHA256 hash using native Python hashlib."""
        if not os.path.isfile(file_path):
            return ""
            
        sha256_hash = hashlib.sha256()
        try:
            # Read in chunks to prevent memory overload on large binaries
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return ""

    def verify_custom_binary(self, tool_name: str, file_path: str) -> bool:
        """Verifies a custom downloaded binary against the recorded hash."""
        expected_hash = self.checksums.get(tool_name, "")
        if not expected_hash:
            return False
            
        actual_hash = self.get_sha256(file_path)
        return actual_hash == expected_hash

# Global instance for easy importing
validator = SecurityValidator()
