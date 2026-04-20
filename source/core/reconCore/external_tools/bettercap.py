import subprocess
import os
from ...security import validator

class bettercap:
    def __init__(self, ar):
        try:
            if not validator.verify_system_package("bettercap"):
                print(f"[!] Integrity verification Failed! 'bettercap' package modified.")
                if not input("[*] Would you still like to proceed [y/n]: ").lower().endswith("y"):
                    return
            else:
                print("[*] Bettercap binary integrity verified via dpkg.")
                subprocess.run(["sudo", "bettercap"])
                return
        except OSError:
            return False
