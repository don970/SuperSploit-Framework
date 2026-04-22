import subprocess
import os
from prompt_toolkit import prompt as get_input
from ...security import validator

class BettercapWrapper:
    @staticmethod
    def run(args=None):
        try:
            if not validator.verify_system_package("bettercap"):
                print("[!] Integrity verification Failed! 'bettercap' package modified.")
                if not get_input("[*] Would you still like to proceed [y/n]: ").lower().startswith("y"):
                    return False
            else:
                print("[*] Bettercap binary integrity verified via dpkg.")
                
            subprocess.run(["sudo", "bettercap"])
            return True
        except OSError as e:
            print(f"[-] OS Error launching bettercap: {e}")
            return False