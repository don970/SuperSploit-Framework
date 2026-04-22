import os
from subprocess import run
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from ...security import validator

installation = f'{os.getenv("HOME")}/.SuperSploit'
history = FileHistory(f'{installation}/.data/.history/history')
session = PromptSession(history=history, auto_suggest=AutoSuggestFromHistory(), enable_history_search=True)

class Phone:
    @classmethod
    def scan(cls, args=None):
        tool_path = "/usr/local/bin/phoneinfoga"
        
        if not validator.verify_custom_binary("phoneinfoga", tool_path):
            print("[!] Checksum verification Failed!")
            if not session.prompt("[*] Would you still like to proceed [y/n]: ").lower().startswith("y"):
                return
        else:
            print("[*] Checksum verified successfully via hashlib.")

        phone_number = session.prompt("Please enter a 10-digit number to scan: ").strip()
        if len(phone_number) < 10:
            print("[-] Invalid input: Please enter at least a 10 digit phone number.")
            return

        # Ensure directory exists before reading/writing
        loot_dir = f"{installation}/.data/loot"
        os.makedirs(loot_dir, exist_ok=True)
        phone_file = f"{loot_dir}/phone_numbers"

        # Check if number exists, append if it doesn't
        try:
            with open(phone_file, "r") as file:
                existing_numbers = file.read()
        except FileNotFoundError:
            existing_numbers = ""

        if phone_number not in existing_numbers:
            with open(phone_file, "a") as file:
                file.write(f"{phone_number}\n")

        print(f"[*] Scanning phone number: [{phone_number}]...")
        result = run(["phoneinfoga", "scan", "-n", phone_number], capture_output=True, text=True)
        
        scan_dir = f"{installation}/.data/scans"
        os.makedirs(scan_dir, exist_ok=True)
        
        with open(f"{scan_dir}/phoneinfoga.scan", "w") as file:
            file.write(result.stdout)
            
        print(f"{result.stdout}\n[*] Scan logged to {scan_dir}/phoneinfoga.scan")