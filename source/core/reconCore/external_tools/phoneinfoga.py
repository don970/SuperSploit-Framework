import os
from subprocess import run
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

from ...security import validator

installation = f'{os.getenv("HOME")}/.SuperSploit'
# ... [Keep history and input setup] ...

class Phone:
    def __init__(self, char):
        try:
            tool_path = "/usr/local/bin/phoneinfoga"
            
            # UPDATED TO USE CUSTOM BINARY HASHING
            if not validator.verify_custom_binary("phoneinfoga", tool_path):
                print(f"[!] Checksum verification Failed!")
                if not input("[*] Would you still like to proceed [y/n]: ").lower().endswith("y"):
                    return
            else:
                print("[*] Checksum verified successfully via hashlib.")

            phone_number = input("Please enter a number to scan: ")
            if not phone_number.endswith("\n"):
                phone_number = phone_number + "\n"
            if len(phone_number) < 10:
                print("please enter a 10 digit phone number.")
                return
            with open(f"{installation}/.data/loot/phone_numbers", "r") as file:
                if phone_number not in file.read():
                    file.close()
                    with open(f"{installation}/.data/loot/phone_numbers", "a") as file1:
                        file1.write(phone_number)
                        file1.close()
            print(f"Scanning phone number: [{phone_number}].")
            data = run(["phoneinfoga", "scan", "-n", phone_number], capture_output=True)
            with open(f"{installation}/.data/scans/phoneinfoga.scan", "w") as file:
                file.write(data.stdout.decode())
                file.close()
            print(f"{data.stdout.decode()}\nscan logged to {installation}/.data/scans/phoneinfoga.scan")
        except KeyboardInterrupt:
            return 
