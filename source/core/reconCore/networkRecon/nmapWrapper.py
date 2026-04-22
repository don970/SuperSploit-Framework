import json
import os
import sys
from subprocess import run
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from ...security import validator

installation = f'{os.getenv("HOME")}/.SuperSploit'
history = FileHistory(f'{installation}/.data/.history/nhistory')
session = PromptSession(history=history, auto_suggest=AutoSuggestFromHistory(), enable_history_search=True)

class NmapWrapper:
    def __init__(self, ip_tuple):
        """Wrapper for host identification and network scanning"""
        self.ip = ip_tuple[0]
        self.subnet = ip_tuple[1]
        self.targetlist = {}
        self.targets = []
        
        # Ensure directories exist
        os.makedirs(f"{installation}/.data/.nmap", exist_ok=True)

    def import_targets(self):
        target_file = f"{installation}/.data/.nmap/target.json"
        try:
            with open(target_file, "r") as file:
                print("[*] Repopulating targets list via target file...")
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return "[-] Target file not found or corrupted."

        networks = list(data.keys())
        for idx, net in enumerate(networks):
            print(f"{idx}: {net}")
            
        try:
            selection = int(session.prompt("Please enter the index of the network: "))
            self.targetlist = data[networks[selection]]
            self.targets = list(self.targetlist.keys())
            
            with open(f"{installation}/.data/.nmap/.targets", "w") as file:
                for target in self.targets:
                    file.write(f"{target}\n")
            return "[*] Targets saved."
        except (ValueError, IndexError):
            return "[-] Invalid selection."

    def format_ip(self):
        # Safely replace the last octet with 0 for subnet scanning
        ip_parts = self.ip.split(".")
        if len(ip_parts) == 4:
            ip_parts[3] = "0"
            base_ip = ".".join(ip_parts)
        else:
            base_ip = self.ip

        prompt_text = f"Would you like to perform a scan with subnet ({base_ip}/{self.subnet})? [y/n]: "
        if not session.prompt(prompt_text).lower().startswith("y"):
            custom_input = session.prompt("[*] Enter the address and subnet [ip/subnet]: ")
            if "/" in custom_input:
                self.ip, self.subnet = custom_input.split("/", 1)
                print("[*] IP and subnet updated.")
                return custom_input
            else:
                print("[-] Invalid format. Using default.")
                
        return f"{base_ip}/{self.subnet}"

    def build_ip_list(self):
        target_range = self.format_ip()
        print(f"[*] Running a ping scan (-sn) on {target_range}")
        
        result = run(["nmap", "-sn", target_range], capture_output=True, text=True)
        self.targets = []
        
        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                parts = line.split()
                if len(parts) >= 5:
                    self.targets.append(parts[4])
                    
        return self.targets

    def verify_nmap(self):
        if not validator.verify_system_package("nmap"):
            print("[!] Integrity verification Failed! 'nmap' package modified.")
            if not session.prompt("[*] Would you still like to proceed [y/n]: ").lower().startswith("y"):
                return False
        else:
            print("[*] Nmap binary integrity verified via dpkg.")
        return True

    def scan_whole_network(self):
        if not self.verify_nmap():
            return "[*] Scan aborted."
        # Scanning logic here...
        pass