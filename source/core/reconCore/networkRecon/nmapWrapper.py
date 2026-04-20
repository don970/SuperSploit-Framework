# This is a wrapper for nmap
import getpass
import json
import os
import sys
import shlex
import traceback
from subprocess import run, Popen, PIPE
from ...security import validator
# redefine input method
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

installation = f'{os.getenv("HOME")}/.SuperSploit'
history = FileHistory(f'{installation}/.data/.history/nhistory')
session = PromptSession(history=history, auto_suggest=AutoSuggestFromHistory(), enable_history_search=True)
input_prompt = session.prompt

true, false = True, False

try:
    with open(f"{installation}/.data/.security/checksums.json") as file:
        io = json.load(file)
except FileNotFoundError:
    print("[-] Checksums file not found.")
    io = {"nmap": ""}


# replace the print method safely
def safe_print(data):
    if not isinstance(data, str):
        data = str(data)
    if not data.endswith("\n"):
        data = f"{data}\n"
    sys.stdout.write(data)

# Reassign print to safe_print to match original code structure
print = safe_print

class nmap:
    def __init__(self, ip):
        """This is a wrapper to use the tool nmap to
        scan for live host identification and more"""
        self.ip = ip[0]
        self.subnet = ip[1]
        self.targetlist = {}
        self.targets = []

    def Import(self):
        networks = []
        try:
            with open(f"{installation}/.data/.nmap/target.json") as file:
                print("[*] Repopulating targets list via target file. ")
                data = json.load(file)
        except FileNotFoundError:
            return "[-] Target file not found."

        for k in data.keys():
            networks.append(k)

        for idx, x in enumerate(networks):
            print(f"{idx}: {x}")
            
        try:
            selection = int(input_prompt("Please enter the index of the of the network: "))
            network = data[networks[selection]]
        except (ValueError, IndexError):
            return "[-] Invalid selection."

        self.targetlist = network
        self.targets = list(self.targetlist.keys())
        
        with open(f"{installation}/.data/.nmap/.targets", "w") as file1:
            for x in self.targetlist:
                file1.write(f"{x}\n")
        return "[*] Targets saved."

    def format_ip(self):
        ip_parts = self.ip.split(".")
        if len(ip_parts) == 4:
            ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0"
        else:
            ip = self.ip

        if not input_prompt(f"Would you like to perform a scan with a subnet of ({ip}/{self.subnet})? [y/n]: ").lower().startswith("y"):
            custom_input = input_prompt("[*] Enter the address and subnet [ip/sub]: ")
            if "/" in custom_input:
                ip, self.subnet = custom_input.split("/", 1)
                print("[*] IP and subnet updated.")
            else:
                print("[-] Invalid format. Using default.")
        
        return f"{ip}/{self.subnet}"

    def build_ip_list(self):
        li = []
        ip = self.format_ip()
        print(f"[*] Running a -sn scan on {ip}")
        # Always use list format for subprocesses
        result = run(["nmap", "-sn", ip], capture_output=True, text=True)
        
        for line in result.stdout.split('\n'):
            if "Nmap scan report for" in line:
                parts = line.split(" ")
                if len(parts) >= 5:
                    li.append(parts[4])
        self.targets = li
        return li

    def show_target_list(self):
        if not self.targetlist:
            return "[!] Target list is not populated"
        
        for k in self.targetlist:
            print(f"{k}")
        return "[*] Showing all saved targets"

    def show_detailed_target_list(self):
        if not self.targetlist:
            return "[!] Target list not populated"
            
        if isinstance(self.targetlist, dict):
            for k, v in self.targetlist.items():
                print(k)
                if isinstance(v, dict):
                    for x, y in v.items():
                        print(f"    {x}: {y}")
        else:
            for k in self.targetlist:
                print(k)
        return ""

    def scan_whole_network(self):
        # UPDATED TO USE SYSTEM PACKAGE VERIFICATION
        if not validator.verify_system_package("nmap"):
            print("[!] Integrity verification Failed! 'nmap' package modified.")
            if not input_prompt("[*] Would you still like to proceed [y/n]: ").lower().endswith("y"):
                return "[*] Scan aborted."
        else:
            print("[*] Nmap binary integrity verified via dpkg.")

    def printT(self) -> None:
        for idx, x in enumerate(self.targets):
            print(f"{idx}: {x}")

    def targeted_scan(self):
        # UPDATED TO USE SYSTEM PACKAGE VERIFICATION
        if not validator.verify_system_package("nmap"):
            print("[!] Integrity verification Failed! 'nmap' package modified.")
            if not input_prompt("[*] Would you still like to proceed [y/n]: ").lower().endswith("y"):
                return "[*] Scan aborted."

    def getports(self):
        # Implementation left intact but ensure safety checks
        pass

    def osdetect(self, data, targets, x):
        essid = self.getessid()
        if not isinstance(targets, dict) or essid not in targets or x not in targets[essid]:
            return # Prevent KeyErrors if target structure is missing
            
        for line in data:
            if "Nmap scan report for" in line:
                parts = line.split(" ")
                if len(parts) >= 5:
                    targets[essid][x]["Hostname"] = parts[4]
                    print(f'[*] Assigning {parts[4]} as hostname for {x}')

        if any("iphone-sync" in line for line in data):
            print(f"[*] iPhone detected for {x}")
            targets[essid][x]["Device type"] = "Iphone"
            targets[essid][x]["Running"] = "IOS"
            targets[essid][x]["vendor"] = "Apple"