# This is a wrapper for nmap
import json
import os
import sys
from subprocess import run, Popen, PIPE


# redefine input method
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

history = FileHistory('.data/.history/history')
input = PromptSession(history=history, auto_suggest=AutoSuggestFromHistory(), enable_history_search=True)
input = input.prompt
installation = f'{os.getenv("HOME")}/.SuperSploit'

# replace the print method
def print(data):
    if "str" not in str(type(data)):
        data = f"{str(data)}"
    if not data.endswith("\n"):
        data = f"{data}\n"

    sys.stdout.write(data)
    return


class nmap:
    def __init__(self, ip):
        """This is a wrapper to use the tool nmap to
        scan for live host identification and more"""
        self.ip = ip[0]
        self.subnet = ip[1]
        self.targetlist = []
        return

    def Import(self):
        networks = []
        targets = []
        with open(f"{installation}/.data/target.json") as file:
            print("[*] Repopulating targets list via target file. ")
            data = json.load(file)
            file.close()
        for k, v in data.items():
            networks.append(k)

        for x in networks:
            print(f"{networks.index(x)}: {x}")
        network = data[networks[int(input("Please enter the index of the of the network: "))]]
        self.targetlist = network
        return "[*] Targets saved."

    def format_ip(self):
        ip = self.ip.split(".")
        st = f"{ip[0]}.{ip[1]}.{ip[2]}.0"
        ip = st
        if not input(f"would you like to perform a scan with a subnet of ({ip}/{self.subnet}): ").startswith("y"):
            ip = input("[*] Enter the address and subnet [ip/sub]: ")
            print("[*] IP and subnet updated.")
        ip = f"{ip}/{self.subnet}"
        return ip

    def build_ip_list(self):
        li = []
        ip = self.format_ip()
        print(f"[*] Running a -sn scan on {ip}")
        a = run(["nmap", "-sn", ip], capture_output=True)
        result = a.stdout.decode().split('\n')
        for x in result:
            if "Nmap scan report for" in x:
                li.append(x.split(" ")[4])
        return li

    def show_target_list(self):
        if len(self.targetlist) == 0:
            return "[!] Target list is not populated"
        try:
            for k, v in self.targetlist.items():
                print(f"{k}")
        except AttributeError:
            for x in self.targetlist:
                print(f"{x}")

        return "[*] Showing all saved targets"

    def show_detailed_target_list(self):
        if len(self.targetlist) == 0:
            return "[!] Target list not populated"
        try:
            for k, v in self.targetlist.items():
                print(k)
                for x, y in v.items():
                    print(f"    {x}: {y}")
        except AttributeError:
            for k in self.targetlist:
                print(k)

    def scan_whole_network(self) -> str:
        try:

            # import target dictionary
            with open(f"{installation}/.data/target.json") as file:
                targets = json.load(file)
                file.close()

            # get ip an essid
            li = self.build_ip_list()
            network = self.getessid()

            print(f"[*] Network ESSID: {network}")

            if network not in targets:
                print(f"[*] Adding ESSID {network}")
                targets[network] = {}

            for x in li:
                targets[network][x] = {}
                print(f"[*] Doing a -O scan on {x}")
                data = run(["sudo", "nmap", "-O", x], capture_output=True)
                l = data.stdout.decode().split("\n")
                for i in l:
                    targets[network][x]["IPV4"] = x
                    if l.index(i) > 4:
                        try:
                            if "MAC Address" in i:
                                a = i.split(": ")[1]
                                targets[network][x]["MAC Address"] = a
                            if "Device type:" in i:
                                b = i.split(": ")[1]
                                targets[network][x]["Device type"] = b
                            if "Running:" in i:
                                c = i.split(": ")[1]
                                targets[network][x]["Running"] = c
                            if "OS details" in i:
                                d = i.split(": ")[1]
                                targets[network][x]["OS details"] = d
                            if "OS CPE:" in i:
                                e = i.split(": ")[1]
                                targets[network][x]["OS CPE"] = e
                        except IndexError:
                            pass

            print("[*] Populating targets file.")

            with open(f"{installation}/.data/target.json", "w") as file:
                file.write(json.dumps(targets, sort_keys=True, indent=4))
                file.close()

            print("[*] Dumping targets to a global list.")
            self.targetlist = li

            return "[*] Targets added."
        except KeyboardInterrupt:
            return "[!] Exiting scan mode"

    def targetedScan(self) -> str or False:
        try:
            target_l = []
            network = self.getessid()
            with open(f"{installation}/.data/target.json") as file:
                targets = json.load(file)
                file.close()
            targets = targets[network]
            for k, v in targets.items():
                target_l.append(k)
            for x in target_l:
                print(f"{target_l.index(x)}: {x}")
            target = target_l[int(input("Please enter the index of the target: "))]
            print(f"[*] Running an -A scan on {target}")
            data = run(["sudo", "nmap", "-A", target], capture_output=True)
            print(data.stdout.decode())
            fp = data.stdout.decode().split("TCP/IP fingerprint:")[1].split("\n")[0]
            print(fp)
            with open(f"{installation}/.data/.assets/figerprints.json") as file:
                fpdb = json.load(file)
                file.close()
            for k, v in fpdb.items():
                if fp == k:
                    print("[*] Fingerprint found")
            return
        except OSError:
            return

    def customScan(self):
        try:
            if len(self.targetlist) < 1:
                return "[!] No targets available."
            for x in self.targetlist:
                print(f"{self.targetlist.index(x)}: {x}")
            data = input("Enter the index of the target: ")
            try:
                data = int(data)
                pass
            except Exception:
                return "[!] Invalid Input"
            data1 = input("Now enter the arguments to use: ")
            print("[*] Scanning... ")
            output = run(["nmap", data1, self.targetlist[data]], capture_output=True)
            print("[*] Populating custom scan file")
            with open(f"{installation}/.data/.custom_scan", "w") as file:
                file.write(output.stdout.decode())
                file.close()
            return "[*] Full scan logged to .data/.custom_scan"
        except KeyboardInterrupt:
            return "[!] Exiting scan mode"

    def traceroute(self):
        run(["traceroute", "google.com"])
        return

    def getessid(self):
        p1 = Popen(['iwconfig'], stdout=PIPE, stdin=PIPE, stderr=PIPE)
        p2 = Popen(['grep', "ESSID"], stdout=PIPE, stdin=PIPE, stderr=PIPE)
        p2.communicate(bytes(p1.communicate()[0]))
        n = p2.communicate()[0].decode().split(" ")
        for x in n:
            if "ESSID" in x:
                return x.split(":")[1][1:len(x.split(":")[1]) -1]

    def getports(self):
        with open(f"{installation}/.data/target.json") as file:
            targets = json.load(file)
            file.close()

        for x in targets[self.getessid()]:
            print(f"[*] Running a port scan for {x}")
            p = run(["nmap", x], capture_output=True)
            fdata = p.stdout.decode().split("\n")
            data = p.stdout.decode().split("\n")[5:]
            print(f"[*] Attempting further os detection on {x}")
            self.osdetect(fdata, targets, x)
            targets[self.getessid()][x]["ports"] = data[0:len(data) - 4]

        with open(f"{installation}/.data/target.json", "w") as file:
            file.write(json.dumps(targets, sort_keys=True, indent=4))
            file.close()

        return

    def osdetect(self, data, targets, x):
        for i in data:
            if "Nmap scan report for" in i:
                targets[self.getessid()][x]["Hostname"] = i.split(" ")[4]
                print(f'[*] Assining {targets[self.getessid()][x]["Hostname"]} as hostname for {x}')

        # os detection via services for apple devices
        if "62078/tcp open  iphone-sync" in data:
            print(f"iphone detected for {x}")
            targets[self.getessid()][x]["Device type"] = "Iphone"
            targets[self.getessid()][x]["Running"] = "IOS"
            targets[self.getessid()][x]["vendor"] = "Apple"

        return