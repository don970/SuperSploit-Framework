# This is a wrapper for nmap
import getpass
import json
import os
import sys
from subprocess import run, Popen, PIPE


# redefine input method
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

history = FileHistory('.data/.history/nhistory')
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
        self.targetlist = {}
        self.targets = []
        return

    def Import(self):
        networks = []
        targets = []
        with open(f"{installation}/.data/.nmap/target.json") as file:
            print("[*] Repopulating targets list via target file. ")
            data = json.load(file)
            file.close()
        for k, v in data.items():
            networks.append(k)

        for x in networks:
            print(f"{networks.index(x)}: {x}")
        network = data[networks[int(input("Please enter the index of the of the network: "))]]
        self.targetlist = network
        for k, v in self.targetlist.items():
            self.targets.append(k)
        with open(f"{installation}/.data/.nmap/.targets", "w") as file1:
            for x in self.targetlist:
                file1.write(f"{x}\n")
            file.close()
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
        self.targets = li
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
            with open(f"{installation}/.data/.nmap/target.json") as file:
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

            with open(f"{installation}/.data/.nmap/target.json", "w") as file:
                file.write(json.dumps(targets, sort_keys=True, indent=4))
                file.close()

            print("[*] Dumping targets to a global list.")
            self.targetlist = li

            return "[*] Targets added."
        except KeyboardInterrupt:
            return "[!] Exiting scan mode"

    def printT(self) -> None:
        for x in self.targets:
            print(f"{self.targets.index(x)}: {x}")
        return

    def targeted_scan(self):
        if len(self.targetlist) == 0:
            return "[!] target list not populated run import-targets or get-targets"
        self.printT()
        target = self.targets[int(input("Please enter the index of the target: "))]
        arg = input("Please enter the arguments for scan: ").split(" ")
        arguments = arg
        if arg == ['']:
            arguments = []
        if not arguments:
            print(f"[*] Running nmap {target}")
            run(["nmap", target])
            return


        cmd = 'sudo nmap '
        for x in arguments:
            cmd += f"{x} "
        cmd += target
        print(f"running {cmd}")
        run(cmd.split(" "))

    def custom_scan(self):
        return

    def traceroute(self):
        pass
    
    def getessid(self):
        passwd = getpass.getpass("Enter sudo passwd: ")
        passwd = f"{passwd}\n".encode("utf-8")
        p1 = Popen(["sudo", "-S", 'iwconfig'], stdout=PIPE, stdin=PIPE, stderr=PIPE)
        p1.communicate(passwd)
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