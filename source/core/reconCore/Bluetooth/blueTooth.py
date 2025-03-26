import json
from subprocess import run, Popen, PIPE
from os import getenv

pipe, true, false = PIPE, True, False
popen = Popen
install_location = f'{getenv("HOME")}/.SuperSploit'
with open(f"{install_location}/.data/.security/checksums.json") as file:
    io = json.load(file)
    file.close()


class checksums:
    ducky = io["ducky"].encode()
    blue_ranger = io["blue-ranger"].encode()


    @staticmethod
    def get_checksum(path):
        check = run(["sha256sum", path], capture_output=true)
        return check.stdout.decode().split(" ")[0]
    
    @staticmethod
    def check(original, to_check):
        if original != to_check.encode():
            return false
        return true
        

class bt:

    @staticmethod
    def ducky(arg):
        try:
            cmd = "python3 source/core/reconCore/Bluetooth/BlueDucky.py".split(" ")
            check = checksums.get_checksum(f"{install_location}/source/core/reconCore/Bluetooth/BlueDucky.py")
            print(f"[*] original checksum {checksums.ducky.decode()}\n[*] current checksum: {check}")
            if checksums.check(checksums.ducky, check):
                print(f"[*] File verified via sha256 checksum\n[*] Running {cmd[0]} {cmd[1]}")
                run(cmd)
                return true
            else:
                if input("[!] sha256 checksum not verified\n[!] Would you like to still proceed [y/n]: ").endswith("y"):
                    print(f"[!] Running unverified {cmd[1]}")
                    run(cmd)
                    return true
                print("[*] Operation canceled by user")
                return False
        except KeyboardInterrupt:
            run(["clear"])
            return True

    @staticmethod
    def ranger(args):
        with open(f"{install_location}/.data/loot/known_devices.txt") as file:
            targets = file.read().split("\n")
            file.close()
        for x in targets:
            print(f"{targets.index(x)}: {x}")


        # set target
        try:
            target = targets[int(input("Please enter the index of the target: "))]
            target = target.split(",")[0]
        except ValueError:
            print("[!] Please enter a correct index number")
            return

        try:
            cmd = f"sudo bash source/core/reconCore/Bluetooth/blue.sh hci0 {target}".split(" ")
            check = checksums.get_checksum(f"{install_location}/source/core/reconCore/Bluetooth/blue.sh")
            print(f"[*] original checksum {checksums.blue_ranger.decode()}\n[*] current checksum: {check}")
            if checksums.check(checksums.blue_ranger, check):
                print(f"[*] File verified via sha256 checksum\n[*] Running {cmd[0]} {cmd[1]}")
                run(cmd)
                return true
            else:
                if input("[!] sha256 checksum not verified\n[!] Would you like to still proceed [y/n]: ").endswith("y"):
                    print(f"[!] Running unverified {cmd[1]}")
                    run(cmd)
                    return true
                print("[*] Operation canceled by user")
                return False
        except KeyboardInterrupt:
            run(["clear"])
            return True

    @staticmethod
    def scan(args):
        return
