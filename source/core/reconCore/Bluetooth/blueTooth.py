from subprocess import run, Popen, PIPE
from os import getenv
from ...security import validator

pipe, true, false = PIPE, True, False
install_location = f'{getenv("HOME")}/.SuperSploit'

class bt:
    @staticmethod
    def ducky(arg):
        try:
            script_path = f"{install_location}/source/core/reconCore/Bluetooth/BlueDucky.py"
            cmd = ["python3", script_path]
            
            if validator.verify_custom_binary("ducky", script_path):
                print(f"[*] File verified securely via native SHA256 checksum")
                run(cmd)
                return True
            else:
                if input("[!] SHA256 checksum not verified\n[!] Would you like to still proceed [y/n]: ").lower().endswith("y"):
                    print(f"[!] Running unverified BlueDucky")
                    run(cmd)
                    return True
                print("[*] Operation canceled by user")
                return False
        except KeyboardInterrupt:
            run(["clear"])
            return True

    @staticmethod
    def ranger(args):
        with open(f"{install_location}/.data/loot/known_devices.txt") as file:
            targets = file.read().split("\n")
            
        for idx, x in enumerate(targets):
            if x:
                print(f"{idx}: {x}")

        try:
            target_idx = int(input("Please enter the index of the target: "))
            target = targets[target_idx].split(",")[0]
        except (ValueError, IndexError):
            print("[!] Please enter a valid index number")
            return

        try:
            script_path = f"{install_location}/source/core/reconCore/Bluetooth/blue.sh"
            cmd = ["sudo", "bash", script_path, "hci0", target]
            
            if validator.verify_custom_binary("blue-ranger", script_path):
                print(f"[*] File verified securely via native SHA256 checksum")
                run(cmd)
                return True
            else:
                if input("[!] SHA256 checksum not verified\n[!] Would you like to still proceed [y/n]: ").lower().endswith("y"):
                    print(f"[!] Running unverified blue.sh")
                    run(cmd)
                    return True
                print("[*] Operation canceled by user")
                return False
        except KeyboardInterrupt:
            run(["clear"])
            return True

    @staticmethod
    def scan(args):
        return
