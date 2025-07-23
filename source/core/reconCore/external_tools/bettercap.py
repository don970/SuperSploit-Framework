import subprocess
import json
import os

true, false = True, False
install_location = f'{os.getenv("HOME")}/.SuperSploit'
with open(f"{install_location}/.data/.security/checksums.json") as file:
    io = json.load(file)
    file.close()


class checksums:
    bettercap = io["bettercap"].encode()

    @staticmethod
    def get_checksum(path):
        check = subprocess.run(["sha256sum", path], capture_output=true)
        return check.stdout.decode().split(" ")[0]

    @staticmethod
    def check(original, to_check):
        if original != to_check.encode():
            return false
        return true

class bettercap:
    def __init__(self, ar):
        try:
            if not checksums.check(checksums.bettercap, checksums.get_checksum("/usr/bin/bettercap")):
                print(f"[!] Checksum verification Failed")
                if input("[*] Would you still like to proceed [y/n]").endswith("y"):
                    pass
                else:
                    return
            else:
                print(f"[*] Checksum verified\noriginal checksum: {checksums.bettercap.decode()}\ncurrent checksum: {checksums.get_checksum('/usr/bin/bettercap')}")
                subprocess.run(["sudo", "bettercap"])
                return
        except OSError:
            return False
        pass