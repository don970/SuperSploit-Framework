# redefine input method
import json
import os
from subprocess import run

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
installation = f'{os.getenv("HOME")}/.SuperSploit'

history = FileHistory(f'{installation}/.data/.history/history')
input = PromptSession(history=history, auto_suggest=AutoSuggestFromHistory(), enable_history_search=True)
input = input.prompt

true, false = True, False

with open(f"{installation}/.data/.security/checksums.json") as file:
    io = json.load(file)
    file.close()


class checksums:
    phoneinfoga = io["phoneinfoga"].encode()

    @staticmethod
    def get_checksum(path):
        check = run(["sha256sum", path], capture_output=true)
        return check.stdout.decode().split(" ")[0]

    @staticmethod
    def check(original, to_check):
        if original != to_check.encode():
            return false
        return true


class Phone:
    def __init__(self, char):
        try:
            if not checksums.check(checksums.phoneinfoga, checksums.get_checksum("/usr/local/bin/phoneinfoga")):
                print(f"[!] Checksum verification Failed")
                if input("[*] Would you still like to proceed [y/n]").endswith("y"):
                    pass
                else:
                    return
            else:
                print(f"[*] Checksum verified\noriginal checksum: {checksums.phoneinfoga.decode()}\ncurrent checksum: {checksums.get_checksum('/usr/local/bin/phoneinfoga')}")

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
