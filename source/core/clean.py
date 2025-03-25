import os.path

from .ToStdOut import ToStdout
print = ToStdout.write
installation = f'{os.getenv("HOME")}/.SuperSploit'


class clean:
    def __init__(self, ar):
        self.ar = ar
        print("[*] Doing a full clean. Clearing history, error log along with all scan and target data.")
        paths = [".data/scans/.personSearch", ".data/loot/.passwords", ".data/.nmap/.targets",
                 ".data/scan/targeted_scan", ".data/scans/phone_numbers", ".data/scan/custom_scan",
                 ".data/.history/history", ".data/.errors/error.log", ".data/scans/phoneinfoga.scan",
                 ".data/scans/.personSearch", ".data/.history/nhistory"]
        for x in paths:
            if os.path.exists(f"{installation}/{x}"):
                with open(f"{installation}/{x}", "w") as file:
                    file.write("")
                    file.close()

        return