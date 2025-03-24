from .ToStdOut import ToStdout
print = ToStdout.write

class clean:
    def __init__(self, ar):
        print("[*] Doing a full clean. Clearing history, error log along with all scan and target data.")
        with open(".data/scans/.personSearch", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/scans/phoneinfoga.scan", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.errors/error.log", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.history/history", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.nmap/custom_scan", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/scans/phone_numbers", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.nmap/targeted_scan", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.nmap/.targets", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/loot/.passwords", "w") as file:
            file.write(" ")
            file.close()

        return