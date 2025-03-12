from .ToStdOut import ToStdout
print = ToStdout.write

class clean:
    def __init__(self, ar):
        print("[*] Doing a full clean. Clearing history, error log along with all scan and target data.")
        with open(".data/.personSearch", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.phoneinfoga.scan", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.errors/error.log", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.history/history", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.nmap/.custom_scan", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.phone_numbers", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.nmap/.targeted_scan", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.nmap/.targets", "w") as file:
            file.write(" ")
            file.close()
        with open(".data/.passwords", "w") as file:
            file.write(" ")
            file.close()

        return