import os
from .database import DatabaseManagment
from .ToStdOut import ToStdout

installation = f'{os.getenv("HOME")}/.SuperSploit'
print = ToStdout.write

class use:
    @classmethod
    def execute(cls, data):
        args = data.split()
        if len(args) < 3:
            print("[-] Usage: use <exploit|target|payload> <index>\n")
            return
            
        category = args[1].lower()
        
        try:
            index = int(args[2])
        except ValueError:
            print("[-] Error: Index must be a number.\n")
            return

        if category == "exploit":
            exploits = DatabaseManagment.getExploits()
            if 0 <= index < len(exploits):
                DatabaseManagment.directlyModify(["exploit", exploits[index]])
                print(f"[*] Set exploit to {exploits[index]}\n")
            else:
                print("[-] Invalid exploit index.\n")
                
        elif category == "target":
            try:
                with open(f"{installation}/.data/.targets", "r") as file:
                    targetList = [x for x in file.read().split("\n") if x]
                if 0 <= index < len(targetList):
                    DatabaseManagment.directlyModify(["target", targetList[index]])
                    print(f"[*] Set target to {targetList[index]}\n")
                else:
                    print("[-] Invalid target index.\n")
            except FileNotFoundError:
                print("[-] Targets file not found.\n")
                
        elif category == "payload":
            payloads = DatabaseManagment.getPayloads()
            if 0 <= index < len(payloads):
                DatabaseManagment.directlyModify(["payload", payloads[index]])
                print(f"[*] Set payload to {payloads[index]}\n")
            else:
                print("[-] Invalid payload index.\n")
        else:
            print(f"[-] Unknown category: {category}\n")