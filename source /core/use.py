import os

from .database import DatabaseManagment

installation = f'{os.getenv("HOME")}/.SuperSploit'

class use:
    def __init__(self, data):
        targetList = []
        data = data.split(" ")
        exploits = DatabaseManagment.getExploits()
        payloads = DatabaseManagment.getPayloads()
        data[2] = int(data[2])
        if data[1] == "exploit":
            DatabaseManagment.directlyModify([data[1], exploits[data[2]]])
        elif data[1] == "target":
            with open(f"{installation}/.data/.targets") as file:
                print("[*] setting R_HOST via target file. ")
                for x in file.read().split("\n"):
                    targetList.append(x)
                file.close()
            DatabaseManagment.directlyModify([data[1], targetList[data[2]]])
        else:
            DatabaseManagment.directlyModify([data[1], payloads[data[2]]])
        pass