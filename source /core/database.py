# global variable
import json
import os.path
import traceback

from .errors import Error as error

global path_to_datbase
install_location = f'{os.getenv("HOME")}/.SuperSploit'
path_to_database = f"{install_location}/.data/.config/data.json"


class DatabaseManagment:

    def __init__(self):
        pass

    @classmethod
    def getCVE(cls):
        try:
            with open(cls.get()["EXPLOIT"], "r") as file:
                data = file.read().split("\n")
                file.close()
            cveCast = ""
            for x in data:
                if "CVE: CVE" in x:
                    cveCast += x
            try:
                cve = cveCast.split("CVE:")[1]
            except IndexError:
                cls.directlyModify(["CVE", None])
                return None
            Str = ""
            for x in list(cve):
                if x == " ":
                    pass
                else:
                    Str += x
            cls.directlyModify(["CVE", Str])
            return Str
        except Exception:
            return "None"

    @classmethod
    def findShells(cls):
        shells = []
        with open("/etc/shells") as file:
            data = file.read().split("\n")
            file.close()
            for x in data:
                try:
                    shells.append(x.split("/")[2])
                except Exception:
                    pass
            print(shells)
            return shells

    @classmethod
    def checkIntegration(cls) -> bool:
        with open(DatabaseManagment.get()["EXPLOIT"]) as file:
            data = file.read()
            file.close()
        if "integrated = True" in data:
            return True
        return False
    
    @classmethod
    def socketedExploit(cls):
        with open(DatabaseManagment.get()["EXPLOIT"]) as file:
            data = file.read()
            file.close()
        if "import socket" in data or "from socket import" in data:
            return True
        return False

    @classmethod
    def addVariableToDatabase(cls, data):
        try:
            if os.path.lexists(path_to_database):
                with open(path_to_database) as file:
                    database = json.load(file)
                    file.close()
                database[data.split(" ")[1]] = data.split(" ")[2]
                with open(path_to_database, "w") as file:
                    file.write(json.dumps(database, sort_keys=True, indent=4))
        except Exception:
            return

    @classmethod
    def findTerm(cls):
        term = None
        with open(f"{install_location}/.data/.config/.terminals", "r") as file:
            terms = file.read().split("\n")
            file.close()
        for x in terms:
            if x in os.listdir("/bin"):
                term = x
        return term

    @classmethod
    def directlyModify(cls, data: list):
        try:
            with open(f"{install_location}/.data/.config/data.json") as file:
                variables = json.load(file)
                file.close()

            if "CVE" in data[0]:
                variables["CVE"] = data[1]

            if "exploit" in data[0]:
                variables["EXPLOIT"] = data[1]

            if "payload" in data[0]:
                variables["PAYLOAD"] = data[1]

            if "target" in data[0]:
                variables["R_HOST"] = data[1]

            with open(f"{install_location}/.data/.config/data.json", "w") as file:
                file.write(json.dumps(variables, sort_keys=True, indent=4))
                file.close()
        except Exception:
            error(traceback.format_exc())
            return

    @classmethod
    def get(cls):
        if os.path.lexists(path_to_database):
            with open(path_to_database) as file:
                data = json.load(file)
                file.close()
            return data

    @staticmethod
    def getExploits():
        exploits = []
        for x in os.listdir(f"{install_location}/exploits/"):
            for i in os.listdir(f"{install_location}/exploits/{x}"):
                exploits.append(f"{install_location}/exploits/{x}/{i}")
        return exploits

    @staticmethod
    def getPayloads():
        exploits = []
        for x in os.listdir(f"{install_location}/payloads/"):
            for i in os.listdir(f"{install_location}/payloads/{x}"):
                exploits.append(f"{install_location}/payloads/{x}/{i}")
        return exploits