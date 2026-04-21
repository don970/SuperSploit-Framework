import json
import os
import traceback
from .errors import Error as error

install_location = f'{os.getenv("HOME")}/.SuperSploit'
path_to_database = f"{install_location}/.data/.config/data.json"

class DatabaseManagment:

    @classmethod
    def getCVE(cls):
        try:
            db_data = cls.get()
            # If CVE is already cached in database, return it immediately to save disk I/O
            if db_data.get("CVE") and db_data.get("CVE") != "None":
                return db_data["CVE"]

            exploit_path = db_data.get("EXPLOIT")
            if not exploit_path or not os.path.exists(exploit_path):
                return None

            with open(exploit_path, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    if "CVE: CVE" in line:
                        try:
                            # Parse out spaces
                            cve = line.split("CVE:")[1].strip().replace(" ", "")
                            cls.directlyModify(["CVE", cve])
                            return cve
                        except IndexError:
                            pass
            
            # If not found
            cls.directlyModify(["CVE", "None"])
            return None
        except Exception:
            return "None"

    @classmethod
    def findShells(cls):
        shells = []
        try:
            with open("/etc/shells", "r") as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Fix: Safely extract the final component of the path
                        shells.append(os.path.basename(line))
            return shells
        except Exception:
            return []

    @classmethod
    def checkIntegration(cls) -> bool:
        exploit_path = cls.get().get("EXPLOIT", "")
        if not exploit_path or not os.path.exists(exploit_path):
            return False
            
        with open(exploit_path, "r", encoding="utf-8", errors="ignore") as file:
            return "integrated = True" in file.read()
    
    @classmethod
    def socketedExploit(cls) -> bool:
        exploit_path = cls.get().get("EXPLOIT", "")
        if not exploit_path or not os.path.exists(exploit_path):
            return False
            
        with open(exploit_path, "r", encoding="utf-8", errors="ignore") as file:
            data = file.read()
            return "import socket" in data or "from socket import" in data

    @classmethod
    def addVariableToDatabase(cls, data):
        parts = data.split(" ", 2)
        if len(parts) < 3:
            help_path = f"{install_location}/.data/.help/add"
            if os.path.exists(help_path):
                with open(help_path, 'r') as file:
                    print(file.read())
            return
            
        try:
            if os.path.exists(path_to_database):
                with open(path_to_database, "r") as file:
                    database = json.load(file)
                
                database[parts[1]] = parts[2]
                
                with open(path_to_database, "w") as file:
                    json.dump(database, file, sort_keys=True, indent=4)
        except Exception as e:
            print(f"[-] Database Error: {e}")

    @classmethod
    def findTerm(cls):
        try:
            with open(f"{install_location}/.data/.config/.terminals", "r") as file:
                terms = [line.strip() for line in file if line.strip()]
                
            bin_files = set(os.listdir("/bin"))
            for term in terms:
                if term in bin_files:
                    return term
        except Exception:
            pass
        return None

    @classmethod
    def directlyModify(cls, data: list):
        if len(data) != 2:
            return
            
        try:
            with open(path_to_database, "r") as file:
                variables = json.load(file)

            key_map = {
                "CVE": "CVE",
                "exploit": "EXPLOIT",
                "payload": "PAYLOAD",
                "target": "R_HOST",
                "port": "R_PORT",
                "verbose": "VERBOSE_LOGGING",
            }

            # Map the lowercase input request to the exact JSON key
            for k, mapped_key in key_map.items():
                if k in data[0].lower():
                    variables[mapped_key] = data[1]

            with open(path_to_database, "w") as file:
                json.dump(variables, file, sort_keys=True, indent=4)
        except Exception:
            error(traceback.format_exc())

    @classmethod
    def get(cls):
        if os.path.exists(path_to_database):
            with open(path_to_database, "r") as file:
                return json.load(file)
        return {}

    @staticmethod
    def getExploits():
        exploits = []
        base_dir = f"{install_location}/exploits/"
        if os.path.exists(base_dir):
            for x in os.listdir(base_dir):
                sub_dir = os.path.join(base_dir, x)
                if os.path.isdir(sub_dir):
                    for i in os.listdir(sub_dir):
                        exploits.append(os.path.join(sub_dir, i))
        return exploits

    @staticmethod
    def getPayloads():
        payloads = []
        base_dir = f"{install_location}/payloads/"
        if os.path.exists(base_dir):
            for x in os.listdir(base_dir):
                sub_dir = os.path.join(base_dir, x)
                if os.path.isdir(sub_dir):
                    for i in os.listdir(sub_dir):
                        payloads.append(os.path.join(sub_dir, i))
        return payloads