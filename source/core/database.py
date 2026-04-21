import json
import os
import traceback
from .errors import Error as error
from .ToStdOut import ToStdout

# Framework Constants
install_location = f'{os.getenv("HOME")}/.SuperSploit'
path_to_database = f"{install_location}/.data/.config/data.json"
write = ToStdout.write

class ExploitCache:
    """Caches parsed exploit details and file locations to reduce system overhead."""
    details = {}
    all_exploits = []
    all_payloads = []

    @classmethod
    def update(cls):
        # 1. Update global file lists using DatabaseManagment helpers
        cls.all_exploits = DatabaseManagment.getExploits()
        cls.all_payloads = DatabaseManagment.getPayloads()

        # 2. Update specific details for the active exploit
        db = DatabaseManagment.get()
        if db and db.get("EXPLOIT"):
            cls._parse_details(db["EXPLOIT"])

    @classmethod
    def _parse_details(cls, path):
        if not os.path.exists(path):
            cls.details = {"path": path, "status": "missing"}
            return

        try:
            # Using encoding/errors to handle binary data safely
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                data = file.read().split("#!#!#!")
            
            if len(data) > 1:
                clean_data = data[1].lstrip('"').rstrip('"')
                # Split details from the options section
                info, options_raw = clean_data.split('# REQUIRED OPTIONS')[0], clean_data.split('# REQUIRED OPTIONS')[1]
                
                finds = []
                for line in options_raw.split("\n"):
                    if ":" in line and len(line.split(" ")) > 1:
                        finds.append(line.split(":")[0].split(" ")[1])

                cls.details = {
                    "path": path,
                    "info": info,
                    "options": finds,
                    "status": "ok"
                }
            else:
                cls.details = {"path": path, "status": "error"}
        except Exception:
            cls.details = {"status": "error"}

class exploitDetails:
    """Displays cached exploit information."""
    def __init__(self, *args):
        os.system("clear")
        cache = ExploitCache.details
        if not cache or cache.get("status") != "ok":
            write("[!] Exploit details unavailable or improperly formatted.")
            return

        write(f"[*] Exploit: {cache['path']}\nDetails:\n{cache['info']}")
        write('# REQUIRED OPTIONS')
        
        db = DatabaseManagment.get()
        for opt in cache['options']:
            if opt in db:
                write(f"{opt} = {db[opt]}")

class DatabaseManagment:

    @classmethod
    def getCVE(cls):
        """Retrieves and caches the CVE number from the active exploit file."""
        try:
            db_data = cls.get()
            if db_data.get("CVE") and db_data.get("CVE") != "None":
                return db_data["CVE"]

            exploit_path = db_data.get("EXPLOIT")
            if not exploit_path or not os.path.exists(exploit_path):
                return None

            with open(exploit_path, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    if "CVE: CVE" in line:
                        try:
                            cve = line.split("CVE:")[1].strip().replace(" ", "")
                            cls.directlyModify(["CVE", cve])
                            return cve
                        except IndexError:
                            pass
            
            cls.directlyModify(["CVE", "None"])
            return None
        except Exception:
            return "None"

    @classmethod
    def getTargets(cls):
        """Safely retrieves target list for the search module."""
        target_dict = {}
        target_file = f"{install_location}/.data/.nmap/.targets"
        if os.path.exists(target_file):
            try:
                with open(target_file, "r") as file:
                    for line in file.read().splitlines():
                        if ":" in line:
                            target, port = line.split(":", 1)
                            target_dict[target.strip()] = port.strip()
                        elif line.strip():
                            target_dict[line.strip()] = "N/A"
            except Exception:
                pass
        return target_dict

    @classmethod
    def findShells(cls):
        """Scans the system for available shells."""
        shells = []
        try:
            with open("/etc/shells", "r") as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        shells.append(os.path.basename(line))
            return shells
        except Exception:
            return []

    @classmethod
    def checkIntegration(cls) -> bool:
        """Determines if the exploit is built specifically for SuperSploit."""
        exploit_path = cls.get().get("EXPLOIT", "")
        if not exploit_path or not os.path.exists(exploit_path):
            return False
            
        with open(exploit_path, "r", encoding="utf-8", errors="ignore") as file:
            return "integrated = True" in file.read()
    
    @classmethod
    def socketedExploit(cls) -> bool:
        """Checks if the exploit uses the socket module."""
        exploit_path = cls.get().get("EXPLOIT", "")
        if not exploit_path or not os.path.exists(exploit_path):
            return False
            
        with open(exploit_path, "r", encoding="utf-8", errors="ignore") as file:
            data = file.read()
            return "import socket" in data or "from socket import" in data

    @classmethod
    def get(cls):
        """Loads the current session database."""
        if os.path.exists(path_to_database):
            try:
                with open(path_to_database, "r") as file:
                    return json.load(file)
            except Exception:
                return {}
        return {}

    @staticmethod
    def getExploits():
        """Safe directory traversal for exploits."""
        exploits = []
        base_dir = os.path.join(install_location, "exploits")
        if os.path.exists(base_dir):
            for x in os.listdir(base_dir):
                sub_dir = os.path.join(base_dir, x)
                if os.path.isdir(sub_dir):
                    for i in os.listdir(sub_dir):
                        exploits.append(os.path.join(sub_dir, i))
        return exploits

    @staticmethod
    def getPayloads():
        """Safe directory traversal for payloads."""
        payloads = []
        base_dir = os.path.join(install_location, "payloads")
        if os.path.exists(base_dir):
            for x in os.listdir(base_dir):
                sub_dir = os.path.join(base_dir, x)
                if os.path.isdir(sub_dir):
                    for i in os.listdir(sub_dir):
                        payloads.append(os.path.join(sub_dir, i))
        return payloads

    @classmethod
    def directlyModify(cls, data: list):
        """Directly writes key-value pairs to the database."""
        if len(data) != 2:
            return
            
        try:
            with open(path_to_database, "r") as file:
                variables = json.load(file)

            key_map = {
                "cve": "CVE",
                "exploit": "EXPLOIT",
                "payload": "PAYLOAD",
                "target": "R_HOST",
                "port": "R_PORT",
                "verbose": "VERBOSE_LOGGING",
            }

            for k, mapped_key in key_map.items():
                if k in data[0].lower():
                    variables[mapped_key] = data[1]

            with open(path_to_database, "w") as file:
                json.dump(variables, file, sort_keys=True, indent=4)
        except Exception:
            error(traceback.format_exc())

    @classmethod
    def getInstall(cls):
        return install_location
    
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