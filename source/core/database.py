import json
import os
import traceback
from .errors import Error as error
from .ToStdOut import ToStdout
import yaml

# Framework Constants
install_location = f'{os.getenv("HOME")}/.SuperSploit'
path_to_database = f"{install_location}/.data/.config/data.json"
write = ToStdout.write


class ExploitCache:
    """Manages memory-resident YAML metadata for all framework modules."""
    details = {}
    metadata_index = {} # Maps path -> YAML metadata summary
    all_exploits = []
    all_payloads = []

    @classmethod
    def update(cls):
        # 1. Update file lists
        cls.all_exploits = DatabaseManagment.getExploits()
        cls.all_payloads = DatabaseManagment.getPayloads()

        # 2. Index all metadata for the search engine
        for path in cls.all_exploits + cls.all_payloads:
            if path not in cls.metadata_index:
                cls.metadata_index[path] = cls._quick_parse(path)

        # 3. Cache the active exploit's full details
        db = DatabaseManagment.get()
        if db and db.get("EXPLOIT"):
            cls._parse_details(db["EXPLOIT"])

    @classmethod
    def _quick_parse(cls, path):
        """Extracts basic metadata for search indexing without loading the full file."""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                data = file.read().split("#!#!#!")
                if len(data) > 1:
                    meta = yaml.safe_load(data[1])
                    return {
                        "name": meta.get("name", os.path.basename(path)),
                        "cve": meta.get("cve", "N/A"),
                        "desc": meta.get("description", "").lower()
                    }
        except Exception:
            pass
        return {"name": os.path.basename(path), "cve": "N/A", "desc": ""}

    @classmethod
    def _parse_details(cls, path):
        """Full YAML parser for the 'info' command."""
        if not os.path.exists(path):
            cls.details = {"status": "missing"}
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                data = file.read().split("#!#!#!")
            if len(data) > 1:
                meta = yaml.safe_load(data[1])
                cls.details = {
                    "path": path,
                    "name": meta.get("name", "Unknown"),
                    "info": meta.get("description", "No description provided."),
                    "options": meta.get("options", []),
                    "cve": meta.get("cve", "N/A"),
                    "status": "ok"
                }
        except Exception:
            cls.details = {"status": "error"}

class exploitDetails:
    
    def __init__(self, *args):
        os.system("clear")
        cache = ExploitCache.details
        if not cache or cache.get("status") != "ok":
            write("[!] Select a valid exploit first.")
            return

        write(f"[*] Exploit:     {cache['name']}")
        write(f"[*] CVE:         {cache['cve']}")
        write(f"[*] Description: {cache['info']}")
        write("\n# REQUIRED OPTIONS")
        db = DatabaseManagment.get()
        for opt in cache['options']:
            write(f"{opt} = {db.get(opt, '[NOT SET]')}")

class DatabaseManagment:
    
    @classmethod
    def getCVE(cls):
        """Retrieves the CVE from the current memory cache."""
        cache = ExploitCache.details
        if cache and cache.get("status") == "ok":
            cve = cache.get("cve", "None")
            # Keep the database in sync for the banner
            cls.directlyModify(["CVE", cve])
            return cve
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