"""
Core Database and Cache Management Module
Handles file system traversals, YAML metadata extraction, and JSON configuration database interactions.
"""
import json
import os
import pathlib
import traceback
from .errors import Error as error
from .ToStdOut import ToStdout
import yaml

# Framework Constants
# Base installation directory for the framework
install_location = f'{os.getenv("HOME")}/.SuperSploit'
# Absolute path to the main configuration/session JSON database
path_to_database = f"{install_location}/.data/.config/data.json"
# Alias for the standard output writing function
write = ToStdout.write


class ExploitCache:
    """Manages memory-resident YAML metadata for all framework modules."""
    # Holds detailed info for the currently active exploit
    details = {}
    metadata_index = {} # Maps path -> YAML metadata summary
    all_exploits = []
    all_payloads = []

    @classmethod
    def update(cls, data=None):
        """Updates the exploit/payload file lists and rebuilds the metadata cache."""
        # 1. Update file lists from the filesystem
        cls.all_exploits = DatabaseManagment.getExploits()
        cls.all_payloads = DatabaseManagment.getPayloads()

        # 2. Index all metadata for the search engine to prevent loading during search
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
                # Split based on the custom delimiter to separate code from YAML metadata
                data = file.read().split("#!#!#!")
                if len(data) > 1:
                    # Parse the YAML block
                    meta = yaml.safe_load(data[1])
                    return {
                        "name": meta.get("name", os.path.basename(path)),
                        "cve": meta.get("cve", "N/A"),
                        "desc": meta.get("description", "").lower(),
                        "target": meta.get("target", "")
                    }
        except Exception:
            pass
        return {"name": os.path.basename(path), "cve": "N/A", "desc": ""}

    @classmethod
    def _parse_details(cls, path):
        """Full YAML parser for the 'info' command."""
        if not os.path.exists(path):
            # Mark as missing if the exploit file was removed or path is invalid
            cls.details = {"status": "missing"}
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                # Split to isolate the YAML metadata section
                data = file.read().split("#!#!#!")
            if len(data) > 1:
                meta = yaml.safe_load(data[1])
                # Populate the details dictionary with all relevant exploit properties
                cls.details = {
                    "path": path,
                    "name": meta.get("name", "Unknown"),
                    "info": meta.get("description", "No description provided."),
                    "options": meta.get("options", []),
                    "cve": meta.get("cve", "N/A"),
                    "target": meta.get("target", ""),
                    "Android Version": meta.get("Android_Version", ""),
                    "Android ID": meta.get("Android_ID", ""),
                    "status": "ok"
                }
        except Exception:
            cls.details = {"status": "error"}

class exploitDetails:
    """Handles the display of currently selected exploit metadata."""

    def __init__(self, *args):
        """Initializes the display, clearing the terminal and printing the cached exploit information."""
        os.system("clear")
        cache = ExploitCache.details
        # Validate that an exploit is selected and its cache loaded successfully
        if not cache or cache.get("status") != "ok":
            write("[!] Select a valid exploit first.")
            return

        # Print the core exploit details header
        write(f"[*] Exploit:     {cache['name']}")
        write(f"[*] CVE:         {cache['cve']}")
        write(f"[*] Description: {cache['info']}")
        write(f"==================================")

        db = DatabaseManagment.get()
        # Dynamically print out all available options mapped in the cache
        for opt, value in cache.items():
            write(f"{opt} = {value}")

class DatabaseManagment:
    aliases = {}
    db = {}
    """
    Centralized utility for reading/writing configuration state
    and mapping module paths across the framework.
    """

    @classmethod
    def getCVE(cls):
        """Retrieves the CVE from the current memory cache and syncs it to the JSON database."""
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
                        # Handle targets defined with specific ports (e.g., IP:PORT)
                        if ":" in line:
                            target, port = line.split(":", 1)
                            target_dict[target.strip()] = port.strip()
                        # Handle targets defined without ports
                        elif line.strip():
                            target_dict[line.strip()] = "N/A"
            except Exception:
                pass
        return target_dict

    @classmethod
    def checkIntegration(cls) -> bool:
        """Determines if the exploit is built specifically for SuperSploit."""
        exploit_path = cls.get().get("EXPLOIT", "")
        if not exploit_path or not os.path.exists(exploit_path):
            return False
            
        # Scan the file for the specific integration variable flag
        with open(exploit_path, "r", encoding="utf-8", errors="ignore") as file:
            return "integrated = True" in file.read()
    
    @classmethod
    def socketedExploit(cls) -> bool:
        """Checks if the exploit uses the socket module."""
        exploit_path = cls.get().get("EXPLOIT", "")
        if not exploit_path or not os.path.exists(exploit_path):
            return False
            
        # Identify if the exploit script imports the native socket module
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
            # Iterate through categories (e.g., windows, linux, android)
            for x in os.listdir(base_dir):
                sub_dir = os.path.join(base_dir, x)
                if os.path.isdir(sub_dir):
                    # Collect individual exploit script paths inside each category
                    for i in os.listdir(sub_dir):
                        exploits.append(os.path.join(sub_dir, i))
        return exploits

    @staticmethod
    def getPayloads():
        """Safe directory traversal for payloads."""
        payloads = []
        base_dir = os.path.join(install_location, "payloads")
        if os.path.exists(base_dir):
            # Iterate through payload categories
            for x in os.listdir(base_dir):
                sub_dir = os.path.join(base_dir, x)
                if os.path.isdir(sub_dir):
                    # Collect individual payload script paths
                    for i in os.listdir(sub_dir):
                        payloads.append(os.path.join(sub_dir, i))
        return payloads

    @classmethod
    def directlyModify(cls, data: list):
        """Directly writes key-value pairs to the database."""
        if len(data) != 2:
            return
            
        try:
            # Read current configurations
            with open(path_to_database, "r") as file:
                variables = json.load(file)

            # Map incoming human-readable keys to internal JSON database keys
            key_map = {
                "cve": "CVE",
                "exploit": "EXPLOIT",
                "payload": "PAYLOAD",
                "target": "R_HOST",
                "port": "R_PORT",
                "verbose": "VERBOSE_LOGGING",
                "dev_mode": "DEV_MODE" ,
                "sessionId": "SESSION_ID",
                "recon_name": "RECON_NAME",
                "recon_path": "RECON_PATH"
            }

            # Update the mapped key if it matches the first item in the input data
            for k, mapped_key in key_map.items():
                if k in data[0].lower():
                    variables[mapped_key] = data[1]

            # Write changes back to the database
            with open(path_to_database, "w") as file:
                json.dump(variables, file, sort_keys=True, indent=4)
        except Exception:
            error(traceback.format_exc())

    @classmethod
    def getInstall(cls):
        if not cls.get()["DEV_MODE"]:
            """Returns the framework's base installation path."""
            return install_location
        return cls.get()["DEV_DICT"]
    
    @classmethod
    def addVariableToDatabase(cls, data):
        """Parses a command string to add a custom variable to the JSON database."""
        # Expects format: "command key value"
        parts = data.split(" ", 2)
        if len(parts) < 3:
            # Print the help menu if the arguments are incomplete
            help_path = f"{install_location}/.data/.help/add"
            if os.path.exists(help_path):
                with open(help_path, 'r') as file:
                    print(file.read())
            return
            
        try:
            if os.path.exists(path_to_database):
                # Load existing database state
                with open(path_to_database, "r") as file:
                    database = json.load(file)
                
                # Set the key-value pair dynamically
                database[parts[1]] = parts[2]
                
                # Save changes back to the file
                with open(path_to_database, "w") as file:
                    json.dump(database, file, sort_keys=True, indent=4)
        except Exception as e:
            print(f"[-] Database Error: {e}")

    @classmethod
    def findTerm(cls):
        """Locates an available terminal emulator on the host system based on a predefined list."""
        try:
            # Read preferred terminals list
            with open(f"{install_location}/.data/.config/.terminals", "r") as file:
                terms = [line.strip() for line in file if line.strip()]
                
            bin_files = set(os.listdir("/bin"))
            # Return the first terminal emulator that exists in /bin
            for term in terms:
                if term in bin_files:
                    return term
        except Exception:
            pass
        return None
    
    @classmethod
    def Debug(cls, data=None):
        """Dumps all primary data structures to standard output for debugging purposes."""
        db = cls.get()
        targets = cls.getTargets()
        payloads = cls.getPayloads()
        exploitdetails = ExploitCache.details
        exploitcache = ExploitCache.metadata_index
        
        print(json.dumps(db, indent=4))
        print(json.dumps(targets, indent=4))
        print(json.dumps(payloads, indent=4))
        print(json.dumps(exploitdetails, indent=4))
        print(json.dumps(exploitcache, indent=4))

    @classmethod
    def _UpdateAliases(cls):
        if len(cls.aliases) > 0:
            write("[*] Using cached aliases database")
            return cls.aliases
        try:
            write("[*] initial launch loading database in to memory")
            with open(f"{install_location}/.data/.config/Aliases.json", "rb") as f:
                cls.aliases = json.load(f)
                return cls.aliases
        except FileNotFoundError:
            write("[!] Error: Aliases.json not found.")
            return 1

    @classmethod
    def _getAliases(cls):
        return cls.aliases

    @classmethod
    def UpdateReconDB(cls):
        db = cls.db
        allfiles = []
        for x in os.listdir(f"{install_location}/recon"):
            files = []
            for i in os.listdir(f"{install_location}/recon/{x}"):
                allfiles.append(f"{install_location}/recon/{x}/{i}")
                files.append(f"{install_location}/recon/{x}/{i}")
            db[x] = files
        return db, allfiles

    @classmethod
    def _reconDB(cls):
        return cls.db
