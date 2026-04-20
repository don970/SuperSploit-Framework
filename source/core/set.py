import json
import os
import traceback
from .errors import Error
from .ToStdOut import ToStdout

installation = f'{os.getenv("HOME")}/.SuperSploit'
db_path = f"{installation}/.data/.config/data.json" # Fixed Path

class SetV:
    @classmethod
    def SetV(cls, data):
        try:
            args = data.split()
            if len(args) < 3: # Changed from < 2 to < 3 to ensure data[2] exists
                print("[-] No arguments supplied for set\n[-] Usage: set <VARIABLE> <VALUE>\n")
                return
                
            key = args[1]
            value = args[2]
            
            # Type casting for booleans
            if value.lower() == "true":
                value = True
            elif value.lower() == "false":
                value = False

            try:
                with open(db_path, "r") as file:
                    variables = json.load(file)
            except (FileNotFoundError, json.JSONDecodeError):
                variables = {} # Create new if missing/corrupt

            # Direct assignment handles both updating AND adding new variables
            variables[key] = value

            with open(db_path, "w") as file:
                json.dump(variables, file, indent=4)
                
            print(f"[*] {key} => {value}\n")
            
        except Exception:
            Error(traceback.format_exc())