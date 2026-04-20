import json
import os
import shlex
from .database import DatabaseManagment
from .ToStdOut import ToStdout
from .exploithandler import exploitDetails

installation = f'{os.getenv("HOME")}/.SuperSploit'

class Show:
    @staticmethod
    def shells(args):
        try:
            with open('/etc/shells') as file:
                ToStdout.write(file.read() + "\n")
        except FileNotFoundError:
            ToStdout.write("[-] /etc/shells not found.\n")

    @staticmethod
    def show(data):
        args = shlex.split(data)
        
        if len(args) < 2:
            ToStdout.write("========== Showing dynamic variables ==========\n")
            for k, v in DatabaseManagment.get().items():
                ToStdout.write(f"{k}: {v}\n")
            return

        target = args[1].lower()

        if target == "details":
            exploitDetails()
            return
            
        elif target == "aliases":
            try:
                with open(f"{installation}/.data/.config/Aliases.json", "r") as file:
                    aliases = json.load(file)
                for k, v in aliases.items():
                    ToStdout.write(f"{k} = {v}\n")
            except (FileNotFoundError, json.JSONDecodeError):
                ToStdout.write("[-] Aliases file missing or corrupt.\n")
            return
            
        # If the user provides specific variables like "show R_HOST L_PORT"
        else:
            db = DatabaseManagment.get()
            requested_vars = args[1:]
            for req in requested_vars:
                if req in db:
                    ToStdout.write(f"{req}: {db[req]}\n")
                else:
                    ToStdout.write(f"[-] Variable '{req}' not set.\n")