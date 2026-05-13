import json
import os
import shlex
from .database import DatabaseManagment
from .ToStdOut import ToStdout
from .exploithandler import exploitDetails

installation = f'{os.getenv("HOME")}/.SuperSploit'

# ASCII Art Banners for visual appeal
BANNER_DYNAMIC_VARS = r"""
 ____                                  _       _ _   
/ ___| _   _ _ __   ___ _ __ ___ _ __ | | ___ (_) |_ 
\___ \| | | | '_ \ / _ \ '__/ __| '_ \| |/ _ \| | __|
 ___) | |_| | |_) |  __/ |  \__ \ |_) | | (_) | | |_ 
|____/ \__,_| .__/ \___|_|  |___/ .__/|_|\___/|_|\__|
            |_|                 |_|                  

"""

BANNER_ALIASES = r"""
  _   _   _   _   _   _   _
 / \ / \ / \ / \ / \ / \ / \
( V | I | R | U | S | . | E )
 \_/ \_/ \_/ \_/ \_/ \_/ \_/

      _.-^^---....,,--
  _--                  --_
 <                        >)
 |                         |
  \._                   _./
"""

BANNER_SHELLS = r"""
           .-------------------------------.
         |  /-------------------------\  |
         | |                           | |
         | |                           | |
         | |       SuperSploit         | |
         | |                           | |
         | |                           | |
         | |                           | |
         | |                           | |
         |  \_________________________/  |
         |_______________________________|
       ,---\_____     []     _______/---,
      /         /______________\         \
     /_____________________________________\
     |                                     |
     |  _________________________________  |
     | | ||_|| ||_|| ||_|| ||_|| ||_|| ||_|| |
     | |_________________________________| |
     |_____________________________________|
"""


class Show:
    @staticmethod
    def shells(args):
        ToStdout.write(BANNER_SHELLS + "\n")
        try:
            with open('/etc/shells') as file:
                ToStdout.write(file.read() + "\n")
        except FileNotFoundError:
            ToStdout.write("[-] Error: /etc/shells not found.\n")
        ToStdout.write("-" * 40 + "\n")  # Footer for consistency

    @staticmethod
    def show(data):
        args = shlex.split(data)

        if len(args) < 2:
            Show._show_dynamic_variables()
            return

        target = args[1].lower()

        if target == "details":
            # Assuming exploitDetails() handles its own output.
            # Adding a simple header/footer for context.
            ToStdout.write("\n" + "=" * 10 + " Exploit Details " + "=" * 10 + "\n")
            exploitDetails()
            ToStdout.write("=" * 37 + "\n")  # Footer matching header length
            return

        elif target == "aliases":
            Show._show_aliases()
            return

        # If the user provides specific variables like "show R_HOST L_PORT"
        else:
            Show._show_specific_variables(args[1:])

    @staticmethod
    def _show_dynamic_variables():
        """Displays all currently set dynamic variables with an ASCII art banner."""
        ToStdout.write(BANNER_DYNAMIC_VARS + "\n")
        db = DatabaseManagment.get()
        if not db:
            ToStdout.write("  No dynamic variables currently set.\n")
        else:
            # Determine max key length for aligned output
            max_key_len = max(len(k) for k in db.keys()) if db else 0
            for k, v in db.items():
                if len(str(v)) > 100:
                    ToStdout.write(f"  {k:<{max_key_len}}: {str(v)[:47]}...\n")
                else:
                    ToStdout.write(f"  {k:<{max_key_len}}: {v}\n")
        ToStdout.write("-" * 40 + "\n")  # Footer

    @staticmethod
    def _show_aliases():
        """Displays all configured aliases with an ASCII art banner."""
        ToStdout.write(BANNER_ALIASES + "\n")
        try:
            with open(f"{installation}/.data/.config/Aliases.json", "r") as file:
                aliases = json.load(file)
            if not aliases:
                ToStdout.write("  No aliases currently defined.\n")
            else:
                # Determine max key length for aligned output
                max_key_len = max(len(k) for k in aliases.keys()) if aliases else 0
                for k, v in aliases.items():
                    ToStdout.write(f"  {k:<{max_key_len}}: {v}\n")
        except FileNotFoundError:
            ToStdout.write(f"[-] Error: Aliases file not found at {installation}/.data/.config/Aliases.json\n")
        except json.JSONDecodeError:
            ToStdout.write("[-] Error: Aliases file is corrupt or malformed JSON.\n")
        ToStdout.write("-" * 40 + "\n")  # Footer

    @staticmethod
    def _show_specific_variables(requested_vars):
        """Displays specific dynamic variables requested by the user."""
        ToStdout.write(BANNER_DYNAMIC_VARS + "\n")  # Re-use banner for specific variables
        db = DatabaseManagment.get()
        max_key_len = max(len(req) for req in requested_vars) if requested_vars else 0

        for req in requested_vars:
            if req in db:
                ToStdout.write(f"  {req:<{max_key_len}}: {db[req]}\n")
            else:
                ToStdout.write(f"  {req:<{max_key_len}}: [-] Variable '{req}' not set.\n")
        ToStdout.write("-" * 40 + "\n")  # Footer