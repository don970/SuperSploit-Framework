import os
import subprocess
import sys
import traceback
from .logger import Logger
from .database import DatabaseManagment
import importlib

install = DatabaseManagment.getInstall()

class Recon:
    """
    Handles the loading, parsing, and execution of reconnaissance modules.
    Modules can be executed directly as a Python module in memory or via an external subprocess.
    memory is the preferred method
    """

    def __init__(self, args=None):
        # Fetch the absolute latest database state on every initialization
        self.db = DatabaseManagment.get()

        # Prompt the user to determine the execution method
        self.module = False if input("[*] Run as a module in python [y/n]: ").lower().startswith("n") else True

        # Fetch the recon name from the database (Note: this variable is currently unused)
        name = self.db["RECON_NAME"]

        # Clean the raw file of metadata and create a buffer for execution
        self.buffer, self.metadata = self.createBuffer()

        # If the user chose not to run as a module, execute it via subprocess immediately
        if not self.module:
            self.exec_with_sub(self.buffer)
            DatabaseManagment._update(self.db)
            return
        self.run()
        DatabaseManagment._update(self.db)
        return




    def run(self):
        """Dynamically loads the recon script into memory as a module and executes its Start() method."""
        print("[*] Running as a python module")
        args = input(f'[*] Enter arguments for {self.db["RECON_PATH"]}: ').split(" ")

        # Dynamically load the python file from the path specified in the database
        spec = importlib.util.spec_from_file_location("recon_module", self.db["RECON_PATH"])
        recon_module = importlib.util.module_from_spec(spec)
        sys.modules["recon_module"] = recon_module
        spec.loader.exec_module(recon_module)
        try:
            # Execute the Start function of the module, passing arguments if they were provided
            if len(args) < 1 or args[0] == "":
                recon_module.Start()
                return
            recon_module.Start(args)
        except Exception:
            # Log the exception if the module fails to run
            Logger.initializeReconMoodle(self.db["RECON_NAME"], self.db["RECON_PATH"], traceback.format_exc())
            print(traceback.format_exc())
        finally:
            del sys.modules["recon_module"]
            print("clean up complete")

    def createBuffer(self):
        """Reads the recon file and strips out the metadata section delimited by '#!#!#!'."""
        with open(self.db["RECON_PATH"], "r") as file:
            raw_data = file.read().split("#!#!#!")

        # The metadata is expected to be in the second section (index 1)
        metadata = raw_data[1]

        # Reconstruct the code by removing the metadata section (index 1)
        if len(raw_data) >= 3:
            # Join everything EXCEPT the metadata block
            clean_buffer = raw_data[0] + raw_data[2]
        else:
            # If no delimiters found, use the first part
            clean_buffer = raw_data[0]
        return clean_buffer, metadata

    def exec_with_sub(self, clean_buffer):
        """Writes the cleaned module to a temporary file and executes it via a separate subprocess."""
        # Define a consistent temporary path for execution
        temp_exec_path = f"{install}/source/core/exploit/recon_module.py"
        with open(temp_exec_path, "w") as file1:
            try:
                file1.write(clean_buffer)
                # Subprocess execution using the CLEANED file
                # Note: db["EXPLOIT"] is used here. Double-check if this shouldn't be db["RECON_NAME"] instead
                args = input(f'[*] Enter arguments for {self.db["RECON_NAME"]}: ').split(" ")

                # Build the command array for the subprocess
                cmd = [f"python3", temp_exec_path]
                for x in args:
                    if len(x) > 0:
                        cmd.append(x)

                print(f"[*] Executing {self.db['RECON_NAME']} via subprocess...")
                subprocess.run(cmd)
            except OSError:
                return traceback.format_exc()
            finally:
                # Ensure the temporary execution file is always cleaned up, even if an error occurs
                if os.path.exists(temp_exec_path):
                    os.remove(temp_exec_path)
