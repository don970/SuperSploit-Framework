import os
import subprocess
import sys
import traceback
import tempfile
import shlex
import types
from .logger import Logger
from .database import DatabaseManagment

install = DatabaseManagment.getInstall()


class Recon:
    """
    Handles the loading, parsing, and execution of reconnaissance modules.
    Securely isolates root-required modules via isolated sudo subprocesses
    and dynamically loads standard modules into memory using cleaned buffers.
    """

    def __init__(self, args=None):
        # Fetch the absolute latest database state
        self.db = DatabaseManagment.get()

        # Clean the raw file of metadata and create a buffer for execution
        self.buffer, self.metadata = self.createBuffer()

        # Determine if root is needed via metadata flag
        self.requires_root = "root: " in self.metadata

        if self.requires_root:
            print("[*] Metadata indicates ROOT privileges are required.")
            self.exec_with_sub(self.buffer, use_sudo=True)
        else:
            # Standard prompt for non-root scripts
            self.module = False if input("[*] Run as a module in python [y/n]: ").lower().startswith("n") else True
            if not self.module:
                self.exec_with_sub(self.buffer, use_sudo=False)
            else:
                self.run()

        DatabaseManagment._update(self.db)

    def run(self):
        """Dynamically loads the cleaned script buffer into memory as a standard user."""
        print("[*] Running in memory as standard user...")

        # Safe argument parsing
        user_input = input(f'[*] Enter arguments for {self.db["RECON_PATH"]}: ')
        args = shlex.split(user_input)

        # Dynamic namespace to prevent collisions if multiple modules run
        module_namespace = f"recon_dynamic_{self.db['RECON_NAME']}"

        # 1. Create a blank, dynamic module object
        recon_module = types.ModuleType(module_namespace)

        # 2. Add it to sys.modules so it acts like a real loaded module
        sys.modules[module_namespace] = recon_module

        try:
            # 3. Execute the CLEANED buffer directly into the module's dictionary
            # This completely ignores the uncleaned file on the hard drive
            exec(self.buffer, recon_module.__dict__)

            if len(args) == 0:
                recon_module.Start()
            else:
                recon_module.Start(args)

        except Exception:
            # Log the exception, but do NOT fall back to a risky subprocess execution
            Logger.initializeReconMoodle(self.db["RECON_NAME"], self.db["RECON_PATH"], traceback.format_exc())
            print(f"[*] In-memory execution failed:\n{traceback.format_exc()}")

        finally:
            if module_namespace in sys.modules:
                del sys.modules[module_namespace]
            print("[*] Clean up complete")

    def createBuffer(self):
        """Reads the recon file and strips out the metadata section delimited by '#!#!#!'."""
        with open(self.db["RECON_PATH"], "r") as file:
            raw_data = file.read().split("#!#!#!")

        if len(raw_data) >= 3:
            metadata = raw_data[1]
            clean_buffer = raw_data[0] + raw_data[2]
        else:
            metadata = ""
            clean_buffer = raw_data[0]

        return clean_buffer, metadata

    def exec_with_sub(self, clean_buffer, use_sudo=False):
        """Securely executes the cleaned module via a temporary file and subprocess."""

        # Use NamedTemporaryFile to prevent static-path race conditions
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
            tmp.write(clean_buffer)
            temp_exec_path = tmp.name

        try:
            # Sanitize arguments via shlex to prevent shell injection
            user_input = input(f'[*] Enter arguments for {self.db["RECON_NAME"]}: ')
            args = shlex.split(user_input)

            # Isolated Python Mode (-I) prevents PYTHONPATH environment hijacking
            if use_sudo:
                print(f"[*] Executing {self.db['RECON_NAME']} via isolated sudo subprocess...")
                cmd = ["sudo", "python3", "-I", temp_exec_path] + args
            else:
                print(f"[*] Executing {self.db['RECON_NAME']} via isolated subprocess...")
                cmd = ["python3", "-I", temp_exec_path] + args

            # check=True properly catches if the script itself crashes
            subprocess.run(cmd, check=True)

        except subprocess.CalledProcessError as e:
            print(f"[*] Target script crashed or exited with error code: {e.returncode}")
        except Exception as e:
            print(f"[*] Subprocess failed to launch: {e}")
            Logger.initializeReconMoodle(self.db["RECON_NAME"], self.db["RECON_PATH"], traceback.format_exc())
        finally:
            # Ensure the temporary execution file is ALWAYS cleaned up
            if os.path.exists(temp_exec_path):
                os.remove(temp_exec_path)