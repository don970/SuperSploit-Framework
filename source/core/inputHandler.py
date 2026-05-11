import os
import traceback
import subprocess
import psutil
import socket
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from .encrypter import Encrypter
from .errors import Error
from .ToStdOut import ToStdout
from .help import Help
from .show import Show
from .set import SetV
from .use import use
from .search import Search
from .banners import Banners
from .inputfixes import Input_fixes
from .sessions import Sessions
from .clean import clean
from .database import DatabaseManagment, ExploitCache, exploitDetails
from .exploithandler import ExploitHandler
import shlex
from .listener import Listener
from .recon_engien import Recon
from .auto_suggest import AutoSuggestCommand as ASC

# set global variables
installation = DatabaseManagment.getInstall()
history = FileHistory(f'{installation}/.data/.history/history')
path = os.getenv("PATH", "").split(os.pathsep)
env = os.environ
Aliases = DatabaseManagment._UpdateAliases()


def get_network_info():
    host = socket.gethostname()
    # Iterate through all network interfaces
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            # Look for IPv4 addresses and ignore loopback (127.0.0.1)
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return addr.address, addr.netmask, host
    return None


class Input:

    @classmethod
    def _update(cls, data=None):
        ExploitCache.update()
        DatabaseManagment._UpdateAliases()

    @classmethod
    def _system_call(cls, cmd_list):
        """Executes a command by searching for it in the system's PATH."""
        try:
            command_name = cmd_list[0]
            for directory in path:
                if os.path.exists(os.path.join(directory, command_name)):
                    subprocess.run(cmd_list)
                    return True

            Error(f"[!] Program not found: {command_name}")
            return False
        except OSError as e:
            ToStdout.write(f"OS Error during system call: {e}\n{traceback.format_exc()}")
            return False

    @classmethod
    def _auto_suggest(cls, data=None):
        db_data = DatabaseManagment.get()
        args = shlex.split(data) if data else []
        # Extract target IP from arguments or fallback to database context
        target_ip = args[1] if len(args) > 1 else db_data.get('R_HOST', db_data.get('TARGET', 'unknown'))
        target_open_ports = db_data.get('open_ports', db_data.get('ports', []))
        
        suggester = ASC(ExploitCache)
        suggester.execute(target_ip, target_open_ports)

    @classmethod
    def check(cls, data):
        # Sanitize and handle empty input
        clean_data = data.strip()
        if not clean_data:
            return

        # Tokenize and apply aliases
        try:
            dataList = shlex.split(clean_data)
            if not dataList:
                return

            for i, token in enumerate(dataList):
                if token in Aliases:
                    dataList[i] = Aliases[token]
        except ValueError as e:
            Error(f"Failed to parse command: {e}")
            return

        # create a list to check for input fixes
        inputFixList = ["cd", "clear", "exit", "cat"]

        try:
            # Handle empty inputs (hitting Enter) gracefully
            if not dataList:
                return

            if "&&" in clean_data:
                fix = Input_fixes.continues(clean_data)
                if fix == 0:
                    return
                else:
                    data = fix[len(fix) - 1]
                    dataList = data.split(' ')
            if ">" in clean_data:
                Input_fixes.out(clean_data)
                return

            cmd_name = dataList[0]
            if cmd_name in inputFixList:
                if Input_fixes(dataList):
                    return
            # ==========================================
            # COMMAND REGISTRIES
            # ==========================================
            general_cmds = {
                "decrypt": Encrypter.decrypt_file,
                "encrypt": Encrypter.encrypt_file,
                "clean": clean,
                "shells": Show.shells,
                "help": Help.display,
                "show": Show.show,
                "set": SetV.SetV,
                "exploit": ExploitHandler,
                "use": use.execute,
                "search": Search.search,
                "banner": Banners,
                "add": DatabaseManagment.addVariableToDatabase,
                "update-info": cls._update,
                "info": exploitDetails,
                "debugdb": DatabaseManagment.Debug,
                "run": Recon,
                "sessions": Sessions.manage,
                "auto_suggest": cls._auto_suggest
            }

            # ==========================================
            # COMMAND EXECUTION ROUTER
            # ==========================================
            try:
                if cmd_name in general_cmds:
                    general_cmds[cmd_name](data)
                    DatabaseManagment._update(DatabaseManagment.get())

                    # Trigger background shell listener if set
                    if cmd_name == "set" and len(dataList) >= 3:
                        if dataList[1].lower() == "listener" and dataList[2].lower() == "true":
                            Listener.start(DatabaseManagment.get())

                    # Trigger Recon Automation auto_suggest if enabled
                    if cmd_name == "run" and DatabaseManagment.get().get("auto_suggest", "").lower() == "true":
                        cls._auto_suggest()

                    return True
                else:
                    # If not an internal command, treat as a system call
                    return cls._system_call(dataList)

            except Exception:
                Error(traceback.format_exc())
                return False
        except Exception:
            Error(traceback.format_exc())
            return False

    @classmethod
    def get(cls):
        # Start background listener automatically on startup if configured
        initial_db = DatabaseManagment.get()
        if str(initial_db.get("listener", "")).lower() == "true":
            Listener.start(initial_db)

        Banners(None)
        while True:
            DatabaseManagment.getCVE()
            # Refresh the memory cache from the database module
            ExploitCache.update()
            data = DatabaseManagment.get()
            try:
                session = PromptSession(history=history, auto_suggest=AutoSuggestFromHistory(), enable_history_search=True)
                inp = session.prompt(f"[SuperSploit]: ")
                cls.check(inp)
            except (KeyboardInterrupt, EOFError):
                DatabaseManagment._update(data)
                ToStdout.write("\n[*] Exiting SuperSploit...\n")
                break
            except Exception:
                Error(traceback.format_exc())
                continue