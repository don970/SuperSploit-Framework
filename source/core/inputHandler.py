import json
import os
import traceback
import subprocess
from encodings.aliases import aliases

import psutil
import socket
from subprocess import PIPE
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
from .clean import clean
from .exploithandler import ExploitHandler, ExploitCache
from .security import validator
from .database import DatabaseManagment, ExploitCache, exploitDetails
from .exploithandler import ExploitHandler
import shlex

installation = DatabaseManagment.getInstall()
history = FileHistory(f'{installation}/.data/.history/history')
path = os.getenv("PATH").split(":")
true, false = True, False
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
        return

    @classmethod
    def sys_call_Linux(cls, data):
        for k, v in Aliases.items():
            if k in data:
                data[data.index(k)] = v

        for x in path:
            if os.path.exists(f"{x}/{data[0]}"):
                subprocess.run(data)
                return True

        Error(f"[!] Program not found: {data[0]}")
        return False

    @classmethod
    def sys_call_other(cls, data):
        try:
            for x in path:
                if os.path.exists(f"{x}/{data[0]}"):
                    subprocess.run(data)
                    return True

            Error(f"[!] Program not found: {data[0]}")
            return False
        except OSError:
            ToStdout.write(traceback.format_exc())
    def __init__(self):
        """This handles all the input"""
        pass

    @staticmethod
    def recon_ng(args):
        # UPDATED TO USE SYSTEM PACKAGE VERIFICATION
        if not validator.verify_system_package("recon-ng"):
            print(f"[!] Integrity verification Failed! 'recon-ng' package modified.")
            if not input("[*] Would you still like to proceed [y/n]: ").lower().endswith("y"):
                return
        else:
            print(f"[*] Integrity verified via dpkg for recon-ng.")
            
        subprocess.run(["sudo", "recon-ng"])
        return

    @classmethod
    def check(cls, data):
        # create a list copy of supplied data for iteration
        cmd = shlex.split(data)
        rebuilt_cmd = ""
        for x in cmd:
            for k, v in Aliases.items():
                if x == k:
                    cmd[cmd.index(k)] = v

        for i in cmd:
            rebuilt_cmd += f"{i} "

        rebuilt_cmd = rebuilt_cmd.rstrip()
        dataList = shlex.split(rebuilt_cmd)

        # create a list to check for input fixes
        inputFixList = ["cd", "clear", "exit", "cat"]

        try:
            if "&&" in data:
                fix = Input_fixes.continues(data)
                if fix == 0:
                    return
                else:
                    data = fix[len(fix) - 1]
                    dataList = data.split(' ')
            if ">" in data:
                Input_fixes.out(data)
                return
            if dataList[0] in inputFixList:
                if Input_fixes(dataList):
                    return
            if data.endswith(" "):
                data = data.rstrip(" ") # NOTE: Changed lstrip to rstrip to fix trailing spaces properly

            cmd_name = shlex.split(data)[0]

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
                "debugdb": DatabaseManagment.Debug
            }

          
            # ==========================================
            # COMMAND EXECUTION ROUTER
            # ==========================================
            try:
                if cmd_name in general_cmds:
                    general_cmds[cmd_name](data)
                    return True
                
                elif "Linux" in os.uname():
                    data = dataList
                    cls.sys_call_Linux(data)
                    return True
                
                else:
                    data = dataList
                    cls.sys_call_other(data)
                    return True

            except Exception:
                Error(traceback.format_exc())
                return False
                
        except Exception:
            Error(traceback.format_exc())
            return False

    @classmethod
    def get(cls):
        Banners(None)
        while True:
            DatabaseManagment.getCVE()
            # Refresh the memory cache from the database module
            ExploitCache.update() 
            
            try:
                data = PromptSession(history=history, auto_suggest=AutoSuggestFromHistory(), enable_history_search=True)
                inp = data.prompt(f"[SuperSploit]: ")
                cls().check(inp)
            except Exception:
                Error(traceback.format_exc())
                continue