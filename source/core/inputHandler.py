import json
import os
import traceback
import subprocess
from socket import gethostname
from subprocess import PIPE
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from .errors import Error
from .ToStdOut import ToStdout
from .help import Help
from .show import Show
from .set import SetV
from .use import use
from .search import Search
from .banners import Banners
from .database import DatabaseManagment
from .inputfixes import Input_fixes
from .clean import clean
from .exploithandler import ExploitHandler
from .reconCore.Bluetooth import bt
from .reconCore.external_tools.namesearch import NameSearch
from .reconCore.external_tools.phoneinfoga import Phone
from .reconCore.external_tools.bettercap import bettercap
from .reconCore.external_tools.wireshark import wireshark
from .reconCore.networkRecon import nmap as n

installation = f'{os.getenv("HOME")}/.SuperSploit'
history = FileHistory(f'{installation}/.data/.history/history')
path = os.getenv("PATH").split(":")

with open(".data/.config/Aliases.json") as file:
    aliases = json.load(file)
    file.close()

env = os.environ
def get_network_info():
    host = gethostname()
    data = subprocess.run(["ip", "addr"], capture_output=True).stdout.decode().split("\n")
    for i in data:
        if "inet" and "brd" in i and ":" not in i:
            ip = i.split(" ")[5].split('/')[0]
            subnet = i.split(" ")[5].split('/')[1]
            return ip, subnet, host

try:
    n = n(get_network_info())
except TypeError:
    n = n(["0.0.0.0", "24", "0.0.0.0"])


class Input:

    @classmethod
    def sys_call_Linux(cls, data):
        dataList = data.split(' ')
        with open(f"{installation}/.data/.config/Aliases.json") as file:
            Aliases = json.load(file)
            file.close()
        for k, v in Aliases.items():
            if k in dataList:
                dataList[dataList.index(k)] = v
        for x in path:
            if os.path.exists(f"{x}/{dataList[0]}"):
                subprocess.run(dataList)
                return True
        Error(f"[!] Program not found: {dataList[0]}")
        return False

    @classmethod
    def sys_call_other(cls, data):
        try:
            cmd = subprocess.Popen(data.split(" "), stdout=PIPE, stdin=PIPE, stderr=PIPE)
            output = cmd.communicate()[0], cmd.communicate()[2]
            for x in output:
                if len(x) > 0:
                    ToStdout.write(x.decode())
                return True
        except Exception:
            Error(traceback.format_exc())
            return False

    def __init__(self):
        """This handles all the input"""
        pass
    @staticmethod
    def recon_ng():
        subprocess.run(["sudo", "recon-ng"])
        return 

    @classmethod
    def check(cls, data):
        # create a list copy of supplied data
        dataList = data.split(" ")
        for k, v in aliases.items():
            if k in data.split(" "):
                dataList = data.split(' ')[0:len(data.split(" ")) - 1]
                dataList.append(v)

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
                data = data.lstrip(" ")

            functions = [clean, Show.shells, Help.help, Show.show, SetV.SetV, ExploitHandler, use, Search.search, Banners, DatabaseManagment.addVariableToDatabase]
            inputs = ["clean", "shells", "help", "show", "set", "exploit", "use", "search", "banner", "add"]

            reconFuctions = [cls.recon_ng, NameSearch.main, wireshark, bettercap, Phone, bt]
            recconInputs = ["recon-ng", "name-search", "wireshark", "bettercap", "phoneinfoga", "bt"]

            Wififuncs = [n.getports, n.show_detailed_target_list, n.scan_whole_network, n.targeted_scan, n.show_target_list, n.Import, n.custom_scan, n.traceroute]
            WifiInputs = ["port-scan", "view-targets-v", "get-targets", "scan-target", "view-targets", "import-targets", "custom-scan", "traceroute"]

            btinputs = ["ducky"]
            btfuncs = [bt.ducky]
            try:
                if data.split(" ")[0] in inputs:
                    functions[inputs.index(data.split(" ")[0])](data)
                    return True
                if data.split(" ")[0] in recconInputs:
                    reconFuctions[recconInputs.index(data.split(" ")[0])](data)
                    return True
                if data.split(" ")[0] in WifiInputs:
                    print(Wififuncs[WifiInputs.index(data.split(" ")[0])]())
                    return True

                if data.split(" ")[0] in btinputs:
                    btfuncs[btinputs.index(data.split(" ")[0])](data)
                    return True
                if "Linux" in os.uname():
                    cls.sys_call_Linux(data)
                    return True
                cls.sys_call_other(data)
            except Exception:
                Error(traceback.format_exc())
                return False
        except Exception:
            Error(traceback.format_exc())
            return False

    @classmethod
    def get(cls):
        # call the class to make the banner
        Banners()
        while True:
            DatabaseManagment.getCVE()
            try:
                data = PromptSession(history=history, auto_suggest=AutoSuggestFromHistory(), enable_history_search=True)
                inp = data.prompt(f"[SuperSploit]: ")
                cls().check(inp)
            except Exception:
                Error(traceback.format_exc())
                continue
