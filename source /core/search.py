import os
import traceback

from prompt_toolkit import prompt
from .ToStdOut import ToStdout
from .errors import Error

input = prompt
installation = f'{os.getenv("HOME")}/.SuperSploit'

class Search:
    def __init__(self):
        pass

    @classmethod
    def search(cls, data):
        targetlist = []
        try:
            data = data.split(" ")
            if len(data) < 2:
                ToStdout.write("Please provide a argument to search for. ")
                with open(f"{installation}/.data/.help/search", "r") as file:
                    ToStdout.write(file.read())
                    file.close()
                    return
            key = {}
            exploits = []
            searches = data[2:]
            found = []
            if data[1] == "exploits":
                for x in os.listdir(f"{installation}/exploits"):
                    for y in os.listdir(f"{installation}/exploits/{x}"):
                        exploits.append(f"{installation}/exploits/{x}/{y}")
                if len(data) < 3:
                    for i in exploits:
                        print(f'{exploits.index(i)}: {i}')
                for z in exploits:
                    for s in searches:
                        if s in z:
                            found.append(z)
                for xx in found:
                    print(f'{exploits.index(xx)}: {xx}')
                return
            elif data[1] == "payloads":
                for x in os.listdir(f"{installation}/payloads"):
                    for y in os.listdir(f"{installation}/payloads/{x}"):
                        exploits.append(f"{installation}/payloads/{x}/{y}")
                if len(data) < 3:
                    for i in exploits:
                        print(f'{exploits.index(i)}: {i}')
                for z in exploits:
                    for s in searches:
                        if s in z:
                            found.append(z)
                for xx in found:
                    print(f'{exploits.index(xx)}: {xx}')
                return
            elif data[1] == "targets":
                with open(f"{installation}/.data/.nmap/.targets") as file:
                    for x in file.read().split("\n"):
                        targetlist.append(x)
                    file.close()
                for x in targetlist:
                    print(f"{targetlist.index(x)}: {x}")
            else:
                return
        except Exception:
            Error(traceback.format_exc())
