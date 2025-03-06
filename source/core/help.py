import os
import subprocess
import traceback
from subprocess import PIPE

from .ToStdOut import ToStdout
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from .errors import Error

installation = f'{os.getenv("HOME")}/.SuperSploit'
history = InMemoryHistory()


class Help:
    def __init__(self):
        pass

    @classmethod
    def help(cls, data):
        if "menu" in data:
            a = data.split(" ")[1]
            data = PromptSession(history=history, auto_suggest=AutoSuggestFromHistory(), enable_history_search=True)
            while True:
                ToStdout.write('all - shows basic help page')
                a = data.prompt("[Help]: ")
                if "exit" in a or "back" in a:
                    break
                if a in os.listdir(f"{installation}/.data/.help"):
                    with open(f"{installation}/.data/.help/{a}", "r") as file:
                        ToStdout.write("\033[H\033[J")
                        ToStdout.write(file.read())
                        file.close()
                    continue
                try:
                    if "clear" in a:
                        ToStdout.write("\033[H\033[J")
                    else:
                        cmd = subprocess.Popen(a.split(" "), stdout=PIPE, stdin=PIPE, stderr=PIPE)
                        output = cmd.communicate()[0], cmd.communicate()[1]
                        for x in output:
                            if len(x) > 0:
                                ToStdout.write(x.decode())
                        continue
                except Exception:
                    Error(traceback.format_exc())
        try:
            a = data.split(" ")[1]
            if a in os.listdir(f"{installation}/.data/.help"):
                with open(f"{installation}/.data/.help/{a}", "r") as file:
                    ToStdout.write("\033[H\033[J")
                    ToStdout.write(file.read())
                    file.close()
                    return
        except Exception as e:
            if "Index Error" in str(e):
                pass
            with open(f"{installation}/.data/.help/all", "r") as file:
                ToStdout.write("\033[H\033[J")
                ToStdout.write(file.read())
                file.close()