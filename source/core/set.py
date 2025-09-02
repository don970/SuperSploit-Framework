import json
import os
import traceback
from .errors import Error
from .ToStdOut import ToStdout
import sys

installation = f'{os.getenv("HOME")}/.SuperSploit'

class SetV:

    @classmethod
    def SetV(cls, data):
        try:
            if len(data.split(" ")) < 2:
                print("No arguments supplied for set\n")
                with open(f"{installation}/.data/.help/set", "r") as file:
                    print(file.read())
                    file.close()
                return
            data = data.split(" ")
            with open(f"{installation}/.data/data.json") as file:
                variables = json.load(file)
                file.close()
            for k, v in variables.items():
                if data[1] == k:
                    if data[2] == "true":
                        data[2] = True
                    if data[2] == 'false':
                        data[2] = False
                    variables[k] = data[2]
            with open(f"{installation}/.data/data.json", "w") as file:
                file.write(json.dumps(variables))
                file.close()
        except Exception:
            Error(traceback.format_exc())
            return
