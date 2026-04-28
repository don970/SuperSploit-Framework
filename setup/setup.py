#!/bin/python3
import json
import os
import subprocess
from os import getenv
from subprocess import run
import pathlib

try:
    import prompt_toolkit
except ImportError:
    prompt_cmd = "sudo apt-get install python3-prompt-toolkit"
    run(prompt_cmd.split())

from prompt_toolkit import prompt as input

# first lets set up important variables
home = getenv("HOME")
installation = pathlib.Path(f'{home}/.SuperSploit')

# now create a class called SuperSploit
class SuperSploit:

    def __init__(self):
        self.create_aliases()
        self.install_dependencies()

    def create_aliases(self):
        cwd = pathlib.Path(os.getcwd())
        # lets create the base dictionary
        a = {"~": getenv("HOME"), "install_dir": f"{getenv('HOME')}/.SuperSploit"}
        # write the dictionary to a json file using the json libary
        with open(f"{installation}/.data/.config/Aliases.json", "w") as file:
            # create the json dump
            data = json.dumps(a, sort_keys=True, indent=4)
            # write the data to the json file
            file.write(data)

    def install_dependencies(self):
        # install the pip dependencys
        run(["pip3", "install", "-r", f"{installation}/setup/requirements.txt"])



if __name__ == "__main__":
    SuperSploit()