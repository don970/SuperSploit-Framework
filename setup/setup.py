#!/bin/python3
import json
from os import getenv, chdir, getcwd, listdir, getenv
from subprocess import run, Popen, PIPE
import traceback

try:
    import request
    import prompt_toolkit
except ImportError:
    requests_cmd = "sudo apt-get install python3-request"
    prompt_cmd = "sudo apt-get install python3-prompt-toolkit"
    run(requests_cmd.split())
    run(prompt_cmd.split())

from prompt_toolkit import prompt as input

# first lets set up important variables

installation = f'{getenv("HOME")}/.SuperSploit'
true = True
false = False
home = getenv("HOME")
pipe = PIPE

# now create a class called SuperSploit
class SuperSploit:

    def __init__(self):
        self.create_aliases()
        self.install_dependencys()
        self.install_pybluez()
        self.install_phoneinfoga()
        self.install_recon_ng()
        self.xterm()
        return

    def create_aliases(self):
        # lets create the base dictionary
        a = {"~": getenv("HOME"), "install_dir": f"{getenv('HOME')}/.SuperSploit"}

        # write the dictionary to a json file using the json libary
        with open(f"{installation}/.data/.config/Aliases.json", "w") as file:
            # create the json dump
            data = json.dumps(a, sort_keys=True, indent=4)
            # write the data to the json file
            file.write(data)
            # close the file
            file.close()
        # exit with code 0
        return 0

    def install_phoneinfoga(self):
        print("installing phoneinfoga")
        req = requests.get("https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install")
        with open("/tmp/install", "w") as file:
            file.write(req.content.decode())
            file.close()
        run(["bash", "/tmp/install"])
        run(["sudo", "mv", "phoneinfoga", "/usr/local/bin/phoneinfoga"])
        return 0

    def install_recon_ng(self):
        cwd = getcwd()
        chdir(f"{getenv('HOME')}/.SuperSploit/source/core/reconCore/external_tools/")
        run(["git", "clone", "https://github.com/lanmaster53/recon-ng.git"])
        chdir("recon-ng")
        run(["pip", "install", "--break-system-packages", "-r", "REQUIREMENTS"])
        chdir(cwd)
        return 0

    def install_dependencys(self):
        apt_deps = ["bettercap", "wireshark", "python3-pyfiglet", "netcat-traditional", "adb", "fastboot", "pip",
                    "python3-pydbus", "libbluetooth-dev"]

        # install the apt dependencys
        for x in apt_deps:
            try:
                run(["sudo", "apt-get", "install", x, "-y"])
            except OSError as e:
                print(e)

        # install the pip dependencys
        run(["sudo", "pip", "install", "--break-system-packages", "-r", f"{installation}/setup/requirements.txt"])

    def install_pybluez(self):
        chdir("setup")
        run(["unzip", "pybluez-master.zip"])
        chdir("pybluez-master")
        run(["sudo", "python3", "setup.py", "install"])
        chdir(installation)
        return


    def xterm(self):
        cmd = Popen(["sudo", "apt-get", "install", "xterm", "-y"], stderr=pipe, stdin=pipe)
        err = cmd.communicate()[1]
        if err:
            print(err)
            return
        return True


SuperSploit()