import json
from os import getenv, chdir, getcwd, listdir
from subprocess import run
import traceback
import requests
from prompt_toolkit import prompt as input
# first lets set up important variables
installation = f'{getenv("HOME")}/.SuperSploit'
true = True
false = False


# now lets create a class called SuperSploit
class SuperSploit:
  
  def __init__(self):
    self.create_aliases()
    self.install_dependencys()
    self.install_phoneinfoga()
    self.install_recon_ng()
    self.findTerm()
    return
    
  def create_aliases(self):
    # lets create the base dictionary
    a = {"~": getenv("HOME"), "install_dir": f"{getenv('HOME')}/.SuperSploit"}
    
    # lets write the diction to a json file using the json libary
    with open(f"{installation}/.data/Aliases.json", "w") as file:
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
    run(["pip", "install", "--break-system-packages", "-r" ,"REQUIREMENTS"])
    chdir(cwd)
    return 0

  def install_dependencys(self):
    apt_deps = ["bettercap", "wireshark", "python3-pyfiglet", "netcat-traditional", "adb", "fastboot", "pip"]
    pip_deps = ["pure-python-adb", "pwn", "impacket"]
  
    # install the apt dependencys
    for x in apt_deps:
      try:
        run(["sudo", "apt-get", "install", x, "-y"])
      except OSError as e:
        print(e)
      
    # install the pip dependencys
    for i in pip_deps:
      try:
        run(["sudo", "pip", "install", "--break-system-packages", i])
      except OSError as e:
        print(e)
  
  def findTerm(self):
    programs = listdir("/bin")
    run(["clear"])
    with open(".data/.terminals") as file:
      terms = file.read().split("\n")
      file.close()
      
    for x in terms:
      if x in programs:
        print(f"[*] {x} already installed")
        return 0
    for x in terms:
      print(f"{terms.index(x)}: {x}")
    try:
      data = input("Enter the index of the terminal program to attempt to install: ")
      STR = f"sudo apt-get install {terms[int(data)]}"
      run(STR.split(" "))
    except ValueError:
      STR = f"sudo apt-get install tilix"
      run(STR.split(" "))

SuperSploit()
