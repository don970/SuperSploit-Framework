import getpass
import os
import subprocess

class bt:
    def __init__(self, info):
        self.all = False
        self.targetList = []
        self.targetDict = {}
        self.input = None
        self.out = None
        self.menu()

    def resetFlags(self):
        self.out = None
        self.input = None
        if self.all:
            self.targetList = []

    def scan(self):
        os.system("clear")
        print("Scanning")
        targets = subprocess.run(["hcitool", "scan"], capture_output=True)
        targetslist = targets.stdout.decode().split("\n")
        for x in targetslist:
            if "\t" in x:
                self.targetList.append(x.split("\t")[1])
        if len(targetslist) > 0:
            return True
        return False

    def show_targets(self):
        subprocess.run(['clear'])
        for x in self.targetList:
            print(x)

        if len(self.targetDict) > 0:
            for k, v in self.targetDict.items():
                print(f"Device physical address: {k}\nDevice info: {v}")
        input("press enter to continue")
        return

    def BlueRanger(self):
        os.system("clear")
        cwd = os.getcwd()
        os.chdir(f"{cwd}/source/core/reconCore/Bluetooth")
        for x in self.targetList:
            print(f"{self.targetList.index(x)}: {x}")
        self.input = int(input("Enter target index to track: "))
        subprocess.run(["sudo", "bash", "./blue.sh", "hci0", self.targetList[self.input]])
        if input("Would you like to reset all flags: ").startswith("y"):
            self.all = True
            self.resetFlags()
            return
        self.all = False
        return

    def Dinfo(self):
        os.system("clear")
        for x in self.targetList:
            print(f"{self.targetList.index(x)}: {x}")
        self.input = int(input("Enter target index: "))
        self.targetDict[self.targetList[self.input]] = subprocess.run(["sudo", "hcitool", "info", self.targetList[self.input]], capture_output=True).stdout.decode()
        if input("Would you like to reset all flags: ").startswith("y"):
            self.all = True
        self.all = False
        self.resetFlags()

        return
        pass

    def enum(self):
        for x in self.targetList:
            print(f"{self.targetList.index(x)}: {x}")
        self.input = int(input("Enter target index: "))
        self.targetDict[self.targetList[self.input]] = subprocess.run(["sudo", "hcitool", "info", self.targetList[self.input]], capture_output=True).stdout.decode()
        pass

    def menu(self):
        while True:
            subprocess.run(["clear"])
            if len(self.targetList) > 0:
                print("TARGETS AVAILABLE")
            indexes = [0, 1, 2, 3, 4, 5]
            selections = ["return", self.scan, self.BlueRanger, self.show_targets, self.enum, self.Dinfo]
            try:
                try:
                    selected = int(input("""0.) back
1.) Scan for bt devices
2.) BlueRanger "track device"
3.) View BT devices
4.) Enum device
5.) Get device info
Enter Here > """))
                    if selected in indexes:
                        if selected == 0:
                            return
                        selections[indexes.index(selected)]()
                        continue
                except ValueError:
                    continue
            except KeyboardInterrupt:
                return

    @staticmethod
    def ducky(arg):
        cmd = "python3 source/core/reconCore/Bluetooth/BlueDucky.py".split(" ")
        subprocess.run(cmd)
