import os
import sys
import subprocess
from .ToStdOut import ToStdout

true = True
false = False
print = ToStdout.write

class Input_fixes:
    def __init__(self, dataList: list):
        self.list = dataList
        ListOfFixes = [self.cd, self.clear, self.exit, self.cat, self.out]
        fixes = ["cd", "clear", "exit", "cat", ">"]
        ListOfFixes[fixes.index(dataList[0])]()
        return

    @classmethod
    def continues(cls, data):
        def proc_one(data):
            if ">" in data:
                data1 = data.split(" > ")
                with open(data1[1], "a") as file:
                    file.write(subprocess.run(data1[0].split(), capture_output=True).stdout.decode())
                    file.close()
                return 0
            try:
                if "help" in data:
                    return 1, data
                subprocess.run(data.split(" "))
                return 0
            except FileNotFoundError:
                return 1, data

        proc_exit_codes = []
        for x in data.split(" && "):
            i = proc_one(x)
            if i == 0:
                proc_exit_codes.append(0)
            else:
                proc_exit_codes.append(1)
        if 1 in proc_exit_codes:
            return i
        return 0

    def cat(self):
        if len(self.list) < 1:
            return False
        try:
            if self.list[1] == "":
                return False
        except:
            return False
        with open(self.list[1], "r") as file:
            print(file.read())
            file.close()
        return

    @staticmethod
    def exit():
        sys.exit()

    def cd(self) -> int:
        os.chdir(self.list[1])
        return 0

    @staticmethod
    def clear():
        print("\033[H\033[J")

    @classmethod
    def out(cls, data):
        data1 = data.split(" > ")
        with open(data1[1], "a") as file:
            file.write(subprocess.run(data1[0].split(), capture_output=True).stdout.decode())
            file.close()
        return
