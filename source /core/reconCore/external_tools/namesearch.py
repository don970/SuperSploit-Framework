from prompt_toolkit import PromptSession
import os
import urllib.parse

installation = f'{os.getenv("HOME")}/.SuperSploit'
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
history = FileHistory(f'{installation}/.data/.history/history')
input = PromptSession(history=history, auto_suggest=AutoSuggestFromHistory(), enable_history_search=True)
input = input.prompt

class NameSearch:
    @staticmethod
    def append(strs):
        with open(f"{installation}/.data/scans/personSearch", "a") as file:
            file.write(strs)
            file.close()

    @staticmethod
    def write(strs):
        with open(f"{installation}/.data/scans/personSearch", "w") as file:
            file.write(strs)
            file.close()

    @classmethod
    def simpleNamesSearch(cls):
        name = input("Enter the name to search: ")
        sdb = ["facebook.com", "instagram.com", 'linkedin.com', "Avk.com", "twitter.com"]
        list1 = [""]
        print("Using site dictionary to perform a search return")
        for site in sdb:
            if len(name.split(" ")) > 1:
                s = ""
                n = name.split(" ")
                for x in n:
                    if n.index(x) < len(n) - 1:
                        s += f"{x}%20"
                    else:
                        s += x
                name = s
                searchPhrase = f"https://www.google.com/search?q=site%3A%22{site}%22+%7C+intext%3A%22{name}%22"
            else:
                searchPhrase = f"https://www.google.com/search?q=site%3A%22{site}%22+%7C+intext%3A%22{name}%22"
            list1.append(searchPhrase)
        try:
            for x in list1:
                print(f"To search {sdb[list1.index(x)]} just copy the link and past it into a browser.")
                print(x)
        except IndexError:
            return

    @classmethod
    def help(cls):
        print("""[OSNIT Help Menu]
help - Shows this help menu. 3
dork - Returns a list of google dork links for the 
        name and various social media site. 
""")
        pass

    @classmethod
    def main(cls, args):
        print("OSNIT Name Search Tool")
        inputs = ["help", "dork"]
        funs = [cls.help, cls.simpleNamesSearch]
        print("\033[H\033[J")
        while True:
            try:
                data = input("[ONST]: ")
                if data == "exit":
                    return
                for x in funs:
                    funs[inputs.index(data)]()
                continue
            except Exception as e:
                print(e)
        return



