import os
import urllib.parse
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

installation = f'{os.getenv("HOME")}/.SuperSploit'
history = FileHistory(f'{installation}/.data/.history/history')
session = PromptSession(history=history, auto_suggest=AutoSuggestFromHistory(), enable_history_search=True)

class NameSearch:
    @staticmethod
    def append_log(data):
        with open(f"{installation}/.data/scans/personSearch", "a") as file:
            file.write(data + "\n")

    @classmethod
    def simple_names_search(cls):
        name = session.prompt("Enter the name to search: ").strip()
        if not name:
            return
            
        # Use urllib for safer URL encoding instead of manual string replacement
        encoded_name = urllib.parse.quote(name)
        sdb = ["facebook.com", "instagram.com", 'linkedin.com', "vk.com", "twitter.com"]
        
        print("[*] Generating site-specific Google Dorks...")
        for site in sdb:
            search_phrase = f"https://www.google.com/search?q=site%3A%22{site}%22+%7C+intext%3A%22{encoded_name}%22"
            print(f"\n[*] {site.capitalize()}:")
            print(search_phrase)

    @classmethod
    def help_menu(cls):
        print("""
[OSINT Help Menu]
help - Shows this help menu.
dork - Returns a list of google dork links for the target across various social media sites.
exit - Leave the OSINT tool.
""")

    @classmethod
    def main(cls, args=None):
        print("--- OSINT Name Search Tool ---")
        
        # Map string commands directly to their functions for O(1) routing
        commands = {
            "help": cls.help_menu,
            "dork": cls.simple_names_search
        }
        
        os.system("clear")
        cls.help_menu()
        
        while True:
            try:
                data = session.prompt("[ONST]: ").strip().lower()
                if data == "exit":
                    break
                elif data in commands:
                    commands[data]() # Execute the mapped function safely
                else:
                    print("[-] Unknown command. Type 'help' for options.")
            except Exception as e:
                print(f"[-] Error: {e}")