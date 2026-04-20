import os
import traceback
import shlex
from .ToStdOut import ToStdout
from .errors import Error
from .database import DatabaseManagment

installation = f'{os.getenv("HOME")}/.SuperSploit'
print = ToStdout.write

class Search:
    @classmethod
    def search(cls, data):
        try:
            args = shlex.split(data)
            if len(args) < 2:
                print("[-] Please provide an argument to search for.\n")
                try:
                    with open(f"{installation}/.data/.help/search", "r") as file:
                        print(file.read())
                except FileNotFoundError:
                    pass
                return

            category = args[1].lower()
            search_terms = [term.lower() for term in args[2:]]
            items = []

            # Leverage the database methods to keep code DRY
            if category == "exploits":
                items = DatabaseManagment.getExploits()
            elif category == "payloads":
                items = DatabaseManagment.getPayloads()
            elif category == "targets":
                try:
                    with open(f"{installation}/.data/.nmap/.targets", "r") as file:
                        items = [x for x in file.read().split("\n") if x]
                except FileNotFoundError:
                    print("[-] No targets file found.\n")
                    return
            else:
                print(f"[-] Unknown category: {category}\n")
                return

            # If no search terms, print everything
            if not search_terms:
                for idx, item in enumerate(items):
                    print(f'{idx}: {item}\n')
                return

            # Filter items ensuring ALL search terms are found in the string
            found = []
            for item in items:
                # Check if all search terms exist in the lowercased item path
                if all(term in item.lower() for term in search_terms):
                    found.append(item)

            if not found:
                print("[-] No results found.\n")
            else:
                # Use the original index from the main list so the user can use it with 'use'
                for item in found:
                    original_idx = items.index(item)
                    print(f'{original_idx}: {item}\n')

        except Exception:
            Error(traceback.format_exc())