from .database import DatabaseManagment, ExploitCache
import os

class Search: 
    @classmethod
    def search(cls, data):
        parts = data.split(" ")
        if len(parts) < 2:
            print("Please provide an argument to search for.")
            # Helper logic here...
            return

        category = parts[1]
        search_terms = parts[2:]
        
        # Select the correct list from the cache
        if category == "exploits":
            source_list = ExploitCache.all_exploits
        elif category == "payloads":
            source_list = ExploitCache.all_payloads
        elif category == "targets":
            targetlist = DatabaseManagment.getTargets()
            for i, (target, port) in enumerate(targetlist.items()):
                print(f"{i}: {target}:{port}")
            return
        else:
            return

        # Perform the search in memory
        if not search_terms:
            for i, path in enumerate(source_list):
                print(f"{i}: {path}")
            return

        for i, path in enumerate(source_list):
            if any(term.lower() in path.lower() for term in search_terms):
                print(f"{i}: {path}")