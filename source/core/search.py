from .database import DatabaseManagment, ExploitCache
import os

from .ToStdOut import ToStdout

write = ToStdout.write

class Search:
    @classmethod
    def search(cls, data):
        parts = data.split(" ")
        if len(parts) < 2:
            write("Usage: search <exploits|payloads|targets> [keyword]")
            return

        category, search_terms = parts[1], [t.lower() for t in parts[2:]]
        
        if category == "recon":
            db, path_list = DatabaseManagment.UpdateReconDB()
            source_list = path_list
            for i, path in enumerate(source_list):
                if "__pycache__" in path:
                    continue

                meta = ExploitCache.metadata_index.get(path, {})

                # Match against Path, Name, CVE, or Description
                match_pool = f"{path} {meta.get('name')} | {meta.get('desc')}".lower()

                if not search_terms or any(term in match_pool for term in search_terms):
                    cve_str = f" [{meta.get('cat')}]" if meta.get('cat') != "N/A" else ""
                    write(f"{i}: {path}{cve_str}")
            return

        if category == "targets":
            targets = DatabaseManagment.getTargets()
            print("-" * 50)
            for i, (k, v) in enumerate(targets.items()):
                print(f"Target {i}: {k}")
                for x, y in v.items():
                    print(f"   {x}: {y}")
                print("-" * 50)
            return


        source_list = ExploitCache.all_exploits if category == "exploits" else ExploitCache.all_payloads
        
        for i, path in enumerate(source_list):
            if "__pycache__" in path:
                continue

            meta = ExploitCache.metadata_index.get(path, {})
            
            # Match against Path, Name, CVE, or Description
            match_pool = f"{path} {meta.get('name')} {meta.get('cve')} {meta.get('desc')}".lower()
            
            if not search_terms or any(term in match_pool for term in search_terms):
                cve_str = f" [{meta.get('cve')}]" if meta.get('cve') != "N/A" else ""
                write(f"{i}: {path}{cve_str}")