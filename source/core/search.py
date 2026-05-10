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
            try:
                targets = DatabaseManagment.getTargets()
                if not isinstance(targets, dict):
                    write("[-] Targets database is empty or malformed.")
                    return
                    
                print("-" * 50)
                for i, (k, v) in enumerate(targets.items()):
                    print(f"Target {i}: {k}")
                    if isinstance(v, dict):
                        for x, y in v.items():
                            print(f"   {x}: {y}")
                    else:
                        print(f"   status: {v}")
                    print("-" * 50)
            except Exception as e:
                write(f"[-] Error parsing targets database: {e}")
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