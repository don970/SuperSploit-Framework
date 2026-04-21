from .database import DatabaseManagment, ExploitCache
import os

class Search: 
    from .database import DatabaseManagment, ExploitCache
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
        
        if category == "targets":
            for i, (t, p) in enumerate(DatabaseManagment.getTargets().items()):
                write(f"{i}: {t}:{p}")
            return

        source_list = ExploitCache.all_exploits if category == "exploits" else ExploitCache.all_payloads
        
        for i, path in enumerate(source_list):
            meta = ExploitCache.metadata_index.get(path, {})
            
            # Match against Path, Name, CVE, or Description
            match_pool = f"{path} {meta.get('name')} {meta.get('cve')} {meta.get('desc')}".lower()
            
            if not search_terms or any(term in match_pool for term in search_terms):
                cve_str = f" [{meta.get('cve')}]" if meta.get('cve') != "N/A" else ""
                write(f"{i}: {path}{cve_str}")