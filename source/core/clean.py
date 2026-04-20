import os
from .ToStdOut import ToStdout

print = ToStdout.write
installation = f'{os.getenv("HOME")}/.SuperSploit'

def clean(args=None):
    """Refactored from a class to a function since it just executes a single routine"""
    print("[*] Doing a full clean. Clearing history, error log along with all scan and target data.\n")
    
    paths = [
        ".data/scans/.personSearch",
        ".data/loot/.passwords", 
        ".data/.nmap/.targets",
        ".data/scans/targeted_scan", # Fixed path
        ".data/scans/phone_numbers", 
        ".data/scans/custom_scan",   # Fixed path
        ".data/.history/history", 
        ".data/.errors/error.log", 
        ".data/scans/phoneinfoga.scan",
        ".data/.history/nhistory"
    ]
    
    for path in paths:
        full_path = os.path.join(installation, path)
        if os.path.exists(full_path):
            try:
                with open(full_path, "w") as file:
                    pass # Opening in 'w' mode and doing nothing truncates the file
            except Exception as e:
                print(f"[-] Failed to clean {path}: {e}\n")
    print("[*] Clean complete.\n")