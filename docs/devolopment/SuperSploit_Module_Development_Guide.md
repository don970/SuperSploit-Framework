Here is a comprehensive help file and developer guide for adding custom exploits and reconnaissance modules to the SuperSploit framework.

# 🛠️ SuperSploit Module Development Guide

This guide explains how to write, format, and integrate custom exploits and reconnaissance (recon) modules into the SuperSploit framework.

---

## 1. The Core Concept: The Metadata Delimiter
SuperSploit utilizes a unique parsing system to separate a module's execution code from its metadata (like descriptions, authors, or target info). 

Whenever the framework loads a Python-based exploit or recon module, it splits the file's contents using the `#!#!#!` delimiter. 

The file is expected to be split into three parts:
1. **Index 0:** Header/Imports (Optional)
2. **Index 1 (Between the delimiters):** Metadata. The framework strips this section out entirely before execution.
3. **Index 2:** The actual executable code.

### Available YAML Metadata Fields
You can include various YAML keys inside the `#!#!#!` block to hook into SuperSploit's advanced automation features:
* `name`: The display name of the exploit.
* `description`: A brief summary of the exploit.
* `cve`: The CVE identifier (e.g., `CVE-2024-1234`).
* `target`: The intended target OS or service.
* `payload`: A linked payload file (e.g., `payloads/stager/stager.py`). If set, SuperSploit automatically generates a fileless stager and launches a C2 listener before the exploit fires!
* `keywords`: A list of strings/integers (e.g., `[8080, "http", "apache"]`). This directly hooks into the `auto_suggest` engine, which dynamically recommends your exploit when a recon module discovers a matching open port or service.

**Example Metadata Block:**
```yaml
name: Custom Apache RCE
cve: CVE-2024-1234
keywords: [80, 443, 8080, "http", "apache"]
payload: payloads/stager/stager.py
```

---

## 2. Adding Python Exploit Modules

When executing a Python exploit in "module mode" (dynamically loaded into memory), the framework's execution engine looks for a specific entry-point function named `exploit()`. The function must be capable of handling an optional `args` list passed by the user.

### Exploit Module Template (`.py`)
```python
import os
import sys

#!#!#!
# METADATA SECTION
# Author: Your Name
# Description: Example RCE exploit
# Target: Vulnerable Server v1.0
# keywords: [80, "http"]
#!#!#!

def exploit(args=None):
    """
    Main entry point for the exploit.
    """
    print("[*] Executing custom exploit...")
    
    if args:
        print(f"[*] Received arguments: {args}")
        target = args[0]
    else:
        print("[-] No arguments provided. Defaulting to 127.0.0.1")
        target = "127.0.0.1"

    # Your exploit logic here...
    print(f"[*] Exploiting {target} successfully!")

# Fallback for standard subprocess execution
if __name__ == "__main__":
    exploit(sys.argv[1:])
```

---

## 3. Adding Bash and C Exploit Modules

SuperSploit natively supports `.sh` and `.c` files. These do not require the Python-specific module delimiters or `exploit()` functions, as they are handled differently.

### Bash Exploits (`.sh`)
* **Execution:** Run directly via `subprocess.run(["bash", file])`.
* **Success Criteria:** Ensure your script exits with code `0` on success, as the framework uses the return code to log whether the exploit succeeded or failed.

### C Exploits (`.c`)
* **Execution:** The framework will prompt the user for `gcc` options, compile the binary in real-time, execute it, and then safely delete the binary to maintain OPSEC.
* **Writing:** Write standard C code. You can rely on `int main(int argc, char *argv[])` to parse arguments interactively supplied by the user.

---

## 4. Adding Reconnaissance Modules

Recon modules operate very similarly to Python exploits but use a different entry point. When run dynamically in memory, the engine searches for a `Start()` function.

### Recon Module Template (`.py`)
```python
import socket

#!#!#!
# METADATA SECTION
# Author: Your Name
# Description: Custom port scanner
#!#!#!

def Start(args=None):
    """
    Main entry point for the recon module.
    """
    print("[*] Initializing Reconnaissance Module...")
    
    if args:
        target = args[0]
    else:
        target = "127.0.0.1"
        print(f"[*] No target specified, defaulting to {target}")
        
    print(f"[*] Scanning {target}...")
    # Your recon/scanning logic here...

# Fallback for standard subprocess execution
if __name__ == "__main__":
    import sys
    Start(sys.argv[1:])
```

---

## 5. Best Practices & Tips

1. **Error Handling:** When running as an in-memory module, exceptions will be caught by the framework and logged. However, it is best practice to handle your own `try/except` blocks within the `exploit()` or `Start()` functions to provide clean console output to the operator.
2. **Native Handlers:** If your exploit relies on catching a reverse shell, you do not need to write a listener into your exploit script. SuperSploit has a built-in native raw TCP socket listener that operates on a background thread. Simply rely on the framework to catch the connection.
3. **Subprocess vs. Module Execution:** Operators will be prompted whether they want to run your Python script as a module or a subprocess. Always include the `if __name__ == "__main__":` block at the bottom of your scripts so they function correctly regardless of the operator's choice.
