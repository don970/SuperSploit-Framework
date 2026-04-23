🛡️ SuperSploit Framework

![logo1](https://github.com/user-attachments/assets/02f43367-1b7e-42f0-b25c-6ed786079567)

## ⚠️ Disclaimer
*This program is fully capable of breaking the law depending on how it is used. Always ensure you have explicit, written permission from the owner of the device or network you are testing. The author assumes no liability for misuse. Use responsibly.*

---

## 📖 Overview

**SuperSploit** is a highly optimized, Python 3-based exploitation, reconnaissance, and payload management framework. Built as a lightweight, command-line alternative to heavier GUI-laden platforms, it prioritizes speed, reliability, and a minimal system footprint. 

With recent architectural upgrades, SuperSploit now features a **native, plug-and-play modular reconnaissance engine**, completely eliminating the need for heavy external dependencies like Nmap or Recon-ng. By offering granular control over modular payloads and integrating advanced staged deployment strategies, SuperSploit provides a highly efficient execution hub for interactive penetration testing and hardware-level attacks.

---

## 🚀 Core Strengths & Features

### 1. Lightweight & Command-Line First
Designed for speed and reliability, the framework avoids the overhead of a graphical user interface. Its terminal-based architecture utilizes `prompt-toolkit` to provide persistent input history, dynamic auto-suggestions, and a seamless environment that falls back to native system shell execution when a command is unrecognized.

### 2. Performance-Optimized Routing
* **O(1) Command Registry:** SuperSploit utilizes optimized dictionary mappings for command dispatching, ensuring instantaneous response times regardless of how many modules or custom tools are loaded.
* **Intelligent Caching:** Database reads and CVE lookups are cached locally in memory to minimize redundant disk I/O, providing a fluid operator experience.

### 3. Modular & Staged Execution Engine
* **In-Memory Payload Loading:** Utilizing `importlib.util`, Python exploits are dynamically loaded into isolated memory namespaces. This ensures clean execution without permanently writing temporary modules to the source tree.
* **Staged Deployment:** The framework accommodates staged execution logic, giving operators precise, granular control over payload delivery.
* **Fail-Safe C Compilation:** C-based exploits are compiled in real-time (`gcc`). A rigid execution protocol ensures that all compiled binaries are safely purged from the disk after execution or upon interruption.
* **Raw Socket Handlers:** Built-in context-managed native socket listeners for instantly catching reverse shells without relying on external tools like Netcat.

### 4. Zero-Trust Security Validation
* **Hybrid Integrity Checking:** The framework implements a strict zero-trust model. System packages (like Bettercap) are verified natively via `dpkg -V`, while internal scripts and downloaded custom binaries (e.g., Phoneinfoga) are validated using Python's SHA256 hashing.
* **Deep Input Sanitization:** All user-provided shell arguments are tokenized using `shlex.split()`, mitigating arbitrary command injection during payload execution.

### 5. Native Plug-and-Play Reconnaissance
* **Dependency-Free Scanning:** SuperSploit utilizes a custom Python-native multi-threaded TCP scanner (`port-scan`), eliminating reliance on Nmap while maintaining high-speed host discovery.
* **Extensible Module API:** A standardized Abstract Base Class (`ReconModule`) allows developers to drop new Python recon scripts into the `modules/` folder, and the framework will automatically register and load them at runtime.
* **Hardware & OSINT Cores:** Features BlueDucky integration for turning the host into a malicious Bluetooth HID device, alongside tools for Google Dork generation (`name-search`).

---

## ⚙️ Command Layout & Usage

SuperSploit commands are divided into tactical categories for ease of use.

### [1] Core Workspace & Variables
* `add <VAR> <VAL>` : Add a custom variable to the active database.
* `set <VAR> <VAL>` : Set a specific variable value (e.g., `R_HOST`, `L_PORT`).
* `show [TARGET]`   : Show dynamic variables, aliases, or exploit details.
* `use <CAT> <IDX>` : Select an exploit, payload, or target by index.
* `search <CAT>`    : Search the database for exploits, payloads, or targets.

### [2] Execution Engine
* `exploit`         : Execute the currently loaded exploit or payload. Handles Python, Bash, and C files.

### [3] Network & Scanning (Native)
* `port-scan <IP>`  : Run a native, highly-concurrent TCP port scan against a target.
* `view-targets`    : List all currently discovered targets.
* `import-targets`  : Import a saved target list from the database.

### [4] OSINT & External Recon
* `name-search`     : Generate a list of Google Dorks for a specific name across social platforms.
* `phoneinfoga`     : Launch the verified Phoneinfoga wrapper to scan phone numbers.
* `bettercap`       : Launch Bettercap for network manipulation (requires dpkg verification).

### [5] Hardware & Bluetooth
* `ducky`           : Launch the BlueDucky Bluetooth HID injection script.
* `ranger`          : Start the Blue Ranger device tracking script.

### [6] System & Utilities
* `clean`           : Purge history, error logs, scan data, and passwords to reset the workspace safely.
* `all`             : Display the main help menu.

*(Type `help <command>` inside the framework for detailed usage instructions for any specific module).*

---

---

## 🗺️ Future Roadmap

With the recent shift toward a dependency-free, plug-and-play reconnaissance engine, SuperSploit’s development is now heavily focused on expanding its native Python capabilities. The following phases outline our path forward:

### Phase 1: Advanced Native Network Discovery
* **Raw Socket Ping Sweeping:** Developing native ICMP and ARP sweepers using raw sockets to handle local subnet host discovery entirely within Python, fully replacing Nmap's `-sn` capabilities.
* **Asynchronous Scanning Core:** Upgrading the threaded `port-scan` module to utilize Python's `asyncio` for non-blocking, hyper-fast concurrent network mapping and banner grabbing.

### Phase 2: Pure-Python OSINT & Ecosystem Expansion
* **Expanded `ReconModule` API:** Extending the Abstract Base Class to support standardized OSINT modules, credential scrapers, and directory fuzzers without relying on external GitHub clones.
* **Threat Intelligence Integrations:** Building native, API-driven modules for passive reconnaissance using services like Shodan, Censys, and WHOIS databases directly into the SuperSploit database.

### Phase 3: Automated Intelligence Correlation
* **Service-to-Exploit Mapping:** Building a correlation engine that automatically parses the banners and open ports discovered by the native recon engine, cross-referencing them against local CVE lists to suggest viable framework exploits.
* **Automated Attack Chains:** Allowing the framework to pipeline the output of a native discovery module directly into the execution engine for automated, zero-click testing environments.

### Phase 4: Execution Hardening & Extensibility
* **Payload Sandboxing:** Integrating Linux namespaces and `seccomp` profiles to strictly limit the host-level permissions of running exploits, ensuring the framework's host machine remains protected during active engagements.
* **RESTful API Wrapper:** Developing a headless API mode to allow the native recon and execution engines to be orchestrated remotely, making SuperSploit a viable backend for CI/CD security pipelines.

---
