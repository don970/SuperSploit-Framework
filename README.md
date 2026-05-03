🛡️ SuperSploit Framework

![logo1](https://github.com/user-attachments/assets/02f43367-1b7e-42f0-b25c-6ed786079567)

## ⚠️ Disclaimer
*This program is fully capable of breaking the law depending on how it is used. Always ensure you have explicit, written permission from the owner of the device or network you are testing. The author assumes no liability for misuse. Use responsibly.*

---

## 📖 Overview

**SuperSploit** is a highly optimized, Python 3-based exploitation and payload management framework. Built as a lightweight, command-line alternative to heavier GUI-laden platforms, it prioritizes speed, reliability, and a minimal system footprint. 

With a strict focus on attack execution rather than broad discovery, the framework eliminates bloat by offering granular control over modular payloads and advanced staged deployment strategies. SuperSploit provides a highly efficient execution hub for interactive penetration testing, privilege escalation, and direct hardware-level attacks.

---

## 🚀 Core Strengths & Features
<img width="2752" height="1536" alt="unnamed" src="https://github.com/user-attachments/assets/c53c02a0-52e2-414a-8127-67e24e904012" />

### 1. Lightweight & Command-Line First
Designed for speed and reliability, the framework avoids the overhead of a graphical user interface. Its terminal-based architecture utilizes `prompt-toolkit` to provide persistent input history, dynamic auto-suggestions, and a seamless environment that falls back to native system shell execution when a command is unrecognized.

<img width="1536" height="2752" alt="SuperSploit Command Routing Engine Overview" src="https://github.com/user-attachments/assets/acd2826d-84d6-4c33-ac2c-a58eeb4a459a" />

### 2. Performance-Optimized Routing
* **O(1) Command Registry:** SuperSploit utilizes optimized dictionary mappings for command dispatching, ensuring instantaneous response times regardless of how many modules or custom tools are loaded.
* **Intelligent Caching:** Database reads and CVE lookups are cached locally in memory to minimize redundant disk I/O, providing a fluid operator experience.


### 3. Modular & Staged Execution Engine
* **In-Memory Payload Loading:** Utilizing `importlib.util`, Python exploits are dynamically loaded into isolated memory namespaces. This ensures clean execution without permanently writing temporary modules to the source tree.
* **Staged Deployment:** The framework accommodates staged execution logic, giving operators precise, granular control over payload delivery.
<img width="2752" height="1536" alt="SuperSploit Python Exploit Lifecycle" src="https://github.com/user-attachments/assets/16e84cc6-eb9e-47ba-a3f3-3c11cefd2cea"/>
* **Fail-Safe C Compilation:** C-based exploits are compiled in real-time (`gcc`). A rigid execution protocol ensures that all compiled binaries are safely purged from the disk after execution or upon interruption.
* **Raw Socket Handlers:** Built-in context-managed native socket listeners for instantly catching reverse shells.
<img width="2752" height="1536" alt="System Exploitation Framework Workflow" src="https://github.com/user-attachments/assets/4d8d8d14-618a-48f2-9c96-03c67843ecfd" />


### 4. Zero-Trust Security Validation
* **Strict Integrity Checking:** Internal scripts and execution environments are validated using Python's SHA256 hashing to ensure the framework has not been tampered with.
* **Deep Input Sanitization:** All user-provided shell arguments are tokenized using `shlex.split()`, completely mitigating arbitrary command injection during payload execution.
<img width="1536" height="2752" alt="Pen Test Framework Architecture Overview" src="https://github.com/user-attachments/assets/28c8f736-c48e-4362-8dc8-8833598c2381" />

---

## ⚙️ Command Layout & Usage

SuperSploit commands are divided into tactical categories for ease of use.

### [1] Core Workspace & Variables
* `add <VAR> <VAL>` : Add a custom variable to the active database.
* `set <VAR> <VAL>` : Set a specific variable value (e.g., `R_HOST`, `L_PORT`).
* `show [TARGET]`   : Show dynamic variables, aliases, or exploit details.
* `use <CAT> <IDX>` : Select an exploit or payload by index.
* `search <CAT>`    : Search the database for exploits or payloads.

### [2] Execution Engine
* `exploit`         : Execute the currently loaded exploit or payload. Handles Python, Bash, and C files natively.

### [3] System & Utilities
* `clean`           : Purge history, error logs, and temporary payload data to reset the workspace safely.
* `all`             : Display the main help menu.

*(Type `help <command>` inside the framework for detailed usage instructions for any specific module).*

---
<img width="2816" height="1536" alt="Gemini_Generated_Image_e5x2fxe5x2fxe5x2" src="https://github.com/user-attachments/assets/03d8fbcf-6fdd-4f14-9c8f-50f1b2880fda" />

## 🗺️ Future Roadmap for framework core

SuperSploit is continuously evolving to enhance its core exploitation capabilities. The following phases outline our path forward:

### Phase 1: Persistence & Workspace Isolation
* **Relational Database Migration:** Transitioning the flat JSON configurations to a lightweight, asynchronous SQLite backend to handle complex payload configurations.
* **Multi-Tenant Workspaces:** Implementing secure, isolated workspaces to separate targets, environment variables, and activity logs across different engagements.

### Phase 2: Execution Hardening
* **Payload Sandboxing:** Integrating Linux namespaces and `seccomp` profiles to strictly limit the host-level permissions of running exploits, protecting the framework's host machine.
* **Standardized Exploit API:** Enforcing consistent `check()`, `run()`, and `cleanup()` interfaces across all attack payloads through an Abstract Base Class (ABC).

### Phase 3: Automated Attack Chains
* **Execution Pipelining:** Allowing the framework to pipeline the output of one exploit module directly into the execution engine of another for automated, multi-stage privilege escalation environments.
* **Dynamic Feedback Loops:** Enhancing the socket listeners to support complex interactive feedback loops from compromised devices.

### Phase 4: Interface & Extensibility
* **Dynamic Tab Completion:** Real-time auto-suggest and tab completion for active IPs, exploit paths, and CVE numbers directly within the prompt.
* **RESTful API Wrapper:** Developing a headless API mode to allow the execution engine to be orchestrated remotely, making SuperSploit a viable backend for CI/CD security testing pipelines.

---
---

## 🗺️ Future Roadmap for recon

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


## 👥 Credits & Authors

* **Author (Supersploit Framework):** Donald Ford aka don970 https://github.com/don970/Supersploit-updated

