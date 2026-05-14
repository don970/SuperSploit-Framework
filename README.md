# 🛡️ SuperSploit Framework
⚖️ SuperSploit Framework Legal Disclaimer
Please read this disclaimer carefully before downloading, installing, or using the SuperSploit Framework.

1. Educational and Defensive Purpose Only
The SuperSploit Framework ("the Software") is an advanced penetration testing and security research tool developed strictly for educational purposes, ethical hacking, and defensive security auditing. It is designed to help cybersecurity professionals, system administrators, and researchers identify and mitigate vulnerabilities in systems they own or are authorized to evaluate.

2. Explicit Authorization Required
This program is fully capable of interacting with systems and networks in ways that may cause disruption, data loss, or system failure. You must have explicit, mutual, and written consent from the owner of the network, device, or application before using this Software against it. Using this Software against systems without prior permission is strictly prohibited and constitutes a criminal offense under local, state, federal, and international laws (such as the Computer Fraud and Abuse Act in the United States).

3. No Liability and Hold Harmless
The author(s), contributors, and maintainers of the SuperSploit Framework assume no liability and are not responsible for any misuse, damage, or illegal activity caused by this Software. By using this Software, you agree to take full personal and legal responsibility for your actions. If you use this tool to break the law, the author(s) will not be held accountable.

4. No Warranty ("As-Is" Provision)
The Software is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. The authors do not guarantee that the tool will perform as intended or that it will not cause unintended damage to target systems.

5. Legal Compliance
It is the end user's sole responsibility to obey all applicable local, state, federal, and international laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

By continuing to use, download, or distribute the SuperSploit Framework, you acknowledge that you have read, understood, and agreed to the terms of this disclaimer.


**SuperSploit Module Development Guide [Available Here](docs/SuperSploit_Module_Development_Guide.md)**

![logo1](https://github.com/user-attachments/assets/02f43367-1b7e-42f0-b25c-6ed786079567)

## ⚠️ Disclaimer
*This program is fully capable of breaking the law depending on how it is used. Always ensure you have explicit, written permission from the owner of the device or network you are testing. The author assumes no liability for misuse. Use responsibly.*

---

## 📖 Overview

**SuperSploit** is a highly optimized, Python 3-based exploitation and payload management framework. Built as a lightweight, command-line alternative to heavier GUI-laden platforms, it prioritizes speed, operational security (OPSEC), and a minimal system footprint. 

With recent updates, SuperSploit has evolved into a highly autonomous, dependency-free ecosystem. It replaces traditional external tools with pure-Python native asynchronous reconnaissance, intelligent automated exploit suggestions, and a fully authenticated SSL/TLS Command and Control (C2) architecture.

---

## 🚀 Core Strengths & Features

### 1. In-Memory Execution & Fileless Payloads
* **Dynamic Module Loading:** Utilizing `importlib.util`, Python exploits are dynamically loaded directly into isolated memory namespaces, leaving zero temporary files on the disk.
* **Automated Payload Linking:** When an exploit fires, SuperSploit silently compiles a Stage 1 stager into a Base64-encoded Python one-liner for instant, fileless execution on the target.
* **Fail-Safe C Compilation:** C-based exploits are compiled in real-time (`gcc`). A rigid execution protocol ensures that compiled binaries are safely purged from the host disk immediately after execution.

### 2. Secure Command and Control (C2)
* **SSL/TLS Encryption:** The C2 architecture utilizes fully authenticated SSL/TLS stream encryption. SuperSploit automatically generates ephemeral self-signed certificates to wrap raw TCP sockets, securing post-exploitation traffic from network interception.
* **Connection Heartbeat:** The centralized background listener uses OS-level TCP Keepalives and an aggressive 60-second ping loop to automatically detect drops and purge dead sessions.
* **Modular Stage 2 Deployment:** Dynamically deploy custom post-exploitation C2 payloads (`STAGE_TWO`) over the secure TLS tunnel once the initial connection is authenticated.

### 3. Dependency-Free Native Reconnaissance
* **Heuristic Service Detection:** Features a native async port scanner (`asyncio`) equipped with a `ServiceDetector`. It utilizes a dual-probe architecture to natively parse and compile regex signatures from `nmap-service-probes.txt` over raw sockets—completely bypassing the need for Nmap.
* **Scapy OS Fingerprinting:** A pure-Python engine replicates complex network probes (SEQ, OPS, WIN, ECN) to accurately fingerprint operating systems against native databases.
* **Intelligent Auto-Suggest:** The framework automatically analyzes discovered open ports and correlates them with local exploit metadata, instantly suggesting viable attack paths (`auto_suggest`).

### 4. Performance-Optimized Architecture
* **O(1) Command Registry:** Optimized dictionary mappings ensure instantaneous command dispatching.
* **Write-Back Memory Cache:** Centralized in-memory state management drastically reduces disk I/O. A background daemon thread silently flushes dirty data to the target database without interrupting the operator.
* **Zero-Trust Security:** Internal scripts and tools are validated using SHA256 hashing. All user-provided shell arguments are tokenized using `shlex.split()`, mitigating command injection on the host.

---

## ⚙️ Command Layout & Usage

SuperSploit commands are divided into tactical categories for ease of use.

### [1] Core Workspace & Variables
* `add <VAR> <VAL>` : Add a custom variable to the active database.
* `set <VAR> <VAL>` : Set a specific variable value (e.g., `R_HOST`, `LPORT`).
* `show [TARGET]`   : Show dynamic variables, active sessions, aliases, or exploit details.
* `use <CAT> <IDX>` : Select an exploit or payload by index.
* `search <CAT>`    : Search the database for exploits, payloads, or recon modules.

### [2] Execution & Reconnaissance Engine
* `run`             : Execute loaded reconnaissance modules (e.g., port scans, OS fingerprinting).
* `auto_suggest`    : Analyze target data in memory and receive automated exploit recommendations.
* `exploit`         : Execute the currently loaded exploit or payload. Automatically links and deploys C2 payloads.

### [3] System & Utilities
* `sessions`        : Manage active C2 listener connections.
* `clean`           : Purge history, error logs, and temporary payload data.
* `info`            : Display active exploit metadata (CVE, CWE, Target, Options).
* `help`            : Display detailed syntax and command documentation.

---

<img width="2816" height="1536" alt="run_workflow" src="https://github.com/user-attachments/assets/e6814d97-45fa-4cee-a127-5a8a1296411d" />


<img width="2816" height="1536" alt="recon_engine" src="https://github.com/user-attachments/assets/c6cc9fe3-da20-4698-861a-4f2799bbc6e0" />


<img width="2816" height="1536" alt="Framework_arch" src="https://github.com/user-attachments/assets/b21f73ea-6afc-4152-97af-d2dd92dfeb91"/>


## 🗺️ Future Roadmap

With Phase 1 and 2 (Native Recon and Secure C2) effectively implemented, the development path focuses on isolation and automation:

### Phase 3: Execution Hardening & Workspace Isolation
* **Payload Sandboxing:** Integrating Linux namespaces and `seccomp` profiles to strictly limit the host-level permissions of running exploits, ensuring the framework's host machine remains protected.
* **SQLite Relational Migration:** Transitioning flat JSON configurations to a lightweight, asynchronous SQLite backend for multi-tenant workspace isolation.

### Phase 4: Automated Attack Chains & Interface
* **Execution Pipelining:** Allowing the output of one exploit module to pipeline directly into the execution engine of another for zero-click, multi-stage privilege escalation.
* **RESTful API Wrapper:** Developing a headless API mode to orchestrate the execution engine remotely, making SuperSploit a viable backend for CI/CD security testing pipelines.

---

## 👥 Credits & Authors

* **Author (SuperSploit Framework):** Donald Ford aka don970 https://github.com/don970/Supersploit-updated
